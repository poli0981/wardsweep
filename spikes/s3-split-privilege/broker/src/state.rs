//! Job state in SQLite.
//!
//! S3 criterion 6: "broker kill → UI reads job state from SQLite read-only."
//! The interesting part is not writing the rows, it is whether the file is
//! still openable *read-only* after the writer was force-killed mid-transaction.
//!
//! A killed writer can leave a hot rollback journal (`-journal`) or, in WAL
//! mode, a `-wal`/`-shm` pair. SQLite must **write** to recover either of them,
//! so a genuinely read-only open of a database in that state fails with
//! `SQLITE_READONLY_RECOVERY` or `SQLITE_READONLY_DIRECTORY` rather than
//! returning stale-but-readable data. That is a real hazard for the design in
//! `docs/03-ARCHITECTURE.md`, which promises the UI can "read job state
//! directly from SQLite in read-only mode and offer resume or rollback".
//!
//! The journal mode is therefore a command-line switch, so the spike can
//! measure all three rather than assume one.

use anyhow::{Context, Result, bail};
use rusqlite::Connection;

use crate::clock::now_utc;

/// How the database journals, which is what decides criterion 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum JournalMode {
    /// Write-ahead log. Best for concurrent readers *while the writer lives*;
    /// leaves `-wal`/`-shm` behind if the writer dies.
    Wal,
    /// Rollback journal, deleted at the end of each transaction. Leaves a hot
    /// journal only if the process dies mid-transaction.
    Delete,
    /// Rollback journal truncated rather than deleted. Same hazard window as
    /// `Delete`, fewer directory operations.
    Truncate,
}

impl JournalMode {
    fn pragma(self) -> &'static str {
        match self {
            Self::Wal => "WAL",
            Self::Delete => "DELETE",
            Self::Truncate => "TRUNCATE",
        }
    }
}

/// The broker's handle on the job record.
pub struct JobStore {
    connection: Connection,
    job_id: String,
}

impl JobStore {
    /// Open or create the database and start a job row.
    ///
    /// # Errors
    /// If the file cannot be opened, the schema cannot be applied, or the
    /// journal mode is refused.
    pub fn open(
        path: &std::path::Path,
        job_id: &str,
        journal: JournalMode,
        catalog_version: &str,
    ) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("opening {}", path.display()))?;

        // `journal_mode` returns the mode actually adopted, which is not always
        // the one asked for — WAL is refused on some network filesystems, for
        // instance, and silently staying in DELETE would invalidate the whole
        // measurement.
        let adopted: String = connection
            .query_row(
                &format!("PRAGMA journal_mode = {}", journal.pragma()),
                [],
                |row| row.get(0),
            )
            .context("PRAGMA journal_mode")?;
        if !adopted.eq_ignore_ascii_case(journal.pragma()) {
            bail!(
                "asked for journal_mode {} but the database adopted {adopted}",
                journal.pragma()
            );
        }

        // Schema trimmed from docs/18-LOGGING.md. `last_seq` is the spike's
        // addition: it is what lets a UI whose broker died know how far the
        // event stream had got, which is the same resume point the reconnect
        // path needs over the wire.
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS jobs (
                   id TEXT PRIMARY KEY,
                   created_utc TEXT NOT NULL,
                   completed_utc TEXT,
                   status TEXT NOT NULL,
                   app_version TEXT NOT NULL,
                   catalog_version TEXT NOT NULL,
                   last_seq INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS job_stages (
                   job_id TEXT NOT NULL,
                   stage INTEGER NOT NULL,
                   started_utc TEXT NOT NULL,
                   ended_utc TEXT,
                   result TEXT NOT NULL,
                   notes TEXT,
                   PRIMARY KEY (job_id, stage)
                 );",
            )
            .context("applying the schema")?;

        connection
            .execute(
                "INSERT INTO jobs (id, created_utc, status, app_version, catalog_version, last_seq)
                 VALUES (?1, ?2, 'running', ?3, ?4, 0)
                 ON CONFLICT(id) DO UPDATE SET status = 'running'",
                rusqlite::params![job_id, now_utc(), env!("CARGO_PKG_VERSION"), catalog_version],
            )
            .context("inserting the job row")?;

        Ok(Self {
            connection,
            job_id: job_id.to_owned(),
        })
    }

    /// Record that a stage started.
    ///
    /// # Errors
    /// If the insert fails.
    pub fn stage_started(&self, stage: u32) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO job_stages (job_id, stage, started_utc, result)
                 VALUES (?1, ?2, ?3, 'running')
                 ON CONFLICT(job_id, stage) DO UPDATE SET started_utc = excluded.started_utc",
                rusqlite::params![self.job_id, stage, now_utc()],
            )
            .context("recording a stage start")?;
        Ok(())
    }

    /// Record that a stage finished, and how far the event stream has got.
    ///
    /// This is the commit point. Everything the UI can learn after a broker
    /// kill was written by one of these calls.
    ///
    /// # Errors
    /// If either statement fails.
    pub fn stage_finished(
        &self,
        stage: u32,
        result: &str,
        notes: &str,
        last_seq: u64,
        stall: std::time::Duration,
    ) -> Result<()> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction
            .execute(
                "UPDATE job_stages SET ended_utc = ?1, result = ?2, notes = ?3
                 WHERE job_id = ?4 AND stage = ?5",
                rusqlite::params![now_utc(), result, notes, self.job_id, stage],
            )
            .context("recording a stage result")?;
        transaction
            .execute(
                "UPDATE jobs SET last_seq = ?1 WHERE id = ?2",
                rusqlite::params![i64::try_from(last_seq).unwrap_or(i64::MAX), self.job_id],
            )
            .context("recording the resume point")?;

        if !stall.is_zero() {
            // The journal is on disk and the commit has not happened, which is
            // precisely the state a crash has to be observed in. Announced so
            // the harness can kill the process inside this window rather than
            // hoping to land in one.
            crate::facts::emit(&format!(
                "commit|stage={stage}|state=stalling|ms={}",
                stall.as_millis()
            ));
            std::thread::sleep(stall);
        }

        transaction.commit().context("committing a stage")?;
        Ok(())
    }

    /// Mark the job finished.
    ///
    /// # Errors
    /// If the update fails.
    pub fn job_finished(&self, status: &str, last_seq: u64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE jobs SET completed_utc = ?1, status = ?2, last_seq = ?3 WHERE id = ?4",
                rusqlite::params![now_utc(), status, i64::try_from(last_seq).unwrap_or(i64::MAX), self.job_id],
            )
            .context("completing the job")?;
        Ok(())
    }

    /// Force a checkpoint so nothing the UI needs is stranded in a `-wal` file.
    ///
    /// In WAL mode a committed transaction lives in `database-wal` until a
    /// checkpoint folds it back, and a read-only reader that cannot create the
    /// `-shm` shared-memory file cannot see it. Checkpointing after every stage
    /// is what makes criterion 6 survivable in WAL mode — and measuring whether
    /// it is *sufficient* is the point of the spike.
    ///
    /// # Errors
    /// If the checkpoint statement fails.
    pub fn checkpoint(&self) -> Result<()> {
        // TRUNCATE resets the WAL to zero length after folding it back, so a
        // crash immediately afterwards leaves nothing to recover.
        self.connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(()),
                other => Err(other),
            })
            .context("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }
}
