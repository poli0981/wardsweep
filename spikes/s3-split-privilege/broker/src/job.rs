//! The synthetic job.
//!
//! **This job removes nothing.** It advances a counter through the seven stage
//! names in `docs/06-REMOVAL-PIPELINE.md`, emits one sequence-numbered event
//! per tick, and commits a row to SQLite at each stage boundary. No artifact is
//! named, no path is touched, no service is opened. The Safety Gate applies to
//! throwaway code, and a spike that ran a real pipeline to test its IPC would
//! be the wrong trade by an enormous margin.
//!
//! What it exists to produce is a *stream that outlives its reader*. S3
//! criterion 5 says the broker continues when the pipe drops and the UI
//! reconnects to a resumed stream; that can only be observed against a job long
//! enough to be interrupted, whose events are individually identifiable so a
//! gap or a duplicate is detectable rather than plausible.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::json;

use crate::proto::Envelope;
use crate::state::JobStore;

/// `docs/06-REMOVAL-PIPELINE.md`. Names only — nothing here executes a stage.
pub const STAGE_KEYS: [&str; 7] = [
    "preflight",
    "plan",
    "vendor_uninstall",
    "services",
    "reboot",
    "residue_sweep",
    "verify",
];

/// Everything a reader needs, guarded by one lock.
#[derive(Default)]
struct EventLog {
    /// Every event produced so far. `seq` is the index plus one, so a
    /// reconnecting client asking for "everything after 12" is a slice.
    events: Vec<Envelope>,
    finished: bool,
}

/// A running job, readable from the thread serving the pipe.
pub struct JobHandle {
    shared: Arc<(Mutex<EventLog>, Condvar)>,
    pub job_id: String,
}

impl JobHandle {
    /// Start the job on its own thread.
    ///
    /// The store moves into that thread: `rusqlite::Connection` is not `Sync`,
    /// and the job is the only writer, so there is nothing to share.
    #[must_use]
    pub fn start(
        job_id: String,
        store: JobStore,
        ticks_per_stage: u32,
        tick: Duration,
        checkpoint: bool,
        stall_commit: Duration,
    ) -> Self {
        let shared = Arc::new((Mutex::new(EventLog::default()), Condvar::new()));
        let handle = Self {
            shared: Arc::clone(&shared),
            job_id: job_id.clone(),
        };

        std::thread::spawn(move || {
            run(
                &shared,
                &job_id,
                &store,
                ticks_per_stage,
                tick,
                checkpoint,
                stall_commit,
            );
        });

        handle
    }

    /// Events with a sequence number greater than `after`, and whether the job
    /// has finished.
    ///
    /// Blocks until at least one such event exists or the job ends, so the
    /// serving thread does not spin. Returns an empty vector on timeout, which
    /// is how the caller gets a chance to notice its client has gone.
    pub fn events_after(&self, after: u64, timeout: Duration) -> (Vec<Envelope>, bool) {
        let (lock, condition) = &*self.shared;
        let mut log = lock.lock().expect("event log lock poisoned");

        if log.events.len() as u64 <= after && !log.finished {
            let (guard, _) = condition
                .wait_timeout_while(log, timeout, |log| {
                    log.events.len() as u64 <= after && !log.finished
                })
                .expect("event log lock poisoned");
            log = guard;
        }

        let start = usize::try_from(after).unwrap_or(usize::MAX).min(log.events.len());
        (log.events[start..].to_vec(), log.finished)
    }

    /// The highest sequence number produced so far.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        let (lock, _) = &*self.shared;
        lock.lock().expect("event log lock poisoned").events.len() as u64
    }

    /// Whether the job has run to completion.
    #[must_use]
    pub fn finished(&self) -> bool {
        let (lock, _) = &*self.shared;
        lock.lock().expect("event log lock poisoned").finished
    }
}

fn run(
    shared: &Arc<(Mutex<EventLog>, Condvar)>,
    job_id: &str,
    store: &JobStore,
    ticks_per_stage: u32,
    tick: Duration,
    checkpoint: bool,
    stall_commit: Duration,
) {
    for (stage, key) in STAGE_KEYS.iter().enumerate() {
        let stage = u32::try_from(stage).unwrap_or(u32::MAX);
        if let Err(error) = store.stage_started(stage) {
            tracing::error!(stage, %error, "could not record the stage start");
        }

        push(
            shared,
            job_id,
            stage,
            "started",
            &format!("stage.{key}.started"),
            json!({}),
        );

        for progress in 1..=ticks_per_stage {
            std::thread::sleep(tick);
            push(
                shared,
                job_id,
                stage,
                "progress",
                &format!("stage.{key}.progress"),
                json!({ "current": progress, "total": ticks_per_stage }),
            );
        }

        let last_seq = {
            let (lock, _) = &**shared;
            lock.lock().expect("event log lock poisoned").events.len() as u64
        };

        // The commit point. Everything a UI can learn after a broker kill was
        // written here, so the checkpoint has to happen here too — a committed
        // row still sitting in a WAL file is not a row a read-only reader can
        // necessarily see.
        if let Err(error) = store.stage_finished(stage, "ok", "synthetic", last_seq, stall_commit) {
            tracing::error!(stage, %error, "could not record the stage result");
        }
        if checkpoint && let Err(error) = store.checkpoint() {
            tracing::error!(stage, %error, "could not checkpoint");
        }

        push(
            shared,
            job_id,
            stage,
            "done",
            &format!("stage.{key}.done"),
            json!({}),
        );
    }

    let last_seq = {
        let (lock, _) = &**shared;
        lock.lock().expect("event log lock poisoned").events.len() as u64
    };
    // Recorded before the JobComplete event is pushed, so the database's resume
    // point trails the wire by exactly one. That direction is deliberate: a UI
    // recovering from the database replays one event it may already have seen,
    // rather than skipping one it has not.
    if let Err(error) = store.job_finished("completed", last_seq) {
        tracing::error!(%error, "could not complete the job");
    }
    if checkpoint && let Err(error) = store.checkpoint() {
        tracing::error!(%error, "could not checkpoint at completion");
    }

    let (lock, condition) = &**shared;
    let mut log = lock.lock().expect("event log lock poisoned");
    let seq = log.events.len() as u64 + 1;
    log.events.push(Envelope::event(
        seq,
        "JobComplete",
        json!({
            "job_id": job_id,
            "status": "completed",
            "residual_count": 0,
        }),
    ));
    log.finished = true;
    drop(log);
    condition.notify_all();
}

fn push(
    shared: &Arc<(Mutex<EventLog>, Condvar)>,
    job_id: &str,
    stage: u32,
    state: &str,
    message_key: &str,
    args: serde_json::Value,
) {
    let (lock, condition) = &**shared;
    let mut log = lock.lock().expect("event log lock poisoned");
    let seq = log.events.len() as u64 + 1;
    // docs/08-IPC-PROTOCOL.md: events carry message_key + args, never rendered
    // English prose, so the broker stays language-neutral and adding a locale
    // needs no broker change.
    log.events.push(Envelope::event(
        seq,
        "StageEvent",
        json!({
            "job_id": job_id,
            "stage": stage,
            "state": state,
            "message_key": message_key,
            "args": args,
        }),
    ));
    drop(log);
    condition.notify_all();
}
