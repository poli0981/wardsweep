//! Spike S3 broker. Throwaway — see `spikes/s3-split-privilege/README.md`.
//!
//! Stands in for `wardsweep-broker.exe` for exactly as long as it takes to
//! answer the question in `docs/13-P0-SPIKES.md`: does the unelevated UI +
//! elevated broker split work end to end, including reconnection and survival
//! across a process death?
//!
//! It performs **no** destructive operation. The job it runs is synthetic, the
//! scan it reports is synthetic, and the Win32 feature sets that would let it
//! touch SCM or the registry are not compiled in.
//!
//! Two lines of output are load-bearing:
//!
//! - **stdout** carries `S3|key=value|…` facts for `scripts/run-s3.ps1` to
//!   assert on. Machine-readable, one fact per line, never localised.
//! - **stderr** carries the `tracing` log for a human.

#![forbid(unsafe_op_in_unsafe_fn)]

mod clock;
mod client_check;
mod facts;
mod job;
mod pipe;
mod proto;
mod state;
mod win;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde_json::json;

use crate::facts::{emit as fact, one_line};
use crate::job::JobHandle;
use crate::pipe::Pipe;
use crate::proto::{Envelope, FrameError};
use crate::state::{JobStore, JournalMode};

/// A catalog version string. The spike loads no catalog; this is a placeholder
/// so `HelloAck` has the shape `docs/08-IPC-PROTOCOL.md` specifies.
const SYNTHETIC_CATALOG_VERSION: &str = "0 (spike, no catalog loaded)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Create the pipe and serve a client.
    Serve,
    /// Try to create a pipe that already exists, and report what happened.
    Squat,
    /// Measure whether a synchronous pipe handle serialises read against write.
    DuplexProbe,
}

#[derive(Parser)]
#[command(
    name = "s3-broker",
    version,
    about = "Spike S3 broker. Throwaway. Performs no destructive operation.",
    long_about = None,
)]
struct Cli {
    /// Session GUID naming the pipe, as `docs/08-IPC-PROTOCOL.md` specifies.
    #[arg(long, value_name = "GUID")]
    session: String,

    #[arg(long, value_enum, default_value_t = Mode::Serve)]
    mode: Mode,

    /// Where the job database and logs go. Never `%ProgramData%\WardSweep`.
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    /// File name the connecting client must have.
    #[arg(long, default_value = "S3.Ui.exe", value_name = "NAME")]
    expect_client: String,

    /// Journal mode for the job database — the variable in criterion 6.
    #[arg(long, value_enum, default_value_t = JournalMode::Wal)]
    journal_mode: JournalMode,

    /// Events emitted per stage. Seven stages, so the job is 7×(this)+14 events.
    #[arg(long, default_value_t = 4, value_name = "N")]
    ticks_per_stage: u32,

    /// Milliseconds between events. Long enough that a kill lands mid-stream.
    #[arg(long, default_value_t = 250, value_name = "MS")]
    tick_ms: u64,

    /// Hold each commit transaction open for this long before committing.
    ///
    /// The harness needs to kill the broker *inside* a write transaction to
    /// answer criterion 6 honestly. Without this the kill lands wherever it
    /// lands, so a hot journal is present only sometimes and the result flips
    /// between runs — which is how a real hazard gets recorded as a pass.
    /// The broker emits `S3|commit|state=stalling` when the window opens.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    stall_commit_ms: u64,

    /// Skip the per-stage WAL checkpoint.
    ///
    /// The counterfactual for criterion 6. With checkpointing on, a WAL
    /// database is empty at every stage boundary and there is nothing for a
    /// reader to recover; whether that is what makes the read-only open work,
    /// or whether it would have worked anyway, can only be told apart by
    /// turning it off.
    #[arg(long)]
    no_checkpoint: bool,

    /// Mirror every `S3|` fact into this file as well as stdout.
    ///
    /// Needed because `Verb = "runas"` forces `UseShellExecute = true`, which
    /// forecloses stdio redirection: an elevated broker's stdout is attached to
    /// its own new console and the launching UI can never see it. A file is the
    /// only channel back for the facts the harness asserts on.
    #[arg(long, value_name = "PATH")]
    fact_file: Option<PathBuf>,

    /// Accept a client whose image fails verification, logging the refusal.
    ///
    /// Off by default and never used by the harness. It exists so the failure
    /// path can be inspected without editing the code, which is how a spike
    /// stays cheap to re-run.
    #[arg(long, hide = true)]
    ignore_client_verification: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            fact(&format!("fatal|error={}", one_line(&format!("{error:#}"))));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let state_dir = cli.state_dir.clone().unwrap_or_else(default_state_dir);
    // The broker owns directory creation. The shipped UI cannot do it: the
    // architecture test in ui/WardSweep.UI.Tests forbids the UI assembly from
    // referencing System.IO.Directory at all.
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;

    if let Some(path) = &cli.fact_file {
        facts::mirror_to(path)
            .with_context(|| format!("opening the fact file {}", path.display()))?;
    }

    match cli.mode {
        Mode::Serve => serve(cli, &state_dir),
        Mode::Squat => squat(cli),
        Mode::DuplexProbe => duplex_probe(cli),
    }
}

fn default_state_dir() -> PathBuf {
    // %LOCALAPPDATA%\WardSweep\spike-s3 — deliberately not %ProgramData%\WardSweep,
    // which is the real product's state root.
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("WardSweep").join("spike-s3")
}

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

fn serve(cli: &Cli, state_dir: &std::path::Path) -> Result<()> {
    let elevated = win::is_elevated()?;
    let user_sid = win::current_user_sid()?;
    let broker_image = win::own_image_path()?;

    let pipe = pipe::create(&cli.session, &user_sid)?;

    fact(&format!(
        "role=broker|pid={}|elevated={elevated}|session={}|pipe={}|image={}",
        std::process::id(),
        cli.session,
        pipe.name,
        broker_image
    ));

    // S3 criterion 3a. What was asked for is not evidence; what the kernel
    // attached to the object is. The verdict is reported field by field rather
    // than as one boolean, because "the DACL is wrong" and "the DACL is right
    // but spelled differently" are the two answers that must not be confused.
    let dacl = pipe::assess_dacl(&pipe.observed_sddl, &user_sid);
    fact(&format!(
        "dacl|observed={}|expected={}|matches_expected={}|protected={}|everyone={}|authenticated_users={}|launching_user={}|acceptable={}",
        dacl.observed,
        dacl.expected,
        dacl.matches_expected,
        dacl.protected,
        dacl.grants_everyone,
        dacl.grants_authenticated_users,
        dacl.grants_launching_user,
        dacl.acceptable()
    ));
    fact(&format!("dacl|requested={}", pipe::requested_sddl(&user_sid)));

    let database = state_dir.join("jobs.db");
    let mut job: Option<JobHandle> = None;

    loop {
        pipe.accept()?;

        // Captured before asking who the client is, so a process that started
        // after this instant cannot be the one that connected.
        let asked_at = SystemTime::now();
        let client_pid = pipe.client_process_id()?;

        match admit(client_pid, asked_at, &broker_image, &cli.expect_client) {
            Ok(()) => {}
            Err(reason) => {
                fact(&format!(
                    "accept|pid={client_pid}|verdict=refused|reason={}",
                    one_line(&reason)
                ));
                tracing::warn!(client_pid, %reason, "refusing a client");
                if !cli.ignore_client_verification {
                    // Refused before a single command is read, so a hostile
                    // client never reaches the dispatcher at all.
                    pipe.disconnect();
                    continue;
                }
                tracing::warn!("--ignore-client-verification is set; serving anyway");
            }
        }

        fact(&format!("accept|pid={client_pid}|verdict=accepted"));

        let outcome = serve_client(cli, &pipe, &database, &mut job, elevated);
        pipe.disconnect();

        match outcome {
            Ok(Served::Shutdown) => {
                fact("serve|result=shutdown");
                return Ok(());
            }
            Ok(Served::ClientGone { at_seq }) => {
                // docs/08: "If the pipe drops mid-job the broker continues."
                // The job thread is untouched by this; only the reader is gone.
                fact(&format!("client-gone|at_seq={at_seq}|job_continues=true"));
                tracing::info!(at_seq, "client vanished; job continues, awaiting reconnect");
            }
            Err(error) => {
                tracing::error!("{error:#}");
                fact(&format!(
                    "serve|result=error|error={}",
                    one_line(&format!("{error:#}"))
                ));
            }
        }
    }
}

/// Whether a connected client may proceed.
fn admit(
    client_pid: u32,
    asked_at: SystemTime,
    broker_image: &str,
    expected_file_name: &str,
) -> Result<(), String> {
    let identity =
        client_check::identify(client_pid).map_err(|error| format!("unidentifiable: {error:#}"))?;

    if !client_check::predates(&identity, asked_at) {
        // The process holding this id started after the kernel told us the id,
        // so the id was recycled and this is not the process that connected.
        return Err(format!(
            "process id {client_pid} was recycled between the two calls"
        ));
    }

    match client_check::verify_image(&identity, broker_image, expected_file_name) {
        Ok(None) => Ok(()),
        Ok(Some(refusal)) => Err(format!(
            "{refusal} (pid {}, image {})",
            identity.pid, identity.image_path
        )),
        Err(error) => Err(format!("verification failed: {error:#}")),
    }
}

enum Served {
    Shutdown,
    ClientGone { at_seq: u64 },
}

fn serve_client(
    cli: &Cli,
    pipe: &Pipe,
    database: &std::path::Path,
    job: &mut Option<JobHandle>,
    elevated: bool,
) -> Result<Served> {
    let mut cursor: u64 = 0;

    loop {
        let command = match pipe.read_frame() {
            Ok(command) => command,
            Err(FrameError::Closed) => return Ok(Served::ClientGone { at_seq: cursor }),
            Err(FrameError::Broken(error)) => {
                tracing::warn!(%error, "pipe broke mid-frame");
                return Ok(Served::ClientGone { at_seq: cursor });
            }
            Err(other) => {
                // A malformed or oversized frame is a protocol error, not a
                // reason to die: refuse it and keep serving.
                tracing::warn!("{other}");
                let error = Envelope::response(
                    None,
                    "Error",
                    json!({
                        "code": "E_BAD_FRAME",
                        "message_key": "err.ipc.bad_frame",
                        "args": {},
                        "recoverable": true,
                    }),
                );
                if !pipe.write_frame(&error)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
                continue;
            }
        };

        tracing::info!(kind = %command.kind, "command");

        match command.kind.as_str() {
            "Hello" => {
                let claimed = command
                    .payload
                    .get("session")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if let Some(refusal) = client_check::verify_session(claimed, &cli.session) {
                    fact(&format!("hello|verdict=refused|reason={}", one_line(&refusal.to_string())));
                    return Ok(Served::ClientGone { at_seq: cursor });
                }

                cursor = command
                    .payload
                    .get("resume_from")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);

                let ack = Envelope::response(
                    command.id.clone(),
                    "HelloAck",
                    json!({
                        "broker_version": env!("CARGO_PKG_VERSION"),
                        "catalog_version": SYNTHETIC_CATALOG_VERSION,
                        "elevated": elevated,
                        "broker_pid": std::process::id(),
                        "protocol": proto::PROTOCOL_VERSION,
                        "job_id": job.as_ref().map(|j| j.job_id.clone()),
                        "job_last_seq": job.as_ref().map_or(0, JobHandle::last_seq),
                        "job_finished": job.as_ref().is_some_and(JobHandle::finished),
                        "database": database.to_string_lossy(),
                        "resumed_from": cursor,
                    }),
                );
                fact(&format!("hello|elevated={elevated}|resume_from={cursor}"));
                if !pipe.write_frame(&ack)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
            }

            "ScanStart" => {
                if !ack(pipe, &command)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
                if !synthetic_scan(pipe)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
            }

            "ApplyPlan" => {
                if job.is_none() {
                    let job_id = format!("s3-{}", cli.session);
                    let store = JobStore::open(
                        database,
                        &job_id,
                        cli.journal_mode,
                        SYNTHETIC_CATALOG_VERSION,
                    )?;
                    fact(&format!(
                        "job|id={job_id}|database={}|journal={:?}|checkpoint={}",
                        database.display(),
                        cli.journal_mode,
                        !cli.no_checkpoint
                    ));
                    *job = Some(JobHandle::start(
                        job_id,
                        store,
                        cli.ticks_per_stage,
                        Duration::from_millis(cli.tick_ms),
                        !cli.no_checkpoint,
                        Duration::from_millis(cli.stall_commit_ms),
                    ));
                }
                if !ack(pipe, &command)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
                let running = job.as_ref().expect("job was just started");
                match stream(pipe, running, cursor)? {
                    Streamed::Complete { at_seq } => cursor = at_seq,
                    Streamed::ClientGone { at_seq } => {
                        return Ok(Served::ClientGone { at_seq });
                    }
                }
            }

            "JobResume" => {
                cursor = command
                    .payload
                    .get("from_seq")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(cursor);
                if !ack(pipe, &command)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
                let Some(running) = job.as_ref() else {
                    continue;
                };
                fact(&format!("resume|from_seq={cursor}"));
                match stream(pipe, running, cursor)? {
                    Streamed::Complete { at_seq } => cursor = at_seq,
                    Streamed::ClientGone { at_seq } => {
                        return Ok(Served::ClientGone { at_seq });
                    }
                }
            }

            "JobStatus" => {
                let payload = job.as_ref().map_or_else(
                    || json!({ "job_id": null, "last_seq": 0, "finished": false }),
                    |running| {
                        json!({
                            "job_id": running.job_id,
                            "last_seq": running.last_seq(),
                            "finished": running.finished(),
                        })
                    },
                );
                let response = Envelope::response(command.id.clone(), "JobState", payload);
                if !pipe.write_frame(&response)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
            }

            "Shutdown" => {
                let _ = ack(pipe, &command)?;
                return Ok(Served::Shutdown);
            }

            other => {
                tracing::warn!(kind = other, "unknown command");
                let error = Envelope::response(
                    command.id.clone(),
                    "Error",
                    json!({
                        "code": "E_UNKNOWN_COMMAND",
                        "message_key": "err.ipc.unknown_command",
                        "args": { "type": other },
                        "recoverable": true,
                    }),
                );
                if !pipe.write_frame(&error)? {
                    return Ok(Served::ClientGone { at_seq: cursor });
                }
            }
        }
    }
}

fn ack(pipe: &Pipe, command: &Envelope) -> Result<bool> {
    pipe.write_frame(&Envelope::response(command.id.clone(), "Ack", json!({})))
}

/// A scan that scans nothing.
///
/// `docs/08-IPC-PROTOCOL.md` caps `ScanBatch` at 500 findings per frame and
/// makes the broker wait for each write to complete before producing the next
/// batch, so a slow UI throttles the scanner instead of growing a queue. The
/// shape is reproduced here; the findings are fabricated.
fn synthetic_scan(pipe: &Pipe) -> Result<bool> {
    for batch in 0..3u32 {
        let findings: Vec<_> = (0..5)
            .map(|n| {
                json!({
                    "id": format!("finding-{batch}-{n}"),
                    "kind": "synthetic",
                    "message_key": "finding.synthetic",
                })
            })
            .collect();
        let event = Envelope::response(
            None,
            "ScanBatch",
            json!({ "findings": findings, "scanned_count": (batch + 1) * 5, "elapsed_ms": 0 }),
        );
        if !pipe.write_frame(&event)? {
            return Ok(false);
        }
    }

    pipe.write_frame(&Envelope::response(
        None,
        "ScanComplete",
        json!({ "total": 15, "partial": false, "access_denied_paths": [] }),
    ))
}

enum Streamed {
    Complete { at_seq: u64 },
    ClientGone { at_seq: u64 },
}

/// Push events to the client until the job ends or the client vanishes.
fn stream(pipe: &Pipe, job: &JobHandle, from: u64) -> Result<Streamed> {
    let mut cursor = from;
    let mut sent_first: Option<u64> = None;

    loop {
        let (events, finished) = job.events_after(cursor, Duration::from_millis(500));

        for event in events {
            let seq = event.seq.unwrap_or(cursor + 1);
            if !pipe.write_frame(&event)? {
                fact(&format!(
                    "stream|sent_from={}|sent_to={cursor}|result=client_gone",
                    sent_first.unwrap_or(from + 1)
                ));
                return Ok(Streamed::ClientGone { at_seq: cursor });
            }
            sent_first.get_or_insert(seq);
            cursor = seq;
        }

        if finished && job.last_seq() <= cursor {
            fact(&format!(
                "stream|sent_from={}|sent_to={cursor}|result=complete",
                sent_first.unwrap_or(from + 1)
            ));
            return Ok(Streamed::Complete { at_seq: cursor });
        }
    }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// Try to create a pipe whose name is already held.
///
/// This is the handover question. When the UI shuts the unelevated broker down
/// and starts an elevated one on the same session GUID, the name is briefly
/// unowned and anything running as this user could claim it. What makes that
/// window harmless is `FILE_FLAG_FIRST_PIPE_INSTANCE`: the elevated broker's
/// own creation then *fails* rather than quietly becoming a second instance
/// behind the squatter, so the handover aborts instead of proceeding into a
/// pipe someone else is serving.
fn squat(cli: &Cli) -> Result<()> {
    let user_sid = win::current_user_sid()?;
    match pipe::create(&cli.session, &user_sid) {
        Ok(created) => {
            // The name was free. Either the first broker is not running, or —
            // the finding this probe exists to catch — FIRST_PIPE_INSTANCE did
            // not do what the design assumes.
            fact(&format!("squat|result=created|pipe={}", created.name));
            Ok(())
        }
        Err(error) => {
            fact(&format!(
                "squat|result=refused|error={}",
                one_line(&format!("{error:#}"))
            ));
            Ok(())
        }
    }
}

/// Does a synchronous pipe handle serialise a write behind a pending read?
///
/// It matters because `docs/08-IPC-PROTOCOL.md` has the broker streaming
/// `ScanBatch` events while remaining able to receive `ScanCancel`. If the
/// kernel serialises the two directions on a synchronous handle, that is
/// impossible without `FILE_FLAG_OVERLAPPED`, and the real broker's I/O model
/// is decided by the answer rather than by preference.
///
/// Method: a reader thread blocks in `ReadFile` while the client deliberately
/// sends nothing; the main thread then times a `WriteFile`. A write that
/// returns immediately means the directions are independent.
fn duplex_probe(cli: &Cli) -> Result<()> {
    use windows::Win32::Storage::FileSystem::WriteFile;

    let user_sid = win::current_user_sid()?;
    let pipe = pipe::create(&cli.session, &user_sid)?;
    fact(&format!("duplex|state=listening|pipe={}", pipe.name));
    pipe.accept()?;

    // A raw handle crossing into the reader thread. `HANDLE` is not `Send`, and
    // making the whole `Pipe` shareable for one probe would be the tail wagging
    // the dog, so the handle travels as an integer.
    // Control measurement first: the same write, with no read outstanding. A
    // duplex result is meaningless without it — a slow write could just as
    // easily mean the client is not draining the pipe, and only the contrast
    // between the two timings distinguishes handle serialisation from
    // ordinary backpressure.
    let control_payload = b"s3-duplex-control";
    let mut control_written = 0u32;
    let control_started = Instant::now();
    // SAFETY: payload and out-parameter are live, and the handle is ours.
    let control = unsafe {
        WriteFile(
            pipe.raw(),
            Some(control_payload.as_slice()),
            Some(&raw mut control_written),
            None,
        )
    };
    fact(&format!(
        "duplex|control_write_ms={}|control_ok={}",
        control_started.elapsed().as_millis(),
        control.is_ok()
    ));

    let raw = pipe.raw().0 as usize;
    let reader = std::thread::spawn(move || {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::ReadFile;

        let handle = HANDLE(raw as *mut std::ffi::c_void);
        let mut buffer = vec![0u8; 4096];
        let mut read = 0u32;
        let started = Instant::now();
        // SAFETY: the handle is owned by `pipe` on the main thread, which
        // outlives this thread because it is joined below.
        let outcome = unsafe {
            ReadFile(
                handle,
                Some(buffer.as_mut_slice()),
                Some(&raw mut read),
                None,
            )
        };
        (started.elapsed(), outcome.is_ok(), read)
    });

    // Let the read reach the kernel before timing the write against it.
    std::thread::sleep(Duration::from_millis(300));

    let payload = b"s3-duplex-probe";
    let mut written = 0u32;
    let started = Instant::now();
    // SAFETY: payload and written are live for the call, and the handle is the
    // one this function created.
    let outcome = unsafe {
        WriteFile(
            pipe.raw(),
            Some(payload.as_slice()),
            Some(&raw mut written),
            None,
        )
    };
    let write_elapsed = started.elapsed();

    fact(&format!(
        "duplex|write_ms={}|write_ok={}|written={written}",
        write_elapsed.as_millis(),
        outcome.is_ok()
    ));

    let (read_elapsed, read_ok, read_bytes): (Duration, bool, u32) =
        reader.join().unwrap_or((Duration::ZERO, false, 0));
    fact(&format!(
        "duplex|read_ms={}|read_ok={read_ok}|read_bytes={read_bytes}",
        read_elapsed.as_millis()
    ));
    // The verdict the real broker's I/O model turns on.
    fact(&format!(
        "duplex|serialised={}",
        write_elapsed.as_millis() > 500
    ));

    Ok(())
}

