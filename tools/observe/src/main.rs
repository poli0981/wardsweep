//! `wardsweep-observe` — the read-only snapshot and diff harness.
//!
//! A separate binary from the broker on purpose. `docs/16-OBSERVATION-HARNESS.md`:
//! "Snapshots are **read-only**. The harness has no removal code path at all —
//! it is a separate binary from the broker for exactly this reason."
//!
//! `wardsweep observe …` in `docs/11-CLI-REFERENCE.md` forwards to this
//! executable rather than linking its logic into the broker frontend, so the
//! documented UX and the process boundary both hold.
//!
//! # Why this exists before the scanner
//!
//! `CONTRIBUTING.md` ranks a real observation diff above any amount of code,
//! because no catalog entry may ship without one. An empty catalog finds
//! nothing, which is harmless; a guessed catalog deletes the wrong thing.
//!
//! # Shape
//!
//! Only [`collect`] touches Win32. [`model`], [`diff`] and [`clock`] are pure
//! logic and run their tests on Linux, which is where `rust-ci.yml` lints this
//! crate with `--all-features`.

mod clock;
mod collect;
mod diff;
mod model;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::diff::NoiseFilter;

/// `docs/11-CLI-REFERENCE.md` exit codes, for the subset this binary uses.
mod exit {
    /// Success.
    pub const SUCCESS: u8 = 0;
    /// Nothing found, nothing to do.
    pub const NOTHING: u8 = 1;
    /// The scan failed.
    pub const SCAN_ERROR: u8 = 2;
}

#[derive(Parser)]
#[command(
    name = "wardsweep-observe",
    version,
    about = "Read-only snapshot and diff harness for building catalog entries.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture the current state of the machine.
    Snapshot {
        /// Where to write the snapshot.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
        /// Free-text label, so a directory of snapshots is readable.
        #[arg(long, default_value = "", value_name = "TEXT")]
        label: String,
    },

    /// Compare two snapshots.
    Diff {
        /// The earlier snapshot.
        #[arg(long, value_name = "PATH")]
        before: PathBuf,
        /// The later snapshot.
        #[arg(long, value_name = "PATH")]
        after: PathBuf,
        /// Where to write the diff.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
        /// Apply no noise filter at all.
        ///
        /// Suppressed changes are recorded rather than dropped either way, so
        /// this is for auditing the rules rather than for recovering data.
        #[arg(long)]
        no_filter: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(exit::SCAN_ERROR)
        }
    }
}

fn run(command: &Command) -> Result<u8> {
    match command {
        Command::Snapshot { output, label } => snapshot(output, label),
        Command::Diff {
            before,
            after,
            output,
            no_filter,
        } => run_diff(before, after, output, *no_filter),
    }
}

fn snapshot(output: &PathBuf, label: &str) -> Result<u8> {
    let snapshot = collect::snapshot(label, clock::now_utc())?;

    let captured = snapshot.coverage.captured.len();
    let total = model::Domain::all().len();

    write_json(output, &snapshot)?;

    eprintln!(
        "snapshot written to {} — {} services, {} unreadable",
        output.display(),
        snapshot.services.len(),
        snapshot.coverage.access_denied.len()
    );
    // Said every time, not only when it is inconvenient. A snapshot that
    // covered part of the machine and did not say so produces a diff that looks
    // complete, and every domain it skipped reads as "nothing changed there".
    eprintln!(
        "coverage: {captured} of {total} domains — not captured: {}",
        snapshot
            .coverage
            .not_captured
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(exit::SUCCESS)
}

fn run_diff(before: &PathBuf, after: &PathBuf, output: &PathBuf, no_filter: bool) -> Result<u8> {
    let before_snapshot: model::Snapshot = read_json(before)?;
    let after_snapshot: model::Snapshot = read_json(after)?;

    let filter = if no_filter {
        NoiseFilter::permissive()
    } else {
        NoiseFilter::standard()
    };

    let diff = diff::compare(&before_snapshot, &after_snapshot, &filter)
        .context("comparing the snapshots")?;

    write_json(output, &diff)?;

    eprintln!(
        "diff written to {} — {} service changes",
        output.display(),
        diff.services.len()
    );
    for (rule, count) in diff.suppression_counts() {
        // Never silent. A rule that hid something says so and names itself.
        eprintln!("  {count} change(s) suppressed by rule `{rule}` — see `suppressed` in the diff");
    }
    if !diff.coverage.not_captured.is_empty() {
        eprintln!(
            "  this diff says nothing about: {}",
            diff.coverage
                .not_captured
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if diff.services.is_empty() {
        return Ok(exit::NOTHING);
    }
    Ok(exit::SUCCESS)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(value).context("serialising")?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}
