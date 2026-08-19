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
mod redact;
mod suggest;

use std::path::{Path, PathBuf};
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

    /// Emit a draft catalog entry from a diff.
    ///
    /// A starting point requiring human review, never a finished entry.
    Suggest {
        /// The install diff: clean → installed.
        #[arg(long, value_name = "PATH")]
        diff: PathBuf,
        /// The residue diff: after the official uninstaller → clean.
        ///
        /// The more valuable of the two. `docs/16` calls it "the exact set of
        /// things the vendor's own uninstaller leaves behind — which is the
        /// entire reason WardSweep exists".
        #[arg(long, value_name = "PATH")]
        residue: Option<PathBuf>,
        /// Attribute the footprint to this publisher rather than the commonest.
        #[arg(long, value_name = "CN")]
        signer: Option<String>,
        /// Where to write the draft.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },

    /// Replace usernames, machine-local SIDs and host names with placeholders.
    ///
    /// Required before a raw snapshot may be shared, per `docs/16`. It removes
    /// identity, not secrets — a person still reads the file before it is
    /// attached to anything.
    Redact {
        /// The snapshot or diff to redact.
        #[arg(long = "in", value_name = "PATH")]
        input: PathBuf,
        /// Where to write the redacted copy.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
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
        Command::Suggest {
            diff,
            residue,
            signer,
            output,
        } => run_suggest(diff, residue.as_ref(), signer.as_deref(), output),
        Command::Redact { input, output } => run_redact(input, output),
    }
}

fn run_suggest(
    diff_path: &PathBuf,
    residue_path: Option<&PathBuf>,
    signer: Option<&str>,
    output: &PathBuf,
) -> Result<u8> {
    let footprint: diff::Diff = read_json(diff_path)?;
    let residue: Option<diff::Diff> = residue_path.map(read_json).transpose()?;

    if footprint.filesystem_policy_changed || footprint.registry_policy_changed {
        eprintln!(
            "  WARNING: this diff was produced from snapshots taken under different \
             policies. A draft built from it may name footprint that is an artefact of \
             the harness rather than of an installer."
        );
    }

    let draft = suggest::draft(&footprint, residue.as_ref(), signer);
    let toml = suggest::to_toml(&draft, &clock::now_utc()).context("rendering the draft")?;

    ensure_parent(output)?;
    std::fs::write(output, &toml).with_context(|| format!("writing {}", output.display()))?;

    eprintln!(
        "draft written to {} — {} service(s), {} driver(s), {} path(s), {} key(s)",
        output.display(),
        draft.entry.services.len(),
        draft.entry.drivers.len(),
        draft.entry.paths.len(),
        draft.entry.registry.len()
    );
    // Said every time. A draft that reads as finished is the failure mode.
    eprintln!(
        "this is a DRAFT — {} item(s) need review before submitting:",
        draft.review.len()
    );
    for note in &draft.review {
        eprintln!("  - {note}");
    }

    if draft.entry.services.is_empty()
        && draft.entry.paths.is_empty()
        && draft.entry.registry.is_empty()
    {
        eprintln!("nothing was added between these snapshots; there is no footprint to describe");
        return Ok(exit::NOTHING);
    }
    Ok(exit::SUCCESS)
}

fn run_redact(input: &PathBuf, output: &PathBuf) -> Result<u8> {
    let mut document: serde_json::Value = read_json(input)?;
    let report = redact::redact_document(&mut document);

    ensure_parent(output)?;
    let text = serde_json::to_string(&document).context("serialising")?;
    std::fs::write(output, text).with_context(|| format!("writing {}", output.display()))?;

    eprintln!("redacted copy written to {}", output.display());
    if !report.names.is_empty() {
        eprintln!("  account name(s) found: {}", report.names.join(", "));
    }
    if report.applied.is_empty() {
        eprintln!("  no identifying strings were found");
    }
    for (placeholder, count) in &report.applied {
        eprintln!("  {count} substitution(s) → {placeholder}");
    }

    // Never claim more than was done.
    if report.residual.is_empty() {
        eprintln!("  no occurrence of a discovered account name remains");
    } else {
        for (name, count) in &report.residual {
            // Deliberately not "this file still identifies someone". On a real
            // snapshot all 83 residual hits were the English word "Anonymous",
            // and a warning that cries wolf is one people learn to skip past.
            // Say what is there and let the reader judge.
            eprintln!(
                "  CHECK: `{name}` still appears {count} time(s), inside longer words where \
                 replacing it would corrupt unrelated text (`Anonymous` and the like). \
                 Confirm none of them is the account name before sharing."
            );
        }
    }
    eprintln!("  this removes identity, not secrets — read the file before sharing it (docs/16)");

    if report.residual.is_empty() {
        Ok(exit::SUCCESS)
    } else {
        // Exit non-zero so a script cannot publish the result by accident.
        Ok(exit::NOTHING)
    }
}

fn snapshot(output: &PathBuf, label: &str) -> Result<u8> {
    let snapshot = collect::snapshot(label, clock::now_utc(), collect::Request::default())?;

    let captured = snapshot.coverage.captured.len();
    let total = model::Domain::all().len();

    write_snapshot(output, &snapshot)?;

    eprintln!(
        "snapshot written to {} — {} services, {} files, {} registry keys, {} unreadable",
        output.display(),
        snapshot.services.len(),
        snapshot.files.len(),
        snapshot.registry.len(),
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

    write_diff(output, &diff)?;

    eprintln!(
        "diff written to {} — {} service changes, {} file changes, {} registry changes",
        output.display(),
        diff.services.len(),
        diff.files.len(),
        diff.registry.len()
    );
    if diff.registry_policy_changed {
        eprintln!(
            "  WARNING: the two snapshots used different registry policies. \
             Key differences may be an artefact of the policy rather than a \
             change on the machine — compare `registry_policy` in both."
        );
    }
    if diff.filesystem_policy_changed {
        // Loud, and first. Every file difference below may be the policy rather
        // than the machine, and a reviewer who reads the list without knowing
        // that will attribute the harness's own settings to an installer.
        eprintln!(
            "  WARNING: the two snapshots used different filesystem policies. \
             File differences may be an artefact of the policy rather than a \
             change on the machine — compare `filesystem_policy` in both."
        );
    }
    for (signer, count) in &diff.signers {
        eprintln!("  {count} file(s) signed by `{signer}`");
    }
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

    if diff.services.is_empty() && diff.files.is_empty() && diff.registry.is_empty() {
        return Ok(exit::NOTHING);
    }
    Ok(exit::SUCCESS)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Write a snapshot: compact, because it is machine input.
///
/// A snapshot of this machine holds three quarters of a million file records.
/// Pretty-printing costs roughly 40% of the file size to indent something
/// nobody reads by hand — the diff is what a person looks at, and that stays
/// indented.
fn write_snapshot(path: &PathBuf, value: &model::Snapshot) -> Result<()> {
    ensure_parent(path)?;
    let text = serde_json::to_string(value).context("serialising")?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// Write a diff: indented, because it is read by people and reviewed in a PR.
fn write_diff(path: &PathBuf, value: &diff::Diff) -> Result<()> {
    ensure_parent(path)?;
    let text = serde_json::to_string_pretty(value).context("serialising")?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}
