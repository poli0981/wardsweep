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
mod intersect;
mod model;
mod policy;
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

    /// Keep what every footprint has in common.
    ///
    /// For one anti-cheat observed under several titles, `docs/16`: what every
    /// footprint holds is the anti-cheat, and the rest is per-title
    /// integration. The result is a diff, so `suggest` drafts from it.
    Intersect {
        /// A footprint diff. Give at least two, each from a different title.
        #[arg(long = "diff", value_name = "PATH", required = true)]
        diffs: Vec<PathBuf>,
        /// Where to write the shared footprint.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },

    /// Apply this build's privacy policy to a diff that already exists.
    ///
    /// Drops what the current build refuses to keep — account identity,
    /// hardware identifiers, activity history — from a diff produced before the
    /// rule existed. `diff` applies the same policy to both snapshots, so this
    /// is only needed for a diff that is already written.
    Refilter {
        /// The diff to refilter.
        #[arg(long = "in", value_name = "PATH")]
        input: PathBuf,
        /// Where to write the refiltered diff.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },

    /// Replace usernames, machine-local SIDs and host names with placeholders.
    ///
    /// Required before a raw snapshot may be shared, per `docs/16`. It removes
    /// identity, not secrets — a person still reads the file before it is
    /// attached to anything.
    ///
    /// The local machine's computer and account names are removed as well,
    /// because a document has no reliable path to learn them from.
    Redact {
        /// The snapshot or diff to redact.
        #[arg(long = "in", value_name = "PATH")]
        input: PathBuf,
        /// Where to write the redacted copy.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
        /// Another account name to remove. Repeatable.
        ///
        /// For a file redacted once already, whose profile paths no longer
        /// name anyone to learn from.
        #[arg(long = "also-name", value_name = "NAME")]
        also_names: Vec<String>,
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
        Command::Intersect { diffs, output } => run_intersect(diffs, output),
        Command::Refilter { input, output } => run_refilter(input, output),
        Command::Redact {
            input,
            output,
            also_names,
        } => run_redact(input, output, also_names),
    }
}

fn run_refilter(input: &PathBuf, output: &PathBuf) -> Result<u8> {
    let mut diff: diff::Diff = read_json(input)?;
    ensure_readable_diff(input, &diff)?;
    let format = diff.format_version;
    let report = diff::refilter(&mut diff, &policy::Policy::current());

    write_diff(output, &diff)?;

    eprintln!("refiltered diff written to {}", output.display());
    if report.is_empty() {
        eprintln!("  nothing in it is refused by this build's policy");
    } else {
        report_refiltered(&report);
    }
    if format != diff.format_version {
        eprintln!(
            "  upgraded from diff format {format} to {}: a modified key now carries only the \
             values that changed. Its snapshots stay format {}, and nothing they did not \
             record can be added.",
            diff.format_version, diff.snapshot_format_version
        );
    }
    Ok(exit::SUCCESS)
}

fn run_intersect(paths: &[PathBuf], output: &PathBuf) -> Result<u8> {
    let mut footprints = Vec::with_capacity(paths.len());
    for path in paths {
        let footprint: diff::Diff = read_json(path)?;
        ensure_readable_diff(path, &footprint)?;
        footprints.push(footprint);
    }

    let shared = intersect::intersect(footprints).context("intersecting the footprints")?;
    write_diff(output, &shared)?;

    eprintln!(
        "shared footprint written to {} — {} service change(s), {} file change(s), {} registry \
         change(s) held by every footprint",
        output.display(),
        shared.services.len(),
        shared.files.len(),
        shared.registry.len()
    );
    report_refiltered(&shared.refiltered);
    let held = shared.services.len()
        + shared.suppressed.len()
        + shared.files.len()
        + shared.suppressed_files.len()
        + shared.registry.len();
    for (path, source) in paths.iter().zip(shared.intersection_of.iter().flatten()) {
        eprintln!(
            "  {}: {} change(s), {} of them not in every other footprint",
            path.display(),
            source.changes,
            source.changes.saturating_sub(held)
        );
    }
    if shared.filesystem_policy_changed || shared.registry_policy_changed {
        eprintln!(
            "  WARNING: at least one footprint was taken across a policy change, and its \
             differences may be the harness rather than an installer."
        );
    }
    if !shared.coverage.not_captured.is_empty() {
        eprintln!(
            "  this footprint says nothing about: {}",
            shared
                .coverage
                .not_captured
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // Said every time: the one way an intersection goes wrong without looking
    // wrong.
    eprintln!(
        "  a title observed with the anti-cheat already installed has it missing from its \
         footprint, and so does the intersection"
    );

    if held == 0 {
        eprintln!("nothing is held by every footprint");
        return Ok(exit::NOTHING);
    }
    Ok(exit::SUCCESS)
}

/// Refuse a diff whose shape this build does not know. Without this it would
/// be read, not refused, whenever its fields happened to line up.
fn ensure_readable_diff(path: &Path, read: &diff::Diff) -> Result<()> {
    anyhow::ensure!(
        (diff::OLDEST_DIFF_FORMAT..=diff::DIFF_FORMAT_VERSION).contains(&read.format_version),
        "{} is diff format version {}, and this build reads {} to {}",
        path.display(),
        read.format_version,
        diff::OLDEST_DIFF_FORMAT,
        diff::DIFF_FORMAT_VERSION
    );
    Ok(())
}

/// Say what the privacy policy removed. Never silent: a diff that lost records
/// must say so, or a reader will take their absence for "nothing changed".
fn report_refiltered(report: &diff::Refiltered) {
    if report.is_empty() {
        return;
    }
    eprintln!(
        "  removed by this build's privacy policy (identity, hardware identifiers, activity \
         history): {} registry record(s), {} value(s), {} unreadable-item record(s), {} empty \
         key(s)",
        report.registry_records, report.registry_values, report.access_denied, report.emptied_keys
    );
}

fn run_suggest(
    diff_path: &PathBuf,
    residue_path: Option<&PathBuf>,
    signer: Option<&str>,
    output: &PathBuf,
) -> Result<u8> {
    let footprint: diff::Diff = read_json(diff_path)?;
    let residue: Option<diff::Diff> = residue_path.map(read_json).transpose()?;

    // The same refusal `diff` applies to a snapshot it does not implement.
    for (path, read) in
        std::iter::once((diff_path, &footprint)).chain(residue_path.zip(residue.as_ref()))
    {
        ensure_readable_diff(path, read)?;
    }

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

fn run_redact(input: &PathBuf, output: &PathBuf, also_names: &[String]) -> Result<u8> {
    let mut document: serde_json::Value = read_json(input)?;

    // The machine this runs on is almost always the machine the snapshot came
    // from, and its names reach a document without a profile path to learn
    // them from — OneDrive's host-name list, an application's "last user".
    let local = |variable: &str| {
        std::env::var(variable)
            .ok()
            .filter(|v| !v.trim().is_empty())
    };
    let extra = redact::Extra {
        accounts: also_names
            .iter()
            .cloned()
            .chain(local("USERNAME"))
            .collect(),
        computers: local("COMPUTERNAME").into_iter().collect(),
    };
    let report = redact::redact_document(&mut document, &extra);

    ensure_parent(output)?;
    let text = serde_json::to_string(&document).context("serialising")?;
    std::fs::write(output, text).with_context(|| format!("writing {}", output.display()))?;

    eprintln!("redacted copy written to {}", output.display());
    if !report.names.is_empty() {
        eprintln!("  account name(s) looked for: {}", report.names.join(", "));
    }
    if !report.computers.is_empty() {
        eprintln!(
            "  computer name(s) looked for: {}",
            report.computers.join(", ")
        );
    }
    for name in &report.skipped {
        eprintln!(
            "  NOT APPLIED: `{name}` is shorter than {} characters and would match too much \
             to replace safely. Search the file for it yourself.",
            redact::MIN_NAME_LEN
        );
    }
    if report.applied.is_empty() {
        eprintln!("  no identifying strings were found");
    }
    for (placeholder, count) in &report.applied {
        eprintln!("  {count} substitution(s) → {placeholder}");
    }

    // Never claim more than was done, and never tell the reader what the
    // residue probably is. The previous wording said it was "`Anonymous` and
    // the like"; in a committed diff it was an e-mail address.
    if report.residual.is_empty() {
        eprintln!("  no occurrence of a known name remains, in any letter case");
    } else {
        for (name, residual) in &report.residual {
            eprintln!(
                "  CHECK: `{name}` still appears {} time(s) where replacing it could corrupt \
                 unrelated text — inside a longer word, or glued to other characters. Read \
                 every one before sharing; the first few, with the name masked:",
                residual.count
            );
            for context in &residual.contexts {
                eprintln!("      {context}");
            }
        }
    }
    eprintln!("  this removes identity, not secrets — read the file before sharing it (docs/16)");

    if report.residual.is_empty() && report.skipped.is_empty() {
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
        "snapshot written to {} — {} services, {} files, {} registry keys ({} more standing \
         empty), {} unreadable",
        output.display(),
        snapshot.services.len(),
        snapshot.files.len(),
        snapshot.registry.len(),
        snapshot.registry_empty_keys.as_ref().map_or(0, Vec::len),
        snapshot.coverage.access_denied.len()
    );
    // A snapshot spans minutes, so say how many. A reader who assumes it is an
    // instant will eventually compare two domains that were read far enough
    // apart for the machine to have changed between them.
    if snapshot.domain_started_utc.len() > 1 {
        let starts: Vec<&String> = snapshot.domain_started_utc.values().collect();
        if let (Some(first), Some(last)) = (starts.iter().min(), starts.iter().max()) {
            eprintln!("capture spanned {first} to {last} — a snapshot is not an instant");
        }
    }

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
    report_refiltered(&diff.refiltered);
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
    match diff.rebooted_between {
        // Loud, because it is the loudest cause of change there is and it is
        // invisible in the lists below.
        Some(true) => eprintln!(
            "  WARNING: the machine restarted between these two snapshots. \
             Drivers loaded and unloaded, per-user service instances were \
             recreated, and any pending file renames were carried out — none \
             of that was the subject of the observation."
        ),
        Some(false) => {}
        None => eprintln!(
            "  whether the machine restarted between these snapshots is not \
             known: one of them predates `boot_session`"
        ),
    }
    match &diff.emptied_directories {
        Some(directories) if !directories.is_empty() => {
            eprintln!(
                "  {} director(ies) left standing with nothing in them:",
                directories.len()
            );
            for directory in directories {
                eprintln!("    {directory}");
            }
        }
        Some(_) => {}
        None => eprintln!(
            "  emptied directories are not known: one of these snapshots did not record them"
        ),
    }
    match &diff.emptied_keys {
        Some(keys) if !keys.is_empty() => {
            eprintln!(
                "  {} registry key(s) left standing with no value in them:",
                keys.len()
            );
            for key in keys {
                eprintln!("    {} [view {}]", key.key, key.view);
            }
        }
        Some(_) => {}
        None => eprintln!(
            "  emptied registry keys are not known: these snapshots did not both record them"
        ),
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
