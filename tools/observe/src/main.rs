//! `wardsweep-observe` — the read-only snapshot and diff harness.
//!
//! A separate binary from the broker on purpose. `docs/16-OBSERVATION-HARNESS.md`:
//! "Snapshots are **read-only**. The harness has no removal code path at all —
//! it is a separate binary from the broker for exactly this reason."
//!
//! `wardsweep observe …` in `docs/11-CLI-REFERENCE.md` will forward to this
//! executable rather than linking its logic into the broker frontend, so the
//! documented UX and the process boundary both hold.
//!
//! Not implemented. It is a v0.1 deliverable (`docs/19-ROADMAP.md`), and it is
//! the highest-value thing to build next: `CONTRIBUTING.md` ranks an
//! observation diff from a real install/uninstall cycle above any amount of
//! code, because no catalog entry may ship without one.

use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "wardsweep-observe",
    version,
    about = "Read-only snapshot and diff harness for building catalog entries.",
    long_about = None,
)]
struct Cli;

fn main() -> ExitCode {
    let _cli = Cli::parse();

    eprintln!(
        "wardsweep-observe {} is not implemented yet.",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("Planned surface: snapshot, diff, suggest, intersect, redact.");
    eprintln!("See docs/16-OBSERVATION-HARNESS.md.");
    ExitCode::SUCCESS
}
