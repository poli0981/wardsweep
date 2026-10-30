//! `wardsweep-broker` — the elevated, headless half of the split-privilege
//! architecture described in `docs/03-ARCHITECTURE.md`.
//!
//! It does nothing yet, and saying so precisely is the point of this build.
//! The split-privilege design passed spike **S3** (`spikes/S3-RESULT.md`),
//! the root of the dependency graph in `docs/13-P0-SPIKES.md`. There is still
//! no IPC server, no pipe DACL and no job state: they are written to
//! `docs/08-IPC-PROTOCOL.md` as S3 amended it, not yet.
//!
//! What this binary establishes now is the boundary: it exists, it is separate
//! from the UI, and it is the only place elevated work will ever happen.

use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "wardsweep-broker",
    version,
    about = "Elevated headless broker. Not operational in this build.",
    long_about = None,
)]
struct Cli {
    /// Session GUID naming the pipe the UI will connect on.
    ///
    /// Accepted so the contract in `docs/08-IPC-PROTOCOL.md` is fixed early,
    /// even though no pipe is created yet.
    #[arg(long, value_name = "GUID")]
    session: Option<String>,
}

fn main() -> ExitCode {
    let _cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        version = wardsweep_core::VERSION,
        "broker started with no operational capability"
    );

    eprintln!(
        "wardsweep-broker {} has no IPC server and performs no operations.",
        wardsweep_core::VERSION
    );
    eprintln!("The split-privilege design passed spike S3; see spikes/S3-RESULT.md.");
    ExitCode::SUCCESS
}
