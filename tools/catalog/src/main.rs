//! `wardsweep-catalog` — the catalog integrity gate.
//!
//! Every subcommand here is invoked verbatim by
//! `.github/workflows/catalog-verify.yml`. The job's whole purpose is that a
//! catalog which would be refused at runtime fails CI instead of shipping and
//! failing on a user's machine, so the checks live in `wardsweep-core` and are
//! shared with the broker rather than reimplemented.
//!
//! The tool builds and runs on Linux. That is a hard requirement, not a nicety:
//! `catalog-verify.yml` runs on `ubuntu-latest`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use wardsweep_core::catalog::{self, Catalog, validate, verify};

/// Everything is fine.
const EXIT_OK: u8 = 0;
/// Catalog verification failed — `docs/11-CLI-REFERENCE.md` exit code table.
const EXIT_CATALOG_FAILED: u8 = 9;
/// The command line itself was wrong.
const EXIT_USAGE: u8 = 64;

#[derive(Parser)]
#[command(
    name = "wardsweep-catalog",
    version,
    about = "Validate, verify and audit a WardSweep anti-cheat catalog.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check schema, enums, identifiers and field constraints.
    Validate {
        /// Path to the catalog TOML.
        toml: PathBuf,
    },
    /// Verify the detached Ed25519 signature over the catalog's raw bytes.
    Verify {
        /// Path to the catalog TOML.
        #[arg(long)]
        toml: PathBuf,
        /// Path to the detached signature.
        #[arg(long)]
        sig: PathBuf,
        /// Path to the hex-encoded public key.
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Expand every path and registry key and run it through the deny-list.
    CheckDenylist {
        /// Path to the catalog TOML.
        toml: PathBuf,
    },
    /// Check that every referenced id exists and that no id is reused.
    CheckRefs {
        /// Path to the catalog TOML.
        toml: PathBuf,
    },
    /// Audit `shared = false` claims.
    AuditShared {
        /// Path to the catalog TOML.
        toml: PathBuf,
        /// Fail unless every `shared = false` entry carries evidence.
        #[arg(long)]
        require_evidence: bool,
    },
    /// Generate a signing key pair. Maintainer use; not run in CI.
    Keygen {
        /// Where to write the hex-encoded secret key. Never inside the repository.
        #[arg(long)]
        out_secret: PathBuf,
        /// Where to write the hex-encoded public key, normally `catalog/pubkey.hex`.
        #[arg(long)]
        out_public: PathBuf,
    },
    /// Sign a catalog. Maintainer use; not run in CI.
    Sign {
        /// Path to the catalog TOML.
        #[arg(long)]
        toml: PathBuf,
        /// Path to the hex-encoded secret key.
        #[arg(long)]
        secret: PathBuf,
        /// Where to write the detached signature.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` arrive here too, and are not failures.
            let usage_error = error.use_stderr();
            let _ = error.print();
            return ExitCode::from(if usage_error { EXIT_USAGE } else { EXIT_OK });
        }
    };

    match run(&cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_CATALOG_FAILED)
        }
    }
}

fn run(command: &Command) -> Result<u8> {
    match command {
        Command::Validate { toml } => {
            let catalog = load(toml)?;
            Ok(report(
                toml,
                "schema validation",
                &validate::validate(&catalog),
            ))
        }
        Command::CheckRefs { toml } => {
            let catalog = load(toml)?;
            Ok(report(
                toml,
                "referential integrity",
                &validate::check_refs(&catalog),
            ))
        }
        Command::CheckDenylist { toml } => {
            let catalog = load(toml)?;
            Ok(report(
                toml,
                "deny-list conflict check",
                &validate::check_denylist(&catalog),
            ))
        }
        Command::AuditShared {
            toml,
            require_evidence,
        } => {
            let catalog = load(toml)?;
            let problems = validate::audit_shared(&catalog, *require_evidence);
            Ok(report(toml, "shared-flag audit", &problems))
        }
        Command::Verify { toml, sig, pubkey } => verify_signature(toml, sig, pubkey),
        Command::Keygen {
            out_secret,
            out_public,
        } => keygen(out_secret, out_public),
        Command::Sign { toml, secret, out } => sign(toml, secret, out),
    }
}

fn load(path: &Path) -> Result<Catalog> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read catalog at {}", path.display()))?;
    catalog::parse_bytes(&bytes).with_context(|| format!("cannot parse {}", path.display()))
}

/// Print findings and turn them into an exit code.
fn report(path: &Path, check: &str, problems: &[validate::Problem]) -> u8 {
    if problems.is_empty() {
        println!("ok: {} passed {check}", path.display());
        return EXIT_OK;
    }
    eprintln!(
        "{}: {check} found {} problem{}:",
        path.display(),
        problems.len(),
        if problems.len() == 1 { "" } else { "s" }
    );
    for problem in problems {
        eprintln!("  {problem}");
    }
    EXIT_CATALOG_FAILED
}

fn verify_signature(toml: &Path, sig: &Path, pubkey: &Path) -> Result<u8> {
    let body = std::fs::read(toml)
        .with_context(|| format!("cannot read catalog at {}", toml.display()))?;
    let signature = std::fs::read(sig)
        .with_context(|| format!("cannot read signature at {}", sig.display()))?;
    let key = std::fs::read_to_string(pubkey)
        .with_context(|| format!("cannot read public key at {}", pubkey.display()))?;

    match verify::verify_detached(&body, &signature, &key) {
        Ok(()) => {
            let parsed = catalog::parse_bytes(&body)?;
            println!(
                "ok: {} signature verifies (catalog_version {}, {} anti-cheat, {} game, {} launcher)",
                toml.display(),
                parsed.catalog_version,
                parsed.anticheat.len(),
                parsed.game.len(),
                parsed.launcher.len(),
            );
            Ok(EXIT_OK)
        }
        Err(error) => {
            eprintln!("{}: signature verification failed: {error}", toml.display());
            // Naming the likeliest cause, because this is the failure that
            // wastes the most time when it happens on a CI runner.
            if matches!(error, verify::VerifyError::SignatureMismatch) {
                eprintln!(
                    "  the signature covers raw bytes; check .gitattributes still marks \
                     catalog/*.toml as -text so line endings survive checkout"
                );
            }
            Ok(EXIT_CATALOG_FAILED)
        }
    }
}

fn keygen(out_secret: &Path, out_public: &Path) -> Result<u8> {
    if out_secret.exists() {
        bail!(
            "{} already exists; refusing to overwrite a signing key",
            out_secret.display()
        );
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("cannot read OS randomness")?;

    let signing = SigningKey::from_bytes(&seed);
    let public_hex = hex::encode(signing.verifying_key().to_bytes());

    std::fs::write(out_secret, format!("{}\n", hex::encode(seed)))
        .with_context(|| format!("cannot write {}", out_secret.display()))?;
    std::fs::write(out_public, format!("{public_hex}\n"))
        .with_context(|| format!("cannot write {}", out_public.display()))?;

    println!("public key: {public_hex}");
    println!("written:    {}", out_public.display());
    eprintln!(
        "the secret key is at {} — it must never enter the repository, and \
         anyone holding it can sign a catalog this build will trust",
        out_secret.display()
    );
    Ok(EXIT_OK)
}

fn sign(toml: &Path, secret: &Path, out: &Path) -> Result<u8> {
    let body = std::fs::read(toml).with_context(|| format!("cannot read {}", toml.display()))?;

    // Signing something that does not parse would produce a catalog that is
    // authentically broken.
    let parsed = catalog::parse_bytes(&body)?;
    let problems = validate::validate(&parsed);
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("  {problem}");
        }
        bail!("refusing to sign a catalog that fails validation");
    }

    let seed_hex = std::fs::read_to_string(secret)
        .with_context(|| format!("cannot read secret key at {}", secret.display()))?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("secret key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key is not 32 bytes"))?;

    let signature = SigningKey::from_bytes(&seed).sign(&body);
    std::fs::write(out, signature.to_bytes())
        .with_context(|| format!("cannot write {}", out.display()))?;

    println!("signed {} -> {}", toml.display(), out.display());
    Ok(EXIT_OK)
}
