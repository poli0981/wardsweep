//! `wardsweep` — the command-line frontend.
//!
//! `docs/11-CLI-REFERENCE.md` describes the full surface: `scan`, `plan`,
//! `apply`, `resume`, `rollback`, `quarantine`, `report`, `catalog`, `observe`.
//! This build implements only `catalog`, because only the catalog machinery
//! exists — `docs/19-ROADMAP.md` v0.1 is audit-only and `docs/13-P0-SPIKES.md`
//! gates the rest behind seven recorded spike verdicts.
//!
//! The unimplemented subcommands are **absent** rather than present-and-stubbed.
//! `wardsweep apply` returning "not implemented" reads like a temporary outage;
//! an unrecognised subcommand reads like what it is. This tool is going to ask
//! people to trust it with their drivers, and that starts with not overstating
//! what it can do.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wardsweep_core::catalog::{self, Catalog, validate, verify};

/// Success.
const EXIT_OK: u8 = 0;
/// Nothing found / nothing to do.
const EXIT_NOTHING: u8 = 1;
/// Catalog verification failed.
const EXIT_CATALOG_FAILED: u8 = 9;
/// Usage error.
const EXIT_USAGE: u8 = 64;

#[derive(Parser)]
#[command(
    name = "wardsweep",
    version,
    about = "Audit and remove anti-cheat-bearing games together with their anti-cheat.",
    long_about = None,
)]
struct Cli {
    /// Override the catalog location. Still signature-verified.
    #[arg(long, global = true, value_name = "PATH")]
    catalog: Option<PathBuf>,

    /// Override `%ProgramData%\WardSweep` (portable mode).
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect the loaded catalog.
    #[command(subcommand)]
    Catalog(CatalogCommand),
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Print catalog version, signature status and entry counts.
    Verify,
    /// List every anti-cheat the catalog defines.
    List,
    /// Show one anti-cheat entry in full.
    Show {
        /// The anti-cheat id.
        #[arg(long)]
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let usage_error = error.use_stderr();
            let _ = error.print();
            return ExitCode::from(if usage_error { EXIT_USAGE } else { EXIT_OK });
        }
    };

    let Command::Catalog(command) = &cli.command;
    let path = resolve_catalog_path(cli.catalog.as_deref(), cli.data_dir.as_deref());

    match load_verified(&path) {
        Err(code) => code,
        Ok(loaded) => run_catalog(command, &loaded),
    }
}

/// Where the catalog lives: `--catalog`, else under the data directory.
///
/// `docs/03-ARCHITECTURE.md` puts the shipping catalog at
/// `%ProgramData%\WardSweep\catalog\catalog.toml`; `--data-dir` relocates the
/// whole tree for portable mode and for test harnesses.
fn resolve_catalog_path(explicit: Option<&Path>, data_dir: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    let root = data_dir.map_or_else(default_data_dir, Path::to_path_buf);
    root.join("catalog").join("catalog.toml")
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("WardSweep")
}

struct Loaded {
    catalog: Catalog,
    path: PathBuf,
}

/// Read and verify a catalog, or produce the exit code to return.
///
/// Verification is unconditional (`docs/04-CATALOG-SCHEMA.md`). There is no
/// flag to skip it and no "used with a warning" path.
fn load_verified(path: &Path) -> Result<Loaded, ExitCode> {
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("no catalog at {}", path.display());
        eprintln!(
            "  pass --catalog <path>, or install one under %ProgramData%\\WardSweep\\catalog"
        );
        return Err(ExitCode::from(EXIT_NOTHING));
    };

    let signature_path = signature_path(path);
    let Ok(signature) = std::fs::read(&signature_path) else {
        eprintln!("no signature at {}", signature_path.display());
        eprintln!("  an unverified catalog is refused, never used with a warning");
        return Err(ExitCode::from(EXIT_CATALOG_FAILED));
    };

    if let Err(error) =
        verify::verify_detached(&bytes, &signature, verify::COMPILED_IN_PUBLIC_KEY_HEX)
    {
        eprintln!("catalog signature is not valid: {error}");
        return Err(ExitCode::from(EXIT_CATALOG_FAILED));
    }

    let catalog = match catalog::parse_bytes(&bytes) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("catalog is signed but not readable: {error}");
            return Err(ExitCode::from(EXIT_CATALOG_FAILED));
        }
    };

    // The same four checks catalog-verify.yml runs. A signature proves who
    // wrote the file, not that it is sound: a catalog signed with an older
    // tool, or by hand, can name a protected path and still verify. The
    // checks live in wardsweep-core precisely so that load time applies what
    // CI applied — and now it does.
    let problems: Vec<validate::Problem> = validate::validate(&catalog)
        .into_iter()
        .chain(validate::check_refs(&catalog))
        .chain(validate::check_denylist(&catalog))
        .chain(validate::audit_shared(&catalog, true))
        .collect();
    if !problems.is_empty() {
        eprintln!(
            "catalog is signed but fails {} integrity check(s), and is refused:",
            problems.len()
        );
        for problem in &problems {
            eprintln!("  {problem}");
        }
        return Err(ExitCode::from(EXIT_CATALOG_FAILED));
    }

    // docs/04-CATALOG-SCHEMA.md: "warns if minimum_app_version exceeds its own".
    match requires_newer(&catalog.minimum_app_version, wardsweep_core::VERSION) {
        Some(true) => eprintln!(
            "warning: this catalog expects WardSweep {} or later, and this is {}",
            catalog.minimum_app_version,
            wardsweep_core::VERSION
        ),
        Some(false) => {}
        None => eprintln!(
            "warning: cannot compare the catalog's minimum_app_version `{}` with {}",
            catalog.minimum_app_version,
            wardsweep_core::VERSION
        ),
    }

    Ok(Loaded {
        catalog,
        path: path.to_path_buf(),
    })
}

/// The detached signature beside a catalog: the catalog's own name plus
/// `.sig`, whatever that name is. `with_extension("toml.sig")` turned
/// `my.catalog` into `my.toml.sig`.
fn signature_path(catalog: &Path) -> PathBuf {
    let mut name = catalog.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Whether `required` names a later version than `running`, comparing dotted
/// numeric components and ignoring any pre-release or build suffix. `None` when
/// either is not a version this can read.
fn requires_newer(required: &str, running: &str) -> Option<bool> {
    let parse = |version: &str| -> Option<Vec<u64>> {
        version
            .trim()
            .split(['-', '+'])
            .next()?
            .split('.')
            .map(|component| component.parse().ok())
            .collect()
    };
    let (required, running) = (parse(required)?, parse(running)?);
    let width = required.len().max(running.len());
    let at = |parts: &[u64], index: usize| parts.get(index).copied().unwrap_or(0);
    for index in 0..width {
        let (want, have) = (at(&required, index), at(&running, index));
        if want != have {
            return Some(want > have);
        }
    }
    Some(false)
}

fn run_catalog(command: &CatalogCommand, loaded: &Loaded) -> ExitCode {
    let catalog = &loaded.catalog;
    match command {
        CatalogCommand::Verify => {
            println!("catalog:        {}", loaded.path.display());
            println!("schema version: {}", catalog.schema_version);
            println!(
                "catalog version:{}",
                format_args!(" {}", catalog.catalog_version)
            );
            println!("minimum app:    {}", catalog.minimum_app_version);
            println!("signature:      valid");
            println!(
                "entries:        {} anti-cheat, {} game, {} launcher",
                catalog.anticheat.len(),
                catalog.game.len(),
                catalog.launcher.len()
            );
            ExitCode::from(EXIT_OK)
        }
        CatalogCommand::List => {
            if catalog.anticheat.is_empty() {
                println!("the catalog defines no anti-cheat entries yet");
                println!(
                    "  entries must come from an observation diff — see docs/16-OBSERVATION-HARNESS.md"
                );
                return ExitCode::from(EXIT_NOTHING);
            }
            for ac in &catalog.anticheat {
                println!(
                    "{:<24} {:<10} shared={:<5} risk={:?}",
                    ac.id,
                    format!("{:?}", ac.kind).to_lowercase(),
                    ac.shared,
                    ac.risk
                );
            }
            ExitCode::from(EXIT_OK)
        }
        CatalogCommand::Show { id } => {
            let Some(ac) = catalog.anticheat.iter().find(|ac| &ac.id == id) else {
                eprintln!("no anti-cheat with id `{id}` in {}", loaded.path.display());
                return ExitCode::from(EXIT_NOTHING);
            };
            println!("{} ({})", ac.display, ac.id);
            println!("  kind:      {:?}", ac.kind);
            println!("  risk:      {:?}", ac.risk);
            println!("  shared:    {}", ac.shared);
            println!("  services:  {}", join_or_none(&ac.services));
            println!("  drivers:   {}", join_or_none(&ac.drivers));
            println!("  publisher: {}", join_or_none(&ac.authenticode_cn));
            for entry in &ac.paths {
                println!("  path       [{:?}] {}", entry.class, entry.path);
            }
            for entry in &ac.registry {
                println!("  registry   [{:?}] {}", entry.class, entry.key);
            }
            ExitCode::from(EXIT_OK)
        }
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_sits_beside_the_catalog_whatever_it_is_called() {
        assert_eq!(
            signature_path(Path::new("catalog/catalog.toml")),
            PathBuf::from("catalog/catalog.toml.sig")
        );
        assert_eq!(
            signature_path(Path::new("my.catalog")),
            PathBuf::from("my.catalog.sig")
        );
        assert_eq!(
            signature_path(Path::new("catalog")),
            PathBuf::from("catalog.sig")
        );
    }

    #[test]
    fn versions_compare_by_component_not_by_text() {
        assert_eq!(requires_newer("0.1.0", "0.0.1"), Some(true));
        assert_eq!(requires_newer("0.10.0", "0.9.0"), Some(true));
        assert_eq!(requires_newer("0.9.0", "0.10.0"), Some(false));
        assert_eq!(requires_newer("1.0", "1.0.0"), Some(false));
        assert_eq!(requires_newer("1.2.0-beta", "1.2.0"), Some(false));
        assert_eq!(requires_newer("next", "0.0.1"), None);
    }
}
