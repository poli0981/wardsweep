//! `wardsweep` — the command-line frontend.
//!
//! `docs/11-CLI-REFERENCE.md` describes the full surface: `scan`, `plan`,
//! `apply`, `resume`, `rollback`, `quarantine`, `report`, `catalog`, `observe`.
//! This build implements `catalog`; `scan` in its audit mode, the read-only
//! detection `docs/19-ROADMAP.md` makes v0.1; and `observe`, which runs the
//! separate read-only harness. `docs/13-P0-SPIKES.md` gates the rest behind
//! recorded spike verdicts: the orphan and full scan modes need reference
//! counting, which waits for S2.
//!
//! The unimplemented subcommands are **absent** rather than present-and-stubbed.
//! `wardsweep apply` returning "not implemented" reads like a temporary outage;
//! an unrecognised subcommand reads like what it is. This tool is going to ask
//! people to trust it with their drivers, and that starts with not overstating
//! what it can do.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wardsweep_core::catalog::{self, Catalog, validate, verify};

/// Success.
const EXIT_OK: u8 = 0;
/// Nothing found / nothing to do.
const EXIT_NOTHING: u8 = 1;
/// The scan failed, or the harness could not be run at all.
const EXIT_SCAN_ERROR: u8 = 2;
/// A partial scan: something could not be read. Only a Windows scan can be.
#[cfg(any(windows, test))]
const EXIT_PARTIAL: u8 = 3;
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

    /// Audit this machine against the catalog. Reads only.
    ///
    /// Runs without elevation: what cannot be read is reported as unreadable,
    /// never as absent, and the scan exits 3 — run it elevated for a complete
    /// picture.
    Scan {
        /// What to look for.
        #[arg(long, value_enum, default_value_t = Mode::Audit)]
        mode: Mode,

        /// Newline-delimited JSON, one record per line, `"v": 1`; human text
        /// goes to stderr.
        #[arg(long)]
        json: bool,

        /// Write the output to a file instead of stdout.
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Run the read-only observation harness, `wardsweep-observe`.
    ///
    /// Every argument after `observe` is passed to it unchanged, `--help`
    /// included: `wardsweep observe snapshot -o x.json` is
    /// `wardsweep-observe snapshot -o x.json`. The harness is looked for
    /// beside this executable and nowhere else.
    #[command(disable_help_flag = true)]
    Observe {
        /// The harness's subcommand and its arguments.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<OsString>,
    },
}

/// What `scan` looks for (`docs/11-CLI-REFERENCE.md`).
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Every artifact of every anti-cheat the catalog defines.
    Audit,
    /// Anti-cheat no installed game references. Needs reference counting.
    Orphan,
    /// Both. Needs reference counting.
    Full,
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

    match &cli.command {
        // No catalog: the harness observes the machine, it does not consult
        // the catalog, and a missing or unsigned catalog must not stop it.
        Command::Observe { args } => run_observe(args),
        Command::Catalog(command) => {
            let path = resolve_catalog_path(cli.catalog.as_deref(), cli.data_dir.as_deref());
            match load_verified(&path) {
                Err(code) => ExitCode::from(code),
                Ok(loaded) => run_catalog(command, &loaded),
            }
        }
        Command::Scan { mode, json, output } => {
            if *mode != Mode::Audit {
                eprintln!(
                    "--mode orphan and --mode full need reference counting, which waits for \
                     spike S2 (docs/13-P0-SPIKES.md); this build audits"
                );
                return ExitCode::from(EXIT_USAGE);
            }
            let path = resolve_catalog_path(cli.catalog.as_deref(), cli.data_dir.as_deref());
            match load_verified(&path) {
                // A scan with no catalog looked for nothing: an error, never
                // "nothing found".
                Err(EXIT_NOTHING) => ExitCode::from(EXIT_SCAN_ERROR),
                Err(code) => ExitCode::from(code),
                Ok(loaded) => ExitCode::from(run_scan(&loaded, *json, output.as_deref())),
            }
        }
    }
}

/// The harness's file name on this platform.
fn harness_name() -> String {
    format!("wardsweep-observe{}", std::env::consts::EXE_SUFFIX)
}

/// Where the harness has to be: beside `exe`, the running CLI.
///
/// Never looked up on `PATH`, and never in the working directory, which is the
/// first place Windows searches for a bare program name. `docs/11` makes
/// `observe` a thin alias, and an alias that can be pointed at another program
/// by whoever controls the current directory is not one.
fn harness_beside(exe: &Path) -> PathBuf {
    exe.with_file_name(harness_name())
}

/// The CLI's exit code for the harness's: its own, when it fits.
///
/// The two binaries share `docs/11`'s table, so a code passes through. One that
/// does not fit a byte — a Windows status such as an access violation — or a
/// process ended without one is reported as the scan having failed.
fn exit_code_of(code: Option<i32>) -> u8 {
    code.and_then(|code| u8::try_from(code).ok())
        .unwrap_or(EXIT_SCAN_ERROR)
}

fn run_observe(args: &[OsString]) -> ExitCode {
    let harness = match std::env::current_exe() {
        Ok(exe) => harness_beside(&exe),
        Err(error) => {
            eprintln!("cannot tell where this executable is, so cannot find the harness: {error}");
            return ExitCode::from(EXIT_SCAN_ERROR);
        }
    };
    if !harness.is_file() {
        eprintln!(
            "the observation harness is not installed: {} does not exist",
            harness.display()
        );
        eprintln!(
            "  it is a separate download on the release page (docs/14-DISTRIBUTION-TRUST.md), \
             or build it with `cargo build --release -p wardsweep-observe`, and put {} in {}",
            harness_name(),
            harness.parent().map_or_else(
                || "this executable".to_owned(),
                |dir| dir.display().to_string()
            )
        );
        return ExitCode::from(EXIT_SCAN_ERROR);
    }
    match std::process::Command::new(&harness).args(args).status() {
        Ok(status) => ExitCode::from(exit_code_of(status.code())),
        Err(error) => {
            eprintln!("cannot run {}: {error}", harness.display());
            ExitCode::from(EXIT_SCAN_ERROR)
        }
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
fn load_verified(path: &Path) -> Result<Loaded, u8> {
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("no catalog at {}", path.display());
        eprintln!(
            "  pass --catalog <path>, or install one under %ProgramData%\\WardSweep\\catalog"
        );
        return Err(EXIT_NOTHING);
    };

    let signature_path = signature_path(path);
    let Ok(signature) = std::fs::read(&signature_path) else {
        eprintln!("no signature at {}", signature_path.display());
        eprintln!("  an unverified catalog is refused, never used with a warning");
        return Err(EXIT_CATALOG_FAILED);
    };

    if let Err(error) =
        verify::verify_detached(&bytes, &signature, verify::COMPILED_IN_PUBLIC_KEY_HEX)
    {
        eprintln!("catalog signature is not valid: {error}");
        return Err(EXIT_CATALOG_FAILED);
    }

    let catalog = match catalog::parse_bytes(&bytes) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("catalog is signed but not readable: {error}");
            return Err(EXIT_CATALOG_FAILED);
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
        return Err(EXIT_CATALOG_FAILED);
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

/// Audit this machine, write the report, and say how the scan went.
#[cfg(windows)]
fn run_scan(loaded: &Loaded, json: bool, file: Option<&Path>) -> u8 {
    use wardsweep_core::scan::{engine, win};

    let report = engine::audit(&loaded.catalog, &win::Machine, &win::environment());
    let text = if json {
        match report.to_ndjson() {
            Ok(text) => text,
            Err(error) => {
                eprintln!("the report could not be written as JSON: {error}");
                return EXIT_SCAN_ERROR;
            }
        }
    } else {
        output::render(&report, &loaded.catalog)
    };
    match file {
        Some(path) => {
            if let Err(error) = std::fs::write(path, text) {
                eprintln!("cannot write {}: {error}", path.display());
                return EXIT_SCAN_ERROR;
            }
        }
        None => print!("{text}"),
    }
    // With --json, stdout is the records' alone; the verdict is for a person.
    if json || file.is_some() {
        eprintln!("{}", output::verdict(&report));
    }
    output::exit_code(&report)
}

/// `scan` reads a Windows machine; elsewhere there is none to read.
#[cfg(not(windows))]
fn run_scan(_loaded: &Loaded, _json: bool, _file: Option<&Path>) -> u8 {
    eprintln!("scan reads a Windows machine, and this is not one");
    EXIT_SCAN_ERROR
}

/// How a scan's report reads and what it exits with. Pure, so its tests run on
/// every platform; outside them only Windows has a machine to report on.
#[cfg(any(windows, test))]
mod output {
    use std::fmt::Write as _;

    use wardsweep_core::catalog::Catalog;
    use wardsweep_core::scan::model::{Artifact, Classification, RegView, Report};

    use super::{EXIT_NOTHING, EXIT_OK, EXIT_PARTIAL};

    /// `docs/11`: findings 0, nothing 1, partial 3. Partial wins: a scan that could
    /// not read everything has not found everything, whatever it did find.
    pub(super) fn exit_code(report: &Report) -> u8 {
        if report.partial() {
            EXIT_PARTIAL
        } else if report.findings.is_empty() {
            EXIT_NOTHING
        } else {
            EXIT_OK
        }
    }

    /// The report for a person: findings by anti-cheat, then what was protected,
    /// disbelieved and unreadable, then the verdict.
    pub(super) fn render(report: &Report, catalog: &Catalog) -> String {
        let mut text = String::new();
        let mut current: Option<&str> = None;
        for finding in &report.findings {
            if current != Some(finding.anticheat.as_str()) {
                current = Some(finding.anticheat.as_str());
                let display = catalog
                    .anticheat
                    .iter()
                    .find(|entry| entry.id == finding.anticheat)
                    .map_or(finding.anticheat.as_str(), |entry| entry.display.as_str());
                let _ = writeln!(text, "{display} ({})", finding.anticheat);
            }
            let _ = writeln!(
                text,
                "  {:<11} {}",
                classification_name(finding.classification),
                describe(&finding.artifact)
            );
            for line in &finding.evidence {
                let _ = writeln!(text, "              {line}");
            }
        }
        for item in &report.protected {
            let _ = writeln!(
                text,
                "protected   {} ({}): {}",
                item.target, item.anticheat, item.reason
            );
        }
        for item in &report.disbelieved {
            let _ = writeln!(
                text,
                "disbelieved {} ({}): {}",
                item.item, item.anticheat, item.reason
            );
        }
        for item in &report.unreadable {
            let _ = writeln!(text, "unreadable  {}: {}", item.item, item.reason);
        }
        let _ = writeln!(text, "{}", verdict(report));
        text
    }

    fn classification_name(classification: Classification) -> &'static str {
        match classification {
            Classification::Confirmed => "confirmed",
            Classification::Probable => "probable",
            Classification::Suspicious => "suspicious",
        }
    }

    fn describe(artifact: &Artifact) -> String {
        match artifact {
            Artifact::Service {
                name,
                registry_only: true,
                ..
            } => format!("service {name}, in the registry only"),
            Artifact::Service { name, .. } => format!("service {name}"),
            Artifact::Driver {
                file,
                service,
                image_present,
                ..
            } => {
                let registered = service
                    .as_ref()
                    .map_or_else(String::new, |service| format!(", registered as {service}"));
                let missing = if *image_present {
                    ""
                } else {
                    ", image not on disk"
                };
                format!("driver {file}{registered}{missing}")
            }
            Artifact::RegistryKey {
                key,
                view: RegView::Bits64,
            } => format!("key {key}, 64-bit view"),
            Artifact::RegistryKey {
                key,
                view: RegView::Bits32,
            } => format!("key {key}, 32-bit view"),
            Artifact::Path {
                path,
                directory: true,
            } => format!("folder {path}"),
            Artifact::Path { path, .. } => format!("file {path}"),
        }
    }

    /// One line on how the scan went.
    pub(super) fn verdict(report: &Report) -> String {
        let found = format!(
            "{} finding(s): {} confirmed, {} probable, {} suspicious",
            report.findings.len(),
            report.count(Classification::Confirmed),
            report.count(Classification::Probable),
            report.count(Classification::Suspicious)
        );
        if report.partial() {
            format!(
                "{found}. Partial: {} item(s) could not be read; run elevated for a complete picture",
                report.unreadable.len()
            )
        } else {
            format!("{found}.")
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
    use wardsweep_core::scan::model::{Classification, Report};

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
    fn the_harness_is_looked_for_beside_the_cli_and_nowhere_else() {
        let exe = Path::new("install").join(format!("wardsweep{}", std::env::consts::EXE_SUFFIX));

        assert_eq!(
            harness_beside(&exe),
            Path::new("install").join(format!("wardsweep-observe{}", std::env::consts::EXE_SUFFIX))
        );
    }

    #[test]
    fn everything_after_observe_reaches_the_harness_unchanged() {
        let parsed = |args: &[&str]| -> Vec<OsString> {
            match Cli::try_parse_from(args).expect("parses").command {
                Command::Observe { args } => args,
                _ => panic!("parsed as another command"),
            }
        };

        assert_eq!(
            parsed(&[
                "wardsweep",
                "observe",
                "snapshot",
                "-o",
                "x.json",
                "--label",
                "a b"
            ]),
            ["snapshot", "-o", "x.json", "--label", "a b"]
        );
        // The harness's help, not this one's.
        assert_eq!(parsed(&["wardsweep", "observe", "--help"]), ["--help"]);
        assert_eq!(
            parsed(&["wardsweep", "observe", "diff", "--no-filter"]),
            ["diff", "--no-filter"]
        );
    }

    #[test]
    fn the_harness_exit_code_passes_through_when_it_can() {
        assert_eq!(exit_code_of(Some(0)), 0);
        assert_eq!(exit_code_of(Some(1)), 1);
        // STATUS_ACCESS_VIOLATION, as Windows reports a crashed process.
        assert_eq!(exit_code_of(Some(-1_073_741_819)), EXIT_SCAN_ERROR);
        assert_eq!(exit_code_of(None), EXIT_SCAN_ERROR);
    }

    #[test]
    fn scan_parses_the_way_docs_11_writes_it() {
        let parsed = |args: &[&str]| match Cli::try_parse_from(args).expect("parses").command {
            Command::Scan { mode, json, output } => (mode, json, output),
            _ => panic!("parsed as another command"),
        };

        let (mode, json, output) = parsed(&[
            "wardsweep",
            "scan",
            "--mode",
            "audit",
            "--json",
            "-o",
            "audit.json",
        ]);
        assert!(mode == Mode::Audit && json);
        assert_eq!(output, Some(PathBuf::from("audit.json")));

        let (mode, json, output) = parsed(&["wardsweep", "scan"]);
        assert!(mode == Mode::Audit && !json && output.is_none());

        // Parsed, so that the refusal can say why rather than "invalid value".
        assert!(parsed(&["wardsweep", "scan", "--mode", "orphan"]).0 == Mode::Orphan);
        assert!(Cli::try_parse_from(["wardsweep", "scan", "--mode", "deep"]).is_err());
    }

    fn report(findings: Vec<Classification>, unreadable: usize) -> Report {
        use wardsweep_core::catalog::schema::Risk;
        use wardsweep_core::scan::model::{Artifact, Finding, REPORT_VERSION, Unreadable};

        Report {
            v: REPORT_VERSION,
            findings: findings
                .into_iter()
                .map(|classification| Finding {
                    anticheat: "example-ac".to_owned(),
                    risk: Risk::High,
                    artifact: Artifact::Driver {
                        file: "ExampleAC.sys".to_owned(),
                        service: Some("ExampleAC".to_owned()),
                        image: r"C:\Windows\System32\drivers\ExampleAC.sys".to_owned(),
                        image_present: false,
                    },
                    classification,
                    evidence: vec!["registered by `ExampleAC`".to_owned()],
                })
                .collect(),
            protected: Vec::new(),
            disbelieved: Vec::new(),
            unreadable: (0..unreadable)
                .map(|_| Unreadable {
                    anticheat: None,
                    item: r"HKLM\SYSTEM\CurrentControlSet\Services\Locked".to_owned(),
                    reason: "access denied".to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_partial_scan_exits_3_whatever_it_found() {
        assert_eq!(
            output::exit_code(&report(vec![Classification::Confirmed], 0)),
            EXIT_OK
        );
        assert_eq!(output::exit_code(&report(Vec::new(), 0)), EXIT_NOTHING);
        assert_eq!(output::exit_code(&report(Vec::new(), 1)), EXIT_PARTIAL);
        assert_eq!(
            output::exit_code(&report(vec![Classification::Confirmed], 1)),
            EXIT_PARTIAL
        );
    }

    #[test]
    fn the_human_report_names_the_entry_and_says_when_it_is_partial() {
        let catalog = catalog::parse(
            "schema_version = 1\n\
             catalog_version = \"0.0.1-test\"\n\
             minimum_app_version = \"0.1.0\"\n\n\
             [[anticheat]]\n\
             id = \"example-ac\"\n\
             display = \"Example AC\"\n\
             kind = \"kernel\"\n\
             shared = true\n\
             risk = \"high\"\n",
        )
        .expect("the test catalog parses");

        let text = output::render(&report(vec![Classification::Probable], 1), &catalog);

        assert!(text.starts_with("Example AC (example-ac)\n"), "{text}");
        assert!(
            text.contains(
                "  probable    driver ExampleAC.sys, registered as ExampleAC, image not on disk\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "unreadable  HKLM\\SYSTEM\\CurrentControlSet\\Services\\Locked: access denied\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("Partial: 1 item(s) could not be read"),
            "{text}"
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
