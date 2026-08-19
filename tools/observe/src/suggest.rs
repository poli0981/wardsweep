//! Turning a diff into a draft catalog entry.
//!
//! `docs/16-OBSERVATION-HARNESS.md`: "`suggest` emits a **draft** catalog entry.
//! It is a starting point requiring human review, never a finished entry."
//!
//! # Built on the real schema, not a copy of it
//!
//! The draft is constructed as a [`wardsweep_core::catalog::schema::AntiCheat`]
//! and serialised from that. Writing the TOML by hand would be less code and
//! would drift: a field added to the schema would simply stop appearing in
//! drafts, and the only thing that would notice is `catalog-verify` failing on
//! a contributor's pull request long afterwards.
//!
//! # Inference is deliberately conservative
//!
//! `docs/16` gives the table, and every rule in it resolves *towards* the
//! answer that removes less:
//!
//! | Observation | Inferred |
//! |---|---|
//! | Driver service created | `kind = "kernel"` |
//! | `SERVICE_BOOT_START` | `risk = "critical"` |
//! | No driver, only a user-mode service | `kind = "usermode"` |
//! | Anything unknown | the most conservative value |
//!
//! `shared` is always `true`. `docs/04-CATALOG-SCHEMA.md`: a wrong
//! `shared = false` removes an anti-cheat another installed game still needs,
//! which is the G1 violation the project exists to prevent. Downgrading it is a
//! claim a person makes with evidence from several titles, not something a
//! generator infers from one.
//!
//! # Two filters, both learned from a real run
//!
//! The first draft this module produced from a real observation contained
//! `%SystemRoot%\System32\drivers`, a running application's `leveldb`
//! directory, and a token-broker cache. All three were ordinary machine churn
//! between the two snapshots, swept in because every added path was taken.
//!
//! So a path now has to be **attributable**: some file under it must carry the
//! chosen publisher's signature, or be one of the observed service or driver
//! images. Everything else becomes a review note naming what was dropped.
//!
//! And the draft is checked against the **same deny-list the broker enforces at
//! runtime**, not a copy of its intent. A generator that proposes a path the
//! runtime would refuse has produced an entry that cannot work, and the person
//! reviewing it has no way to know that by reading it.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use wardsweep_core::catalog::schema::{
    AntiCheat, Class, Kind, PathEntry, RegistryEntry, Risk, View,
};

use wardsweep_core::safety::denylist::{Exceptions, Stage, check_path, check_registry_key};
use wardsweep_core::safety::paths::{canonicalise_reg_key, canonicalise_syntactic};

use crate::diff::{ChangeKind, Diff};

/// Path prefixes replaced by the `%VAR%` templates `docs/04` allows.
///
/// Longest first: `%LOCALAPPDATA%` is inside `%USERPROFILE%`, and matching the
/// shorter one first would produce `%USERPROFILE%\AppData\Local\…`, which is
/// correct but loses the more specific variable a reviewer would expect.
const VARIABLES: &[(&str, &str)] = &[
    ("LOCALAPPDATA", "\\AppData\\Local"),
    ("APPDATA", "\\AppData\\Roaming"),
    ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
    ("ProgramFiles", "C:\\Program Files"),
    ("ProgramData", "C:\\ProgramData"),
    ("SystemRoot", "C:\\Windows"),
    ("PUBLIC", "C:\\Users\\Public"),
];

/// A draft entry and the notes a reviewer needs alongside it.
pub struct Draft {
    /// The entry itself, valid against the shipped schema.
    pub entry: AntiCheat,
    /// Signers seen in the diff, most files first.
    pub signers: Vec<(String, usize)>,
    /// Things the generator could not decide and a person must.
    pub review: Vec<String>,
}

/// Build a draft from a footprint diff, and optionally a residue diff.
///
/// The residue diff is the more valuable input: `docs/16` calls it "the exact
/// set of things the vendor's own uninstaller leaves behind — which is the
/// entire reason WardSweep exists". Anything in it is footprint the official
/// uninstaller misses, and is therefore what a catalog entry is *for*.
#[must_use]
pub fn draft(footprint: &Diff, residue: Option<&Diff>, signer: Option<&str>) -> Draft {
    let mut review = Vec::new();

    let mut signers: Vec<(String, usize)> = footprint
        .signers
        .iter()
        .map(|(name, count)| (name.clone(), *count))
        .collect();
    signers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // The signer to attribute the footprint to. Given explicitly, or the most
    // common one — but never silently, because on a machine that installed two
    // things at once the most common is not necessarily the right one.
    let chosen = signer
        .map(str::to_owned)
        .or_else(|| signers.first().map(|(name, _)| name.clone()));
    if signer.is_none() && signers.len() > 1 {
        review.push(format!(
            "several publishers appear in this diff ({}); the draft attributes it to `{}` \
             because it signed the most files. Re-run with --signer to choose another.",
            signers
                .iter()
                .map(|(name, count)| format!("{name} ×{count}"))
                .collect::<Vec<_>>()
                .join(", "),
            chosen.clone().unwrap_or_default()
        ));
    }

    let added_services: Vec<_> = footprint
        .services
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .collect();

    let drivers: BTreeSet<String> = footprint
        .files
        .iter()
        .filter(|change| change.kind == ChangeKind::Added && change.is_driver_image)
        .filter_map(|change| file_name(&change.path))
        .collect();

    // docs/16 inference table.
    let has_driver = added_services.iter().any(|change| change.is_driver) || !drivers.is_empty();
    let boot_start = added_services.iter().any(|change| change.is_boot_start);

    let kind = if has_driver {
        Kind::Kernel
    } else {
        Kind::Usermode
    };
    let risk = if boot_start {
        Risk::Critical
    } else if has_driver {
        Risk::High
    } else {
        // Not "low". Unknown resolves to the more cautious side, and the
        // difference between medium and low is only how loudly the UI warns.
        Risk::Medium
    };

    if !has_driver {
        review.push(
            "no driver was observed, so `kind` is `usermode`. Confirm the anti-cheat really \
             has no kernel component on this title before trusting it."
                .to_owned(),
        );
    }
    if has_driver && !boot_start {
        review.push(
            "a driver was observed but not at boot start. Vanguard has been seen configured \
             either way, so confirm the start type rather than assuming this one generalises."
                .to_owned(),
        );
    }

    // Files this publisher signed, plus the images the observed services point
    // at. Anything else added between the snapshots is somebody else's.
    // The deny-list allows a service key only when the catalog declares that
    // service, and a driver file only when the catalog names it. Those are the
    // two carve-outs `Exceptions` exists for, so the draft is validated with
    // exactly the exceptions its own fields would unlock at runtime — not with
    // `Exceptions::none()`, which refuses the entry for declaring the very
    // services it is about.
    let service_names: Vec<String> = added_services
        .iter()
        .map(|change| change.name.clone())
        .collect();
    let exceptions = Exceptions::new(drivers.iter().cloned(), service_names.iter().cloned());

    let attributable = attributable_paths(footprint, residue, chosen.as_deref(), &added_services);
    let tokens = attribution_tokens(&attributable, &service_names);

    let paths = path_entries(
        footprint,
        residue,
        &attributable,
        &tokens,
        &exceptions,
        &mut review,
    );
    let registry = registry_entries(footprint, &tokens, &exceptions, &mut review);

    if residue.is_none() {
        review.push(
            "no residue diff was given, so every path is classified from the install diff \
             alone. docs/16 calls the residue diff the more valuable of the two — it is the \
             exact set of things the vendor's uninstaller leaves behind."
                .to_owned(),
        );
    }

    review.push(
        "`shared` is `true` and must stay so until at least two titles have been observed. \
         docs/04: a wrong `shared = false` is the G1 violation this project exists to prevent."
            .to_owned(),
    );
    review.push(
        "verify every signer with `signtool verify /v /pa <file>` and paste the output into \
         the pull request, per the docs/16 checklist."
            .to_owned(),
    );

    Draft {
        entry: AntiCheat {
            id: "REVIEW-me".to_owned(),
            display: chosen.as_deref().map_or_else(
                || "REVIEW: unknown publisher".to_owned(),
                |name| format!("REVIEW: {name}"),
            ),
            vendor: chosen.clone(),
            kind,
            shared: true,
            shared_evidence: None,
            risk,
            authenticode_cn: chosen.into_iter().collect(),
            file_hashes: Vec::new(),
            services: added_services
                .iter()
                .map(|change| change.name.clone())
                .collect(),
            drivers: drivers.into_iter().collect(),
            paths,
            registry,
            tasks: Vec::new(),
            firewall_rules: Vec::new(),
            event_sources: Vec::new(),
            official_uninstall: None,
        },
        signers,
        review,
    }
}

/// Every file that can be attributed to this anti-cheat.
///
/// Attribution is by publisher signature, or by being an image an observed
/// service points at. Without it a draft picks up whatever else the machine did
/// between the two snapshots — the first real run produced
/// `%SystemRoot%\System32\drivers`, a running application's `leveldb`
/// directory, and a token-broker cache.
fn attributable_paths(
    footprint: &Diff,
    residue: Option<&Diff>,
    signer: Option<&str>,
    services: &[&crate::diff::ServiceChange],
) -> BTreeSet<String> {
    let mut attributable = BTreeSet::new();

    let mut consider = |change: &crate::diff::FileChange| {
        if change.kind != ChangeKind::Added {
            return;
        }
        if let (Some(want), Some(have)) = (signer, change.signer.as_deref())
            && have.eq_ignore_ascii_case(want)
        {
            attributable.insert(change.path.to_ascii_lowercase());
        }
    };

    for change in &footprint.files {
        consider(change);
    }
    if let Some(residue) = residue {
        for change in &residue.files {
            consider(change);
        }
    }

    // A driver is attestation-signed by Microsoft rather than by its vendor.
    // Measured on a real machine: every `.sys` in the footprint carried
    // "Microsoft Windows Hardware Compatibility Publisher" and only the two
    // user-mode binaries carried the vendor. Signature alone would drop the
    // whole kernel half of the footprint, so a service's own image counts too.
    for service in services {
        if let Some(record) = &service.after {
            attributable.insert(normalise_image(&record.binary_path).to_ascii_lowercase());
        }
    }

    attributable
}

/// Names that identify this anti-cheat in a path or a key.
///
/// Taken from the directories its own files live in, and from its service
/// names. `%ProgramData%\AntiCheatExpert` holds one unsigned `.dat` file and
/// nothing else, so nothing about the file attributes it — but the directory
/// carries the same name as `%ProgramFiles%\AntiCheatExpert`, which the service
/// images anchor. Almost every installer lays itself out that way.
fn attribution_tokens(attributable: &BTreeSet<String>, services: &[String]) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();

    for path in attributable {
        if let Some(parent) = parent_of(path)
            && let Some(leaf) = parent.rsplit('\\').next()
            // A shared system directory names nothing in particular. Without
            // this, `System32\drivers` would make `drivers` an identifier and
            // match half the machine.
            && leaf.len() >= 4
            && !SHARED_DIRECTORIES.contains(&leaf.to_ascii_lowercase().as_str())
        {
            tokens.insert(leaf.to_ascii_lowercase());
        }
    }

    for service in services {
        tokens.insert(service.to_ascii_lowercase());
    }

    tokens
}

/// Directory leaf names too general to identify anything.
const SHARED_DIRECTORIES: &[&str] = &[
    "drivers",
    "system32",
    "syswow64",
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "common files",
    "appdata",
    "local",
    "roaming",
    "temp",
    "bin",
    "lib",
    "data",
    "config",
    "cache",
    "logs",
];

/// Strip the NT prefix and any arguments from a service image path.
fn normalise_image(image: &str) -> String {
    let trimmed = image.trim();
    let without_prefix = trimmed.strip_prefix(r"\??\").unwrap_or(trimmed);

    // `"C:\path\x.exe" -autorun` — take what is inside the quotes.
    if let Some(rest) = without_prefix.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        return rest[..end].to_owned();
    }
    without_prefix.trim().to_owned()
}

/// Directories that gained files, as `%VAR%`-templated path entries.
///
/// Directories rather than individual files: a catalog names a footprint, and
/// an entry per file would be both unreviewable and wrong the moment the
/// vendor ships a patch.
fn path_entries(
    footprint: &Diff,
    residue: Option<&Diff>,
    attributable: &BTreeSet<String>,
    tokens: &BTreeSet<String>,
    exceptions: &Exceptions,
    review: &mut Vec<String>,
) -> Vec<PathEntry> {
    let mut directories: BTreeSet<String> = BTreeSet::new();
    let mut dropped = 0usize;

    let gather = |changes: &[crate::diff::FileChange],
                  directories: &mut BTreeSet<String>,
                  dropped: &mut usize| {
        for change in changes {
            if change.kind != ChangeKind::Added {
                continue;
            }
            let lowered = change.path.to_ascii_lowercase();
            // Signed by the publisher, or living in a directory this
            // anti-cheat names. The second is what keeps an unsigned data file
            // under `%ProgramData%\<Product>` in the footprint.
            let attributed = attributable.contains(&lowered)
                || tokens.iter().any(|token| lowered.contains(token.as_str()));
            if !attributed {
                *dropped += 1;
                continue;
            }
            if let Some(parent) = parent_of(&change.path) {
                directories.insert(parent);
            }
        }
    };

    gather(&footprint.files, &mut directories, &mut dropped);
    // Anything the uninstaller left behind is footprint the entry is *for*.
    if let Some(residue) = residue {
        gather(&residue.files, &mut directories, &mut dropped);
    }

    if dropped > 0 {
        review.push(format!(
            "{dropped} added file(s) could not be attributed to this publisher and were left              out. That is ordinary machine churn between the two snapshots; check the diff if              the footprint looks short."
        ));
    }

    // Collapse a directory whose parent is also listed: `…\Vanguard\Logs` adds
    // nothing over `…\Vanguard`, and the class of the parent covers it.
    let collapsed: Vec<String> = directories
        .iter()
        .filter(|candidate| {
            !directories
                .iter()
                .any(|other| other != *candidate && candidate.starts_with(&format!("{other}\\")))
        })
        .cloned()
        .collect();

    if collapsed.len() > 12 {
        review.push(format!(
            "{} directories gained files. That is more than one product usually installs — \
             check whether the snapshots span something else as well.",
            collapsed.len()
        ));
    }

    collapsed
        .into_iter()
        .filter(|path| {
            // Checked against the deny-list the broker enforces, not against a
            // restatement of its intent. A driver lives in
            // `%SystemRoot%\System32\drivers`, which is shared with the whole
            // operating system: naming it here would be an entry the runtime
            // refuses, and the reviewer could not tell by reading it.
            let allowed = canonicalise_syntactic(path).ok().is_some_and(|canonical| {
                check_path(&canonical, exceptions, Stage::CatalogLoad).is_ok()
            });
            if !allowed {
                review.push(format!(
                    "`{path}` was dropped: the deny-list refuses it. A driver there belongs in \
                     `drivers = [...]` by file name, never as a path."
                ));
            }
            allowed
        })
        .map(|path| PathEntry {
            path: templated(&path),
            // Every path starts as `data`, which docs/04 says is unticked
            // pending review. The generator has no way to tell an install
            // directory from a save directory, and guessing `cache` would tick
            // it by default.
            class: Class::Data,
        })
        .collect()
}

/// Registry keys that were added, deduplicated to their shallowest ancestor.
///
/// Filtered the same way paths are: a key the deny-list refuses is dropped with
/// a note, rather than proposed for a reviewer to discover later.
fn registry_entries(
    footprint: &Diff,
    tokens: &BTreeSet<String>,
    exceptions: &Exceptions,
    review: &mut Vec<String>,
) -> Vec<RegistryEntry> {
    let mut unattributed = 0usize;
    let added: BTreeSet<String> = footprint
        .registry
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .map(|change| change.key.clone())
        .filter(|key| {
            // Registry needs the same attribution as the filesystem. Without
            // it the first real draft carried a shell session key that had
            // nothing to do with the anti-cheat.
            let lowered = key.to_ascii_lowercase();
            let attributed = tokens.iter().any(|token| lowered.contains(token.as_str()));
            if !attributed {
                unattributed += 1;
            }
            attributed
        })
        .collect();

    if unattributed > 0 {
        review.push(format!(
            "{unattributed} added registry key(s) could not be attributed to this anti-cheat              and were left out."
        ));
    }

    added
        .iter()
        .filter(|candidate| {
            !added
                .iter()
                .any(|other| other != *candidate && candidate.starts_with(&format!("{other}\\")))
        })
        .filter(|key| {
            let allowed = canonicalise_reg_key(key)
                .ok()
                .is_some_and(|canonical| check_registry_key(&canonical, exceptions).is_ok());
            if !allowed {
                review.push(format!("`{key}` was dropped: the deny-list refuses it."));
            }
            allowed
        })
        .map(|key| RegistryEntry {
            key: key.clone(),
            // `both` is almost always right per docs/04, and the observation
            // cannot distinguish "only in one view" from "we only looked once".
            view: View::Both,
            class: Class::Config,
        })
        .collect()
}

/// Replace a known prefix with its `%VAR%` template.
fn templated(path: &str) -> String {
    for (variable, prefix) in VARIABLES {
        // `%LOCALAPPDATA%` and `%APPDATA%` are relative to a profile, so they
        // are matched as a fragment rather than as a leading prefix.
        if prefix.starts_with('\\') {
            if let Some(index) = path.to_ascii_lowercase().find(&prefix.to_ascii_lowercase()) {
                return format!("%{variable}%{}", &path[index + prefix.len()..]);
            }
        } else if path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return format!("%{variable}%{}", &path[prefix.len()..]);
        }
    }
    path.to_owned()
}

fn parent_of(path: &str) -> Option<String> {
    path.rfind('\\').map(|index| path[..index].to_owned())
}

fn file_name(path: &str) -> Option<String> {
    path.rsplit('\\').next().map(str::to_owned)
}

/// Render a draft as the TOML `docs/16` specifies, header and all.
///
/// # Errors
/// If the entry cannot be serialised, which would mean the schema and this
/// module have diverged — the failure the whole design is meant to prevent.
pub fn to_toml(draft: &Draft, generated_utc: &str) -> Result<String, toml::ser::Error> {
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        anticheat: [&'a AntiCheat; 1],
    }

    let body = toml::to_string_pretty(&Wrapper {
        anticheat: [&draft.entry],
    })?;

    let mut out = String::new();
    let _ = writeln!(out, "# DRAFT — generated {generated_utc}");
    out.push_str("# REVIEW EVERY FIELD BEFORE SUBMITTING.\n");
    out.push_str("#\n");
    out.push_str("# This is a hypothesis produced from an observation diff, not an entry.\n");
    out.push_str("# CONTRIBUTING.md rejects entries that are not derived from a diff; it does\n");
    out.push_str("# not accept one that was derived from a diff and never read.\n");
    out.push_str("#\n");

    if !draft.signers.is_empty() {
        out.push_str("# Publishers seen in this diff:\n");
        for (name, count) in &draft.signers {
            let _ = writeln!(out, "#   {count:>5} file(s)  {name}");
        }
        out.push_str("#\n");
    }

    out.push_str("# Before submitting:\n");
    for note in &draft.review {
        for (index, line) in wrap(note, 74).into_iter().enumerate() {
            let _ = writeln!(out, "#   {}{line}", if index == 0 { "- " } else { "  " });
        }
    }
    out.push('\n');
    out.push_str(&body);
    Ok(out)
}

/// Wrap a note so the header stays readable in a terminal and a diff.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_prefix_becomes_a_catalog_variable() {
        assert_eq!(
            templated("C:\\Program Files\\Riot Vanguard"),
            "%ProgramFiles%\\Riot Vanguard"
        );
        assert_eq!(
            templated("C:\\Program Files (x86)\\EasyAntiCheat"),
            "%ProgramFiles(x86)%\\EasyAntiCheat"
        );
        assert_eq!(
            templated("C:\\Users\\%USER%\\AppData\\Local\\Riot Games"),
            "%LOCALAPPDATA%\\Riot Games"
        );
    }

    #[test]
    fn the_longer_variable_wins_over_the_one_that_contains_it() {
        // %USERPROFILE%\AppData\Local\… would be correct and useless.
        assert!(templated("C:\\Users\\x\\AppData\\Local\\Y").starts_with("%LOCALAPPDATA%"));
        assert!(templated("C:\\Users\\x\\AppData\\Roaming\\Y").starts_with("%APPDATA%"));
    }

    #[test]
    fn every_variable_the_generator_emits_is_one_the_schema_allows() {
        // The failure this guards: a draft that cannot be loaded, discovered by
        // a contributor when catalog-verify fails on their pull request.
        use wardsweep_core::catalog::expand::KNOWN_VARIABLES;
        for (variable, _) in VARIABLES {
            assert!(
                KNOWN_VARIABLES.contains(variable),
                "%{variable}% is not in the schema's KNOWN_VARIABLES"
            );
        }
    }

    #[test]
    fn an_unknown_prefix_is_left_alone_rather_than_guessed() {
        assert_eq!(templated("D:\\Games\\Thing"), "D:\\Games\\Thing");
    }

    #[test]
    fn a_generated_draft_parses_as_a_catalog() {
        // The reason this module builds a schema::AntiCheat instead of writing
        // TOML: a draft that does not load is discovered by a contributor when
        // catalog-verify fails on their pull request, long after the diff that
        // produced it has been forgotten.
        let diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\Riot Vanguard\vgk.sys",
            r"C:\Program Files\Riot Vanguard\vgc.exe",
        ]);
        let generated = draft(&diff, None, Some("Riot Games, Inc."));
        let body = to_toml(&generated, "2026-08-19T00:00:00.000Z").expect("the draft serialises");

        let catalog = format!(
            "schema_version = 1\ncatalog_version = \"draft\"\n\
             minimum_app_version = \"0.1.0\"\n\n{body}"
        );
        let parsed = wardsweep_core::catalog::parse(&catalog)
            .expect("a generated draft must load through the shipped parser");

        assert_eq!(parsed.anticheat.len(), 1);
        let entry = &parsed.anticheat[0];
        assert!(entry.shared, "shared must default to true — docs/04, G1");
        assert_eq!(entry.drivers, vec!["vgk.sys"]);
    }

    #[test]
    fn a_driver_makes_it_kernel_and_an_unknown_start_type_stays_high_not_low() {
        // The docs/16 inference table, in the direction that removes less.
        let with_driver =
            crate::diff::tests::diff_with_added_files(&[r"C:\Program Files\X\thing.sys"]);
        let generated = draft(&with_driver, None, None);
        assert!(matches!(generated.entry.kind, Kind::Kernel));
        // No service record, so boot start is unknown: high, never low.
        assert!(matches!(generated.entry.risk, Risk::High));

        let no_driver =
            crate::diff::tests::diff_with_added_files(&[r"C:\Program Files\X\thing.exe"]);
        let generated = draft(&no_driver, None, None);
        assert!(matches!(generated.entry.kind, Kind::Usermode));
        assert!(matches!(generated.entry.risk, Risk::Medium));
    }

    /// `path_entries` with everything the caller would normally derive.
    fn entries_for(
        diff: &Diff,
        attributable: &BTreeSet<String>,
        services: &[String],
        review: &mut Vec<String>,
    ) -> Vec<PathEntry> {
        let tokens = attribution_tokens(attributable, services);
        let exceptions = Exceptions::new(Vec::<String>::new(), services.to_vec());
        path_entries(diff, None, attributable, &tokens, &exceptions, review)
    }

    #[test]
    fn a_nested_directory_collapses_into_its_parent() {
        let mut review: Vec<String> = Vec::new();
        let files = [
            r"C:\Program Files\Riot Vanguard\vgk.sys",
            r"C:\Program Files\Riot Vanguard\Logs\a.log",
        ];
        let diff = crate::diff::tests::diff_with_added_files(&files);
        let attributable = files.iter().map(|p| p.to_ascii_lowercase()).collect();
        let paths = entries_for(&diff, &attributable, &[], &mut review);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path, r"%ProgramFiles%\Riot Vanguard");
    }

    #[test]
    fn a_path_the_deny_list_refuses_never_reaches_the_draft() {
        // The first real run proposed `%SystemRoot%\System32\drivers`, because
        // the drivers genuinely live there. The runtime would refuse that entry
        // and a reviewer could not tell by reading it, so the generator is held
        // to the same deny-list the broker enforces.
        let mut review: Vec<String> = Vec::new();
        let files = [r"C:\Windows\System32\drivers\vgk.sys"];
        let diff = crate::diff::tests::diff_with_added_files(&files);
        let attributable = files.iter().map(|p| p.to_ascii_lowercase()).collect();

        let paths = entries_for(&diff, &attributable, &[], &mut review);

        assert!(paths.is_empty(), "got {paths:?}");
        assert!(
            review
                .iter()
                .any(|note| note.contains("deny-list refuses it")),
            "the drop must be explained: {review:?}"
        );
    }

    #[test]
    fn an_unattributable_file_is_dropped_and_counted() {
        // Ordinary machine churn between two snapshots. The first real run swept
        // a running application's leveldb directory into the entry.
        let mut review: Vec<String> = Vec::new();
        let diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\Riot Vanguard\vgk.sys",
            r"C:\Users\x\AppData\Roaming\SomeApp\Local Storage\leveldb\1.ldb",
        ]);
        let attributable =
            std::iter::once(r"c:\program files\riot vanguard\vgk.sys".to_owned()).collect();

        let paths = entries_for(&diff, &attributable, &[], &mut review);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path, r"%ProgramFiles%\Riot Vanguard");
        assert!(
            review
                .iter()
                .any(|note| note.contains("could not be attributed"))
        );
    }

    #[test]
    fn a_service_image_is_attributable_even_when_the_vendor_did_not_sign_it() {
        // Every .sys in the ACE footprint was attestation-signed by Microsoft,
        // not by ACEVILLE. Signature alone would have dropped the kernel half.
        assert_eq!(
            normalise_image(r"\??\C:\WINDOWS\system32\drivers\ACE-BASE.sys"),
            r"C:\WINDOWS\system32\drivers\ACE-BASE.sys"
        );
        assert_eq!(
            normalise_image(r#""C:\Program Files\AntiCheatExpert\ACE-Service64.exe"  -autorun"#),
            r"C:\Program Files\AntiCheatExpert\ACE-Service64.exe"
        );
    }
}
