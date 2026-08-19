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

use std::collections::BTreeSet;
use std::fmt::Write as _;

use wardsweep_core::catalog::schema::{
    AntiCheat, Class, Kind, PathEntry, RegistryEntry, Risk, View,
};

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

    let paths = path_entries(footprint, residue, &mut review);
    let registry = registry_entries(footprint);

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

/// Directories that gained files, as `%VAR%`-templated path entries.
///
/// Directories rather than individual files: a catalog names a footprint, and
/// an entry per file would be both unreviewable and wrong the moment the
/// vendor ships a patch.
fn path_entries(
    footprint: &Diff,
    residue: Option<&Diff>,
    review: &mut Vec<String>,
) -> Vec<PathEntry> {
    let mut directories: BTreeSet<String> = footprint
        .files
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .filter_map(|change| parent_of(&change.path))
        .collect();

    // Anything the uninstaller left behind is footprint the entry is *for*.
    if let Some(residue) = residue {
        for change in &residue.files {
            if change.kind == ChangeKind::Added
                && let Some(parent) = parent_of(&change.path)
            {
                directories.insert(parent);
            }
        }
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
fn registry_entries(footprint: &Diff) -> Vec<RegistryEntry> {
    let added: BTreeSet<String> = footprint
        .registry
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .map(|change| change.key.clone())
        .collect();

    added
        .iter()
        .filter(|candidate| {
            !added
                .iter()
                .any(|other| other != *candidate && candidate.starts_with(&format!("{other}\\")))
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

    #[test]
    fn a_nested_directory_collapses_into_its_parent() {
        let mut review = Vec::new();
        let diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\Riot Vanguard\vgk.sys",
            r"C:\Program Files\Riot Vanguard\Logs\a.log",
        ]);
        let paths = path_entries(&diff, None, &mut review);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path, "%ProgramFiles%\\Riot Vanguard");
    }
}
