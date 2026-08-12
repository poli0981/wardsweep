//! The four catalog integrity checks that `catalog-verify.yml` runs.
//!
//! They live in `core` rather than in the CLI tool so the broker applies the
//! same rules at load time that CI applied at merge time. A catalog that would
//! be refused at runtime must fail CI — that is the entire point of the job.

use std::collections::BTreeMap;

use crate::safety::denylist::{self, Exceptions, Stage};
use crate::safety::paths::{canonicalise_reg_key, canonicalise_syntactic};

use super::expand::expand_for_validation;
use super::schema::{
    AntiCheat, Catalog, Class, Kind, LauncherUninstallKind, PathEntry, RegistryEntry, Risk,
    SUPPORTED_SCHEMA_VERSION, UninstallKind,
};

/// One thing wrong with a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    location: String,
    message: String,
}

impl Problem {
    fn new(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            location: location.into(),
            message: message.into(),
        }
    }

    /// Where in the catalog the problem is, as a dotted path.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// What is wrong, in one line.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

/// The carve-outs this catalog's own entries earn.
///
/// A catalog that declares `drivers = ["vgk.sys"]` and `services = ["vgk"]`
/// unlocks exactly those two names in the deny-list's two carve-outs, and
/// nothing else. See [`crate::safety::denylist::Exceptions`].
#[must_use]
pub fn exceptions_for(catalog: &Catalog) -> Exceptions {
    Exceptions::new(
        catalog.anticheat.iter().flat_map(|ac| ac.drivers.iter()),
        catalog.anticheat.iter().flat_map(|ac| ac.services.iter()),
    )
}

/// Schema and field-level validation.
///
/// Structural parsing has already happened by the time a [`Catalog`] exists;
/// this is everything serde cannot express.
#[must_use]
pub fn validate(catalog: &Catalog) -> Vec<Problem> {
    let mut problems = Vec::new();

    if catalog.schema_version != SUPPORTED_SCHEMA_VERSION {
        problems.push(Problem::new(
            "schema_version",
            format!(
                "unsupported schema version {} (this build implements {SUPPORTED_SCHEMA_VERSION})",
                catalog.schema_version
            ),
        ));
    }
    if catalog.catalog_version.trim().is_empty() {
        problems.push(Problem::new("catalog_version", "must not be empty"));
    }
    if catalog.minimum_app_version.trim().is_empty() {
        problems.push(Problem::new("minimum_app_version", "must not be empty"));
    }

    for (index, ac) in catalog.anticheat.iter().enumerate() {
        let at = format!("anticheat[{index}] `{}`", ac.id);
        check_id(&at, &ac.id, &mut problems);
        validate_anticheat(&at, ac, &mut problems);
    }

    for (index, game) in catalog.game.iter().enumerate() {
        let at = format!("game[{index}] `{}`", game.id);
        check_id(&at, &game.id, &mut problems);
        check_paths(
            &at,
            "install_hints",
            &game.install_hints,
            false,
            &mut problems,
        );
        check_paths(&at, "residue", &game.residue, false, &mut problems);
        check_paths(&at, "saves", &game.saves, true, &mut problems);
        check_registry(&at, &game.registry, &mut problems);
    }

    for (index, launcher) in catalog.launcher.iter().enumerate() {
        let at = format!("launcher[{index}] `{}`", launcher.id);
        check_id(&at, &launcher.id, &mut problems);
        if let Some(uninstall) = &launcher.uninstall {
            let needs_command = matches!(
                uninstall.kind,
                LauncherUninstallKind::Protocol
                    | LauncherUninstallKind::Msi
                    | LauncherUninstallKind::Exe
            );
            if needs_command && uninstall.command.is_none() {
                problems.push(Problem::new(
                    format!("{at}.uninstall"),
                    format!("kind = {:?} requires a `command`", uninstall.kind),
                ));
            }
        }
        if let Some(key) = &launcher.detect_registry
            && canonicalise_reg_key(key).is_err()
        {
            problems.push(Problem::new(
                format!("{at}.detect_registry"),
                format!("not a recognisable registry key: {key}"),
            ));
        }
    }

    problems
}

fn validate_anticheat(at: &str, ac: &AntiCheat, problems: &mut Vec<Problem>) {
    if ac.display.trim().is_empty() {
        problems.push(Problem::new(format!("{at}.display"), "must not be empty"));
    }

    // docs/04: "`kernel` implies a driver and therefore a reboot stage."
    if matches!(ac.kind, Kind::Kernel) && ac.drivers.is_empty() {
        problems.push(Problem::new(
            format!("{at}.drivers"),
            "kind = \"kernel\" but no driver filenames are listed",
        ));
    }
    // docs/04: "`critical` = boot-start driver."
    if matches!(ac.risk, Risk::Critical) && matches!(ac.kind, Kind::Usermode) {
        problems.push(Problem::new(
            format!("{at}.risk"),
            "risk = \"critical\" is reserved for boot-start drivers, but kind = \"usermode\"",
        ));
    }

    for (index, driver) in ac.drivers.iter().enumerate() {
        if driver.contains('\\') || driver.contains('/') {
            problems.push(Problem::new(
                format!("{at}.drivers[{index}]"),
                format!("must be a bare filename, not a path: {driver}"),
            ));
        }
        let is_sys = std::path::Path::new(driver)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("sys"));
        if !is_sys {
            problems.push(Problem::new(
                format!("{at}.drivers[{index}]"),
                format!("driver filenames end in .sys: {driver}"),
            ));
        }
    }

    for (index, hash) in ac.file_hashes.iter().enumerate() {
        let valid = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
            problems.push(Problem::new(
                format!("{at}.file_hashes[{index}]"),
                "must be 64 hex characters (SHA-256)",
            ));
        }
    }

    if ac.services.iter().any(|s| s.trim().is_empty()) {
        problems.push(Problem::new(
            format!("{at}.services"),
            "contains an empty name",
        ));
    }

    check_paths(at, "paths", &ac.paths, false, problems);
    check_registry(at, &ac.registry, problems);

    if let Some(uninstall) = &ac.official_uninstall {
        let at = format!("{at}.official_uninstall");
        match uninstall.kind {
            UninstallKind::Exe => {
                if uninstall
                    .command
                    .as_ref()
                    .is_none_or(|c| c.trim().is_empty())
                {
                    problems.push(Problem::new(
                        &at,
                        "kind = \"exe\" requires a `command` path",
                    ));
                }
            }
            UninstallKind::Msi => match uninstall.command.as_deref() {
                Some(code) if looks_like_product_code(code) => {}
                Some(other) => problems.push(Problem::new(
                    &at,
                    format!("kind = \"msi\" requires an MSI product code in braces, got: {other}"),
                )),
                None => problems.push(Problem::new(&at, "kind = \"msi\" requires a `command`")),
            },
            UninstallKind::None => {
                if uninstall.command.is_some() {
                    problems.push(Problem::new(
                        &at,
                        "kind = \"none\" must not carry a `command`",
                    ));
                }
            }
        }
    }
}

/// `{8-4-4-4-12}` hex, the MSI product code form.
fn looks_like_product_code(value: &str) -> bool {
    let Some(inner) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}')) else {
        return false;
    };
    let groups: Vec<&str> = inner.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(len, group)| group.len() == *len)
        && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn check_id(at: &str, id: &str, problems: &mut Vec<Problem>) {
    let kebab = !id.is_empty()
        && id.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if !kebab {
        problems.push(Problem::new(
            format!("{at}.id"),
            format!("ids are stable kebab-case: {id}"),
        ));
    }
}

fn check_paths(
    at: &str,
    field: &str,
    entries: &[PathEntry],
    expect_save_class: bool,
    problems: &mut Vec<Problem>,
) {
    for (index, entry) in entries.iter().enumerate() {
        let at = format!("{at}.{field}[{index}]");

        if expect_save_class && entry.class != Class::Save {
            problems.push(Problem::new(
                &at,
                "entries under `saves` must be class = \"save\"",
            ));
        }
        if !expect_save_class && entry.class == Class::Save {
            problems.push(Problem::new(
                &at,
                "class = \"save\" belongs in the game's `saves` list, which is never removed by default",
            ));
        }
        if entry.path.contains('*') || entry.path.contains('?') {
            problems.push(Problem::new(
                &at,
                format!("wildcards are not allowed in a path: {}", entry.path),
            ));
        }

        match expand_for_validation(&entry.path) {
            Err(error) => problems.push(Problem::new(&at, error.to_string())),
            Ok(expansions) => {
                for expansion in expansions {
                    if let Err(error) = canonicalise_syntactic(&expansion) {
                        problems.push(Problem::new(
                            &at,
                            format!("{} does not canonicalise: {error}", entry.path),
                        ));
                    }
                }
            }
        }
    }
}

fn check_registry(at: &str, entries: &[RegistryEntry], problems: &mut Vec<Problem>) {
    for (index, entry) in entries.iter().enumerate() {
        let at = format!("{at}.registry[{index}]");
        if let Err(error) = canonicalise_reg_key(&entry.key) {
            problems.push(Problem::new(&at, error.to_string()));
        }
        if entry.class == Class::Save {
            problems.push(Problem::new(
                &at,
                "class = \"save\" is not meaningful for a registry key",
            ));
        }
    }
}

/// Referential integrity: every id referenced exists, and no id is reused.
#[must_use]
pub fn check_refs(catalog: &Catalog) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();

    for (kind, id) in catalog
        .anticheat
        .iter()
        .map(|ac| ("anticheat", ac.id.as_str()))
        .chain(catalog.game.iter().map(|g| ("game", g.id.as_str())))
        .chain(catalog.launcher.iter().map(|l| ("launcher", l.id.as_str())))
    {
        if let Some(previous) = seen.insert(id, kind) {
            problems.push(Problem::new(
                format!("{kind} `{id}`"),
                format!("id is already used by a {previous} entry; ids are never reused"),
            ));
        }
    }

    for game in &catalog.game {
        for referenced in &game.anticheat {
            if !catalog.anticheat.iter().any(|ac| &ac.id == referenced) {
                problems.push(Problem::new(
                    format!("game `{}`.anticheat", game.id),
                    format!("references unknown anti-cheat id `{referenced}`"),
                ));
            }
        }
        for platform in &game.platforms {
            if !catalog.launcher.iter().any(|l| &l.id == platform) {
                problems.push(Problem::new(
                    format!("game `{}`.platforms", game.id),
                    format!("references unknown launcher id `{platform}`"),
                ));
            }
        }
    }

    problems
}

/// Run every catalog path and registry key through the deny-list.
///
/// `docs/04-CATALOG-SCHEMA.md`: entries are expanded **before** the deny-list
/// check, and a catalog naming a protected location fails verification as a
/// whole. This is that check.
#[must_use]
pub fn check_denylist(catalog: &Catalog) -> Vec<Problem> {
    let exceptions = exceptions_for(catalog);
    let mut problems = Vec::new();

    let path_groups = catalog
        .anticheat
        .iter()
        .map(|ac| (format!("anticheat `{}`", ac.id), "paths", &ac.paths))
        .chain(catalog.game.iter().flat_map(|g| {
            [
                (
                    format!("game `{}`", g.id),
                    "install_hints",
                    &g.install_hints,
                ),
                (format!("game `{}`", g.id), "residue", &g.residue),
                (format!("game `{}`", g.id), "saves", &g.saves),
            ]
        }));

    for (owner, field, entries) in path_groups {
        for (index, entry) in entries.iter().enumerate() {
            let at = format!("{owner}.{field}[{index}]");
            let Ok(expansions) = expand_for_validation(&entry.path) else {
                continue; // already reported by `validate`
            };
            for expansion in expansions {
                let Ok(canonical) = canonicalise_syntactic(&expansion) else {
                    continue; // already reported by `validate`
                };
                if let Err(reason) =
                    denylist::check_path(&canonical, &exceptions, Stage::CatalogLoad)
                {
                    problems.push(Problem::new(
                        &at,
                        format!(
                            "`{}` resolves to {canonical}, which is denied: {reason}",
                            entry.path
                        ),
                    ));
                }
            }
        }
    }

    let registry_groups = catalog
        .anticheat
        .iter()
        .map(|ac| (format!("anticheat `{}`", ac.id), &ac.registry))
        .chain(
            catalog
                .game
                .iter()
                .map(|g| (format!("game `{}`", g.id), &g.registry)),
        );

    for (owner, entries) in registry_groups {
        for (index, entry) in entries.iter().enumerate() {
            let at = format!("{owner}.registry[{index}]");
            let Ok(canonical) = canonicalise_reg_key(&entry.key) else {
                continue; // already reported by `validate`
            };
            if let Err(reason) = denylist::check_registry_key(&canonical, &exceptions) {
                problems.push(Problem::new(
                    &at,
                    format!("`{}` is denied: {reason}", entry.key),
                ));
            }
        }
    }

    problems
}

/// Audit `shared = false` claims.
///
/// A wrong `shared = false` removes an anti-cheat another game still needs,
/// which is the G1 violation the whole project exists to prevent. With
/// `require_evidence`, the claim must be backed by [`super::schema::SharedEvidence`]
/// naming at least two observed titles and at least one observation.
#[must_use]
pub fn audit_shared(catalog: &Catalog, require_evidence: bool) -> Vec<Problem> {
    let mut problems = Vec::new();

    for ac in &catalog.anticheat {
        let at = format!("anticheat `{}`", ac.id);
        if ac.shared {
            continue;
        }
        let Some(evidence) = &ac.shared_evidence else {
            if require_evidence {
                problems.push(Problem::new(
                    at,
                    "shared = false requires [anticheat.shared_evidence]; \
                     leave shared = true unless you can show otherwise",
                ));
            }
            continue;
        };
        if evidence.titles_observed.len() < 2 {
            problems.push(Problem::new(
                format!("{at}.shared_evidence.titles_observed"),
                "shared = false needs at least two observed titles (docs/16-OBSERVATION-HARNESS.md)",
            ));
        }
        if evidence.observation_ids.is_empty() {
            problems.push(Problem::new(
                format!("{at}.shared_evidence.observation_ids"),
                "must name at least one observation the claim came from",
            ));
        }
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::parse;

    fn catalog_from(body: &str) -> Catalog {
        parse(body).expect("test catalog should parse")
    }

    const HEADER: &str = "schema_version = 1\n\
                          catalog_version = \"0.0.1-test\"\n\
                          minimum_app_version = \"0.1.0\"\n";

    #[test]
    fn catalog_naming_protected_path_fails_verification() {
        for hostile in [
            r"C:\\Windows\\System32",
            r"%SystemRoot%\\System32",
            r"%SystemRoot%",
            r"C:\\Users\\ExampleUser\\NTUSER.DAT",
            r"C:\\ProgramData\\Microsoft\\Windows",
            r"\\\\localhost\\C$\\Windows",
            r"C:\\",
        ] {
            let body = format!(
                "{HEADER}\n[[anticheat]]\n\
                 id = \"hostile\"\ndisplay = \"Hostile\"\nkind = \"usermode\"\n\
                 shared = true\nrisk = \"low\"\n\
                 paths = [{{ path = \"{hostile}\", class = \"install\" }}]\n"
            );
            let catalog = catalog_from(&body);
            let problems = check_denylist(&catalog);
            assert!(
                !problems.is_empty(),
                "catalog naming {hostile} must fail verification"
            );
        }
    }

    #[test]
    fn a_catalog_cannot_unlock_system32_by_declaring_a_driver() {
        // Declaring vgk.sys earns exactly one carve-out: the driver file itself.
        // It does not make the surrounding directory writable.
        let body = format!(
            "{HEADER}\n[[anticheat]]\n\
             id = \"vanguard-like\"\ndisplay = \"Example\"\nkind = \"kernel\"\n\
             shared = true\nrisk = \"critical\"\n\
             drivers = [\"vgk.sys\"]\nservices = [\"vgk\"]\n\
             paths = [{{ path = \"C:\\\\Windows\\\\System32\\\\drivers\", class = \"install\" }}]\n"
        );
        let catalog = catalog_from(&body);
        assert!(!check_denylist(&catalog).is_empty());
    }

    #[test]
    fn a_service_key_the_catalog_declares_is_allowed() {
        let body = format!(
            "{HEADER}\n[[anticheat]]\n\
             id = \"example-ac\"\ndisplay = \"Example\"\nkind = \"kernel\"\n\
             shared = true\nrisk = \"high\"\n\
             drivers = [\"exampleac.sys\"]\nservices = [\"ExampleAC\"]\n\
             registry = [\
               {{ key = \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\ExampleAC\", view = \"64\", class = \"service\" }}\
             ]\n"
        );
        let catalog = catalog_from(&body);
        assert_eq!(check_denylist(&catalog), Vec::new());

        // ...but a service it did not declare is not.
        let body = body.replace("Services\\\\ExampleAC", "Services\\\\Tcpip");
        let catalog = catalog_from(&body);
        assert!(!check_denylist(&catalog).is_empty());
    }

    #[test]
    fn shared_false_without_evidence_fails_the_audit() {
        let body = format!(
            "{HEADER}\n[[anticheat]]\n\
             id = \"solo-ac\"\ndisplay = \"Solo\"\nkind = \"usermode\"\n\
             shared = false\nrisk = \"low\"\n"
        );
        let catalog = catalog_from(&body);
        assert!(audit_shared(&catalog, true).len() == 1);
        // Without --require-evidence the same catalog is merely unaudited.
        assert!(audit_shared(&catalog, false).is_empty());
    }

    #[test]
    fn shared_false_with_thin_evidence_still_fails() {
        let body = format!(
            "{HEADER}\n[[anticheat]]\n\
             id = \"solo-ac\"\ndisplay = \"Solo\"\nkind = \"usermode\"\n\
             shared = false\nrisk = \"low\"\n\
             [anticheat.shared_evidence]\n\
             titles_observed = [\"only-one\"]\n\
             observation_ids = []\n"
        );
        let catalog = catalog_from(&body);
        assert_eq!(audit_shared(&catalog, true).len(), 2);
    }

    #[test]
    fn dangling_and_reused_ids_are_caught() {
        let body = format!(
            "{HEADER}\n\
             [[anticheat]]\nid = \"ac-one\"\ndisplay = \"One\"\nkind = \"usermode\"\nshared = true\nrisk = \"low\"\n\
             [[game]]\nid = \"ac-one\"\ndisplay = \"Clash\"\nanticheat = [\"missing-ac\"]\nplatforms = [\"nosuch\"]\n"
        );
        let catalog = catalog_from(&body);
        let problems = check_refs(&catalog);
        assert_eq!(problems.len(), 3, "{problems:?}");
    }

    #[test]
    fn save_class_is_confined_to_the_saves_list() {
        let body = format!(
            "{HEADER}\n[[game]]\nid = \"a-game\"\ndisplay = \"A Game\"\n\
             residue = [{{ path = \"%LOCALAPPDATA%\\\\A\\\\Cache\", class = \"save\" }}]\n\
             saves = [{{ path = \"%LOCALAPPDATA%\\\\A\\\\Saved\", class = \"cache\" }}]\n"
        );
        let catalog = catalog_from(&body);
        let problems = validate(&catalog);
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn a_clean_minimal_catalog_passes_every_check() {
        let catalog = catalog_from(HEADER);
        assert_eq!(validate(&catalog), Vec::new());
        assert_eq!(check_refs(&catalog), Vec::new());
        assert_eq!(check_denylist(&catalog), Vec::new());
        assert_eq!(audit_shared(&catalog, true), Vec::new());
    }
}
