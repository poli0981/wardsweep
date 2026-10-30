//! The audit: every catalog entry, matched against the machine.
//!
//! `docs/05-DETECTION-ENGINE.md` is the specification. What this first slice
//! does, entry by entry:
//!
//! - **Services** are asked of the service control manager, and of the
//!   `Services` key when SCM does not know them: a driver written past SCM is
//!   only there. An SCM entry whose every query fails with "file not found" is
//!   stale — its key is gone — and is reported as disbelieved, not present.
//! - **Drivers** are found by the image file name of every driver key, so a
//!   registration whose image is not on disk is still the anti-cheat's: EA's
//!   minifilter has none while no game runs. An image with no key is found too.
//! - **Registry keys** under `HKLM\SOFTWARE` are read in both WOW64 views, and
//!   the same key found in both is two artifacts.
//! - **Paths** are expanded with this machine's values, one per game library
//!   for `%STEAM_LIBRARY%` and `%EPIC_LIBRARY%`, and looked at without
//!   following a reparse point.
//! - Every path and key passes the deny-list, with the entry's own carve-outs;
//!   what it refuses is reported as protected and never as a finding.
//! - Anything unreadable is reported as unreadable, and makes the scan partial.
//!
//! Classification follows `docs/05` "Matching strategy": a file artifact by its
//! own signature, anything else by whether the entry's files confirmed the
//! publisher. A verification error is never `suspicious`.
//!
//! Not yet: games and their residue, which need the launchers' install records,
//! and the ownership graph and reference counting, which wait for spike S2
//! (`docs/13`). Without them nothing here is an orphan.

use std::collections::BTreeMap;

use crate::catalog::expand::expand_with;
use crate::catalog::schema::{AntiCheat, Catalog, View};
use crate::catalog::validate::exceptions_for;
use crate::safety::denylist::{DenyReason, Exceptions, Stage, check_path, check_registry_key};
use crate::safety::paths::{canonicalise_reg_key, canonicalise_syntactic};

use super::model::{
    Artifact, Classification, Disbelieved, Finding, Protected, REPORT_VERSION, RegView, Report,
    Unreadable,
};
use super::view::{Lookup, MachineView, PathKind, ServiceKey, Signature};

/// The values this machine gives the catalog's `%VAR%` placeholders.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    values: BTreeMap<String, Vec<String>>,
}

impl Environment {
    /// An environment with no values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Give a variable its values; several for a multi-valued one.
    #[must_use]
    pub fn with(mut self, name: &str, values: Vec<String>) -> Self {
        self.values.insert(name.to_ascii_uppercase(), values);
        self
    }

    /// A variable's values, if this machine has any.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Vec<String>> {
        self.values.get(&name.to_ascii_uppercase()).cloned()
    }

    fn system_root(&self) -> String {
        self.lookup("SystemRoot")
            .and_then(|values| values.into_iter().next())
            .unwrap_or_else(|| "C:\\Windows".to_owned())
    }
}

/// Audit a machine against a catalog. Reads only.
#[must_use]
pub fn audit(catalog: &Catalog, machine: &dyn MachineView, environment: &Environment) -> Report {
    let mut report = Report {
        v: REPORT_VERSION,
        findings: Vec::new(),
        protected: Vec::new(),
        disbelieved: Vec::new(),
        unreadable: Vec::new(),
    };
    // Read once: every driver key, for every entry's driver names.
    let driver_keys = match machine.driver_keys() {
        Lookup::Found(keys) => keys,
        Lookup::Absent => Vec::new(),
        Lookup::Unreadable(reason) => {
            report.unreadable.push(Unreadable {
                anticheat: None,
                item: SERVICES_KEY.to_owned(),
                reason,
            });
            Vec::new()
        }
    };
    for entry in &catalog.anticheat {
        Audit {
            entry,
            exceptions: exceptions_for(entry),
            machine,
            environment,
            driver_keys: &driver_keys,
            report: &mut report,
            found: Vec::new(),
        }
        .run();
    }
    report
}

const SERVICES_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services";

/// A finding before its classification is settled: a file artifact's comes
/// from its own signature, anything else's from the entry's files.
struct Pending {
    artifact: Artifact,
    evidence: Vec<String>,
    judged: Option<Classification>,
}

/// One catalog entry's audit.
struct Audit<'a> {
    entry: &'a AntiCheat,
    exceptions: Exceptions,
    machine: &'a dyn MachineView,
    environment: &'a Environment,
    driver_keys: &'a [ServiceKey],
    report: &'a mut Report,
    found: Vec<Pending>,
}

impl Audit<'_> {
    fn run(mut self) {
        for name in &self.entry.services {
            self.service(name);
        }
        for file in &self.entry.drivers {
            self.driver(file);
        }
        for entry in &self.entry.registry {
            for view in views(&entry.key, entry.view) {
                self.registry_key(&entry.key, view);
            }
        }
        for entry in &self.entry.paths {
            self.path(&entry.path);
        }
        self.settle();
    }

    fn unreadable(&mut self, item: &str, reason: String) {
        self.report.unreadable.push(Unreadable {
            anticheat: Some(self.entry.id.clone()),
            item: item.to_owned(),
            reason,
        });
    }

    fn protected(&mut self, target: &str, reason: String) {
        self.report.protected.push(Protected {
            anticheat: self.entry.id.clone(),
            target: target.to_owned(),
            reason,
        });
    }

    fn service(&mut self, name: &str) {
        match self.machine.service(name) {
            Lookup::Found(status) if status.stale => {
                self.report.disbelieved.push(Disbelieved {
                    anticheat: self.entry.id.clone(),
                    item: name.to_owned(),
                    reason: "the service control manager still lists it, and every query \
                             fails with \"file not found\": its key is gone and SCM has not \
                             noticed. Not reported as present."
                        .to_owned(),
                });
            }
            Lookup::Found(status) => {
                let artifact = Artifact::Service {
                    name: name.to_owned(),
                    image: Some(status.image.clone()),
                    registry_only: false,
                };
                self.with_image(
                    artifact,
                    &status.image,
                    "the service control manager lists it",
                );
            }
            Lookup::Absent => match self.machine.service_key(name) {
                Lookup::Found(key) => {
                    let artifact = Artifact::Service {
                        name: name.to_owned(),
                        image: (!key.image.is_empty()).then(|| key.image.clone()),
                        registry_only: true,
                    };
                    self.with_image(
                        artifact,
                        &key.image,
                        "its key is in `Services` and the service control manager does not \
                         list it: written past SCM (docs/05)",
                    );
                }
                Lookup::Absent => {}
                Lookup::Unreadable(reason) => {
                    self.unreadable(&format!("{SERVICES_KEY}\\{name}"), reason);
                }
            },
            Lookup::Unreadable(reason) => self.unreadable(name, reason),
        }
    }

    /// Record an artifact whose evidence includes a configured image, judged by
    /// that image's signature when it is on disk.
    fn with_image(&mut self, artifact: Artifact, configured: &str, why: &str) {
        let mut evidence = vec![why.to_owned()];
        let judged = match image_file(configured, &self.environment.system_root()) {
            Some(image) => match self.machine.path(&image) {
                Lookup::Found(PathKind::File) => {
                    let (classification, said) = judge(self.machine.signature(&image), self.entry);
                    evidence.push(format!("image `{image}`: {said}"));
                    Some(classification)
                }
                Lookup::Found(_) | Lookup::Absent => {
                    evidence.push(format!("image `{image}` is not on disk"));
                    None
                }
                Lookup::Unreadable(reason) => {
                    evidence.push(format!("image `{image}` could not be read: {reason}"));
                    None
                }
            },
            None => None,
        };
        self.found.push(Pending {
            artifact,
            evidence,
            judged,
        });
    }

    fn driver(&mut self, file: &str) {
        let registered: Vec<&ServiceKey> = self
            .driver_keys
            .iter()
            .filter(|key| {
                image_file(&key.image, &self.environment.system_root())
                    .and_then(|image| file_name(&image).map(str::to_owned))
                    .is_some_and(|name| name.eq_ignore_ascii_case(file))
            })
            .collect();
        if registered.is_empty() {
            // An image with no registration: what an uninstaller that deleted the
            // key and kept the file leaves.
            let image = format!(
                "{}\\System32\\drivers\\{file}",
                self.environment.system_root()
            );
            match self.machine.path(&image) {
                Lookup::Found(PathKind::File) => {
                    let (classification, said) = judge(self.machine.signature(&image), self.entry);
                    self.found.push(Pending {
                        artifact: Artifact::Driver {
                            file: file.to_owned(),
                            service: None,
                            image: image.clone(),
                            image_present: true,
                        },
                        evidence: vec![
                            "an image with no driver key registering it".to_owned(),
                            format!("image: {said}"),
                        ],
                        judged: Some(classification),
                    });
                }
                Lookup::Found(_) | Lookup::Absent => {}
                Lookup::Unreadable(reason) => self.unreadable(&image, reason),
            }
            return;
        }
        for key in registered {
            let image = image_file(&key.image, &self.environment.system_root())
                .unwrap_or_else(|| key.image.clone());
            let present = matches!(self.machine.path(&image), Lookup::Found(PathKind::File));
            let mut evidence = vec![format!("registered by `{SERVICES_KEY}\\{}`", key.name)];
            let judged = if present {
                let (classification, said) = judge(self.machine.signature(&image), self.entry);
                evidence.push(format!("image: {said}"));
                Some(classification)
            } else {
                // Not a removal: EA's minifilter has no image while no game runs.
                evidence.push(
                    "the image is not on disk, which for some drivers is their normal state \
                     while no game runs"
                        .to_owned(),
                );
                None
            };
            self.found.push(Pending {
                artifact: Artifact::Driver {
                    file: file.to_owned(),
                    service: Some(key.name.clone()),
                    image,
                    image_present: present,
                },
                evidence,
                judged,
            });
        }
    }

    fn registry_key(&mut self, key: &str, view: RegView) {
        let refused = match canonicalise_reg_key(key) {
            Ok(canonical) => check_registry_key(&canonical, &self.exceptions)
                .err()
                .map(|reason| reason.to_string()),
            Err(error) => Some(error.to_string()),
        };
        if let Some(reason) = refused {
            self.protected(key, reason);
            return;
        }
        match self.machine.registry_key(key, view) {
            Lookup::Found(()) => self.found.push(Pending {
                artifact: Artifact::RegistryKey {
                    key: key.to_owned(),
                    view,
                },
                evidence: vec![match view {
                    RegView::Bits64 => "present in the 64-bit view".to_owned(),
                    RegView::Bits32 => "present in the 32-bit view (WOW6432Node)".to_owned(),
                }],
                judged: None,
            }),
            Lookup::Absent => {}
            Lookup::Unreadable(reason) => self.unreadable(&format!("{key} ({view:?})"), reason),
        }
    }

    fn path(&mut self, template: &str) {
        let expansions = match expand_with(template, |name| self.environment.lookup(name)) {
            Ok(expansions) => expansions,
            Err(error) => {
                self.unreadable(template, format!("cannot be expanded: {error}"));
                return;
            }
        };
        for path in expansions {
            let kind = match self.machine.path(&path) {
                Lookup::Found(kind) => kind,
                Lookup::Absent => continue,
                Lookup::Unreadable(reason) => {
                    self.unreadable(&path, reason);
                    continue;
                }
            };
            // The syntactic check: an audit reads, and the handle-resolved check
            // belongs to the stage that would delete. A link is refused here, as
            // the deny-list refuses any path through one.
            let refused = if kind == PathKind::ReparsePoint {
                Some(DenyReason::ReparsePointInPath.to_string())
            } else {
                match canonicalise_syntactic(&path) {
                    Ok(canonical) => check_path(&canonical, &self.exceptions, Stage::CatalogLoad)
                        .err()
                        .map(|reason| reason.to_string()),
                    Err(error) => Some(error.to_string()),
                }
            };
            if let Some(reason) = refused {
                self.protected(&path, reason);
                continue;
            }
            let signable = kind == PathKind::File && is_signable(&path);
            let (judged, evidence) = if signable {
                let (classification, said) = judge(self.machine.signature(&path), self.entry);
                (Some(classification), vec![said])
            } else {
                (None, vec![format!("{} exists", describe(kind))])
            };
            self.found.push(Pending {
                artifact: Artifact::Path {
                    path,
                    directory: kind == PathKind::Directory,
                },
                evidence,
                judged,
            });
        }
    }

    /// Give every artifact its classification and hand it to the report.
    fn settle(self) {
        let confirmed = self
            .found
            .iter()
            .any(|pending| pending.judged == Some(Classification::Confirmed));
        let suspicious = self
            .found
            .iter()
            .any(|pending| pending.judged == Some(Classification::Suspicious));
        for pending in self.found {
            let mut evidence = pending.evidence;
            let classification = pending.judged.unwrap_or_else(|| {
                if confirmed && !suspicious {
                    evidence.push("the entry's signed files confirm the publisher".to_owned());
                    Classification::Confirmed
                } else {
                    evidence.push(
                        "nothing found confirms the publisher, so this rests on the name alone"
                            .to_owned(),
                    );
                    Classification::Probable
                }
            });
            self.report.findings.push(Finding {
                anticheat: self.entry.id.clone(),
                artifact: pending.artifact,
                classification,
                evidence,
            });
        }
    }
}

/// The views a catalog key is read in. Only `HKLM\SOFTWARE` is redirected for
/// a 32-bit installer, so only there is "both" two reads; anywhere else the two
/// views are one key, and reading it twice would report one artifact twice.
fn views(key: &str, view: View) -> Vec<RegView> {
    let redirected = key
        .get(..14)
        .is_some_and(|head| head.eq_ignore_ascii_case("HKLM\\SOFTWARE\\"));
    match view {
        View::Bits32 => vec![RegView::Bits32],
        View::Both if redirected => vec![RegView::Bits64, RegView::Bits32],
        View::Bits64 | View::Both => vec![RegView::Bits64],
    }
}

/// Judge a file by its signature against the publishers the entry names.
fn judge(signature: Signature, entry: &AntiCheat) -> (Classification, String) {
    let ours = |signer: &str| {
        entry
            .authenticode_cn
            .iter()
            .any(|name| name.eq_ignore_ascii_case(signer))
    };
    match signature {
        Signature::Verified(signer) if ours(&signer) => {
            (Classification::Confirmed, format!("signed by {signer}"))
        }
        Signature::Verified(signer) if entry.authenticode_cn.is_empty() => (
            Classification::Probable,
            format!("signed by {signer}; the catalog names no publisher to check it against"),
        ),
        Signature::Verified(signer) => (
            Classification::Suspicious,
            format!("signed by {signer}, not by the publisher the catalog names"),
        ),
        Signature::Unsigned => (Classification::Suspicious, "not signed".to_owned()),
        Signature::Invalid => (
            Classification::Suspicious,
            "its signature does not verify".to_owned(),
        ),
        Signature::Unknown(reason) => (
            Classification::Probable,
            format!(
                "its signature could not be checked ({reason}), which is unknown, not unsigned"
            ),
        ),
    }
}

/// A service's configured image as a file path: quotes and arguments removed,
/// and the kernel's own spellings — `\SystemRoot\`, `\??\`, a bare
/// `system32\` — written out against `%SystemRoot%`.
fn image_file(configured: &str, system_root: &str) -> Option<String> {
    let text = configured.trim();
    let text = if let Some(quoted) = text.strip_prefix('"') {
        quoted.split('"').next().unwrap_or_default()
    } else {
        let lowered = text.to_ascii_lowercase();
        [".exe", ".sys", ".dll"]
            .iter()
            .filter_map(|extension| lowered.find(extension).map(|at| at + extension.len()))
            .min()
            .map_or(text, |end| &text[..end])
    };
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let lowered = text.to_ascii_lowercase();
    let expanded = if let Some(rest) = lowered.strip_prefix("\\systemroot\\") {
        format!("{system_root}\\{}", &text[text.len() - rest.len()..])
    } else if let Some(rest) = lowered.strip_prefix("%systemroot%\\") {
        format!("{system_root}\\{}", &text[text.len() - rest.len()..])
    } else if lowered.starts_with("\\??\\") {
        text[4..].to_owned()
    } else if lowered.starts_with("system32\\") {
        format!("{system_root}\\{text}")
    } else {
        text.to_owned()
    };
    Some(expanded)
}

fn file_name(path: &str) -> Option<&str> {
    path.rsplit('\\').next().filter(|name| !name.is_empty())
}

/// A file whose Authenticode signature is worth reading.
fn is_signable(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    [".exe", ".dll", ".sys", ".msi"]
        .iter()
        .any(|extension| lowered.ends_with(extension))
}

fn describe(kind: PathKind) -> &'static str {
    match kind {
        PathKind::File => "the file",
        PathKind::Directory => "the directory",
        PathKind::ReparsePoint => "a link",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::scan::view::ServiceStatus;

    const HEADER: &str = "schema_version = 1\n\
                          catalog_version = \"0.0.1-test\"\n\
                          minimum_app_version = \"0.1.0\"\n";

    fn catalog(body: &str) -> Catalog {
        crate::catalog::parse(&format!("{HEADER}\n{body}")).expect("the test catalog parses")
    }

    /// A machine held in maps. Anything not in a map is absent.
    #[derive(Default)]
    struct Fake {
        services: BTreeMap<String, Lookup<ServiceStatus>>,
        keys: BTreeMap<String, ServiceKey>,
        registry: BTreeMap<(String, RegView), Lookup<()>>,
        paths: BTreeMap<String, Lookup<PathKind>>,
        signatures: BTreeMap<String, Signature>,
        driver_keys_unreadable: bool,
    }

    impl Fake {
        fn key(mut self, key: &str, view: RegView) -> Self {
            self.registry
                .insert((key.to_ascii_lowercase(), view), Lookup::Found(()));
            self
        }
        fn file(mut self, path: &str, signature: Signature) -> Self {
            self.paths
                .insert(path.to_ascii_lowercase(), Lookup::Found(PathKind::File));
            self.signatures.insert(path.to_ascii_lowercase(), signature);
            self
        }
        fn directory(mut self, path: &str) -> Self {
            self.paths.insert(
                path.to_ascii_lowercase(),
                Lookup::Found(PathKind::Directory),
            );
            self
        }
    }

    impl MachineView for Fake {
        fn service(&self, name: &str) -> Lookup<ServiceStatus> {
            self.services
                .get(&name.to_ascii_lowercase())
                .cloned()
                .unwrap_or(Lookup::Absent)
        }
        fn service_key(&self, name: &str) -> Lookup<ServiceKey> {
            self.keys
                .get(&name.to_ascii_lowercase())
                .cloned()
                .map_or(Lookup::Absent, Lookup::Found)
        }
        fn driver_keys(&self) -> Lookup<Vec<ServiceKey>> {
            if self.driver_keys_unreadable {
                return Lookup::Unreadable("access denied".to_owned());
            }
            Lookup::Found(
                self.keys
                    .values()
                    .filter(|key| key.is_driver())
                    .cloned()
                    .collect(),
            )
        }
        fn registry_key(&self, key: &str, view: RegView) -> Lookup<()> {
            self.registry
                .get(&(key.to_ascii_lowercase(), view))
                .cloned()
                .unwrap_or(Lookup::Absent)
        }
        fn path(&self, path: &str) -> Lookup<PathKind> {
            self.paths
                .get(&path.to_ascii_lowercase())
                .cloned()
                .unwrap_or(Lookup::Absent)
        }
        fn signature(&self, path: &str) -> Signature {
            self.signatures
                .get(&path.to_ascii_lowercase())
                .cloned()
                .unwrap_or(Signature::Unknown("not in the fixture".to_owned()))
        }
    }

    fn environment() -> Environment {
        Environment::new()
            .with("ProgramFiles", vec!["C:\\Program Files".to_owned()])
            .with("SystemRoot", vec!["C:\\Windows".to_owned()])
            .with(
                "STEAM_LIBRARY",
                vec![
                    "C:\\Program Files (x86)\\Steam".to_owned(),
                    "D:\\SteamLibrary".to_owned(),
                ],
            )
    }

    const EXAMPLE: &str = "[[anticheat]]\n\
                           id = \"example-ac\"\ndisplay = \"Example\"\nkind = \"kernel\"\n\
                           shared = true\nrisk = \"high\"\n\
                           authenticode_cn = [\"Example Vendor\"]\n";

    fn kinds(report: &Report) -> Vec<(&Artifact, Classification)> {
        report
            .findings
            .iter()
            .map(|finding| (&finding.artifact, finding.classification))
            .collect()
    }

    #[test]
    fn wow64_both_views_produce_distinct_artifacts() {
        // docs/12's named test: one logical key, two artifacts, both removed.
        let body = format!(
            "{EXAMPLE}registry = [{{ key = \"HKLM\\\\SOFTWARE\\\\ExampleAC\", view = \"both\", class = \"config\" }}]\n"
        );
        let machine = Fake::default()
            .key("HKLM\\SOFTWARE\\ExampleAC", RegView::Bits64)
            .key("HKLM\\SOFTWARE\\ExampleAC", RegView::Bits32);

        let report = audit(&catalog(&body), &machine, &environment());

        let views: Vec<RegView> = report
            .findings
            .iter()
            .filter_map(|finding| match &finding.artifact {
                Artifact::RegistryKey { view, .. } => Some(*view),
                _ => None,
            })
            .collect();
        assert_eq!(views, [RegView::Bits64, RegView::Bits32]);
    }

    #[test]
    fn an_unredirected_key_is_read_once() {
        // HKCU\SOFTWARE is the same key in both views; two artifacts would be
        // one key reported twice.
        let body = format!(
            "{EXAMPLE}registry = [{{ key = \"HKCU\\\\SOFTWARE\\\\ExampleAC\", view = \"both\", class = \"config\" }}]\n"
        );
        let machine = Fake::default()
            .key("HKCU\\SOFTWARE\\ExampleAC", RegView::Bits64)
            .key("HKCU\\SOFTWARE\\ExampleAC", RegView::Bits32);
        let report = audit(&catalog(&body), &machine, &environment());
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    }

    #[test]
    fn a_driver_written_past_scm_is_found_and_a_missing_image_is_not_a_removal() {
        let body = format!("{EXAMPLE}services = [\"ExampleAC\"]\ndrivers = [\"exampleac.sys\"]\n");
        let mut machine = Fake::default();
        machine.keys.insert(
            "exampleac".to_owned(),
            ServiceKey {
                name: "ExampleAC".to_owned(),
                image: "system32\\drivers\\exampleac.sys".to_owned(),
                service_type: 2,
            },
        );

        let report = audit(&catalog(&body), &machine, &environment());

        assert!(report.findings.iter().any(|finding| matches!(
            &finding.artifact,
            Artifact::Service {
                registry_only: true,
                ..
            }
        )));
        let driver = report
            .findings
            .iter()
            .find(|finding| matches!(finding.artifact, Artifact::Driver { .. }))
            .expect("the registration is the driver, image or not");
        assert!(matches!(
            &driver.artifact,
            Artifact::Driver { image_present: false, image, .. }
                if image == "C:\\Windows\\system32\\drivers\\exampleac.sys"
        ));
        assert_eq!(driver.classification, Classification::Probable);
    }

    #[test]
    fn a_stale_scm_entry_is_not_a_present_driver() {
        let body = format!("{EXAMPLE}services = [\"ExampleAC\"]\n");
        let mut machine = Fake::default();
        machine.services.insert(
            "exampleac".to_owned(),
            Lookup::Found(ServiceStatus {
                image: String::new(),
                stale: true,
            }),
        );

        let report = audit(&catalog(&body), &machine, &environment());

        assert_eq!(report.findings, []);
        assert_eq!(report.disbelieved.len(), 1);
        assert!(!report.partial());
    }

    #[test]
    fn unreadable_is_partial_and_never_absent() {
        let body = format!(
            "{EXAMPLE}services = [\"ExampleAC\"]\n\
             paths = [{{ path = \"%ProgramFiles%\\\\ExampleAC\", class = \"install\" }}]\n"
        );
        let mut machine = Fake {
            driver_keys_unreadable: true,
            ..Fake::default()
        };
        machine.services.insert(
            "exampleac".to_owned(),
            Lookup::Unreadable("access denied".to_owned()),
        );
        machine.paths.insert(
            "c:\\program files\\exampleac".to_owned(),
            Lookup::Unreadable("access denied".to_owned()),
        );

        let report = audit(&catalog(&body), &machine, &environment());

        assert_eq!(report.findings, []);
        assert!(report.partial());
        assert_eq!(report.unreadable.len(), 3, "{:?}", report.unreadable);
    }

    #[test]
    fn what_the_deny_list_protects_is_reported_not_found() {
        // A library as a whole is a container: never a finding, however the
        // catalog came to name it.
        let body = format!(
            "{EXAMPLE}paths = [{{ path = \"%STEAM_LIBRARY%\\\\steamapps\\\\common\", class = \"install\" }}]\n"
        );
        let machine = Fake::default().directory("D:\\SteamLibrary\\steamapps\\common");

        let report = audit(&catalog(&body), &machine, &environment());

        assert_eq!(report.findings, []);
        assert_eq!(report.protected.len(), 1, "{:?}", report.protected);
        assert_eq!(
            report.protected[0].target,
            "D:\\SteamLibrary\\steamapps\\common"
        );
    }

    #[test]
    fn a_path_in_every_library_is_looked_for() {
        let body = format!(
            "{EXAMPLE}paths = [{{ path = \"%STEAM_LIBRARY%\\\\steamapps\\\\common\\\\Example\", class = \"install\" }}]\n"
        );
        let machine = Fake::default().directory("D:\\SteamLibrary\\steamapps\\common\\Example");

        let report = audit(&catalog(&body), &machine, &environment());

        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            &report.findings[0].artifact,
            Artifact::Path { path, directory: true } if path.starts_with("D:\\")
        ));
    }

    #[test]
    fn classification_follows_the_signature_and_an_error_is_never_suspicious() {
        let body = format!(
            "{EXAMPLE}paths = [\n\
             {{ path = \"%ProgramFiles%\\\\ExampleAC\\\\ours.exe\", class = \"install\" }},\n\
             {{ path = \"%ProgramFiles%\\\\ExampleAC\\\\theirs.exe\", class = \"install\" }},\n\
             {{ path = \"%ProgramFiles%\\\\ExampleAC\\\\unsigned.dll\", class = \"install\" }},\n\
             {{ path = \"%ProgramFiles%\\\\ExampleAC\\\\busy.dll\", class = \"install\" }},\n\
             ]\n"
        );
        let machine = Fake::default()
            .file(
                "C:\\Program Files\\ExampleAC\\ours.exe",
                Signature::Verified("Example Vendor".to_owned()),
            )
            .file(
                "C:\\Program Files\\ExampleAC\\theirs.exe",
                Signature::Verified("Somebody Else".to_owned()),
            )
            .file(
                "C:\\Program Files\\ExampleAC\\unsigned.dll",
                Signature::Unsigned,
            )
            .file(
                "C:\\Program Files\\ExampleAC\\busy.dll",
                Signature::Unknown("the disk was busy".to_owned()),
            );

        let report = audit(&catalog(&body), &machine, &environment());

        let classes: Vec<Classification> =
            kinds(&report).into_iter().map(|(_, class)| class).collect();
        assert_eq!(
            classes,
            [
                Classification::Confirmed,
                Classification::Suspicious,
                Classification::Suspicious,
                Classification::Probable,
            ]
        );
    }

    #[test]
    fn a_key_is_confirmed_only_through_the_entrys_signed_files() {
        let body = format!(
            "{EXAMPLE}registry = [{{ key = \"HKLM\\\\SOFTWARE\\\\ExampleAC\", view = \"64\", class = \"config\" }}]\n\
             paths = [{{ path = \"%ProgramFiles%\\\\ExampleAC\\\\ours.exe\", class = \"install\" }}]\n"
        );
        let signed = Fake::default()
            .key("HKLM\\SOFTWARE\\ExampleAC", RegView::Bits64)
            .file(
                "C:\\Program Files\\ExampleAC\\ours.exe",
                Signature::Verified("Example Vendor".to_owned()),
            );
        let report = audit(&catalog(&body), &signed, &environment());
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.classification == Classification::Confirmed)
        );

        let alone = Fake::default().key("HKLM\\SOFTWARE\\ExampleAC", RegView::Bits64);
        let report = audit(&catalog(&body), &alone, &environment());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].classification, Classification::Probable);
    }

    /// The machine as FC 26's first launch left it, from the committed install
    /// diff: every service, registry key and file it added, and the folders
    /// holding those files.
    fn machine_from_ea_install() -> Fake {
        let diff: serde_json::Value = serde_json::from_str(include_str!(
            "../../../observations/2026-10-09-ea-anticheat/install.json"
        ))
        .expect("the committed diff is JSON");
        let added = |domain: &str| -> Vec<serde_json::Value> {
            diff[domain]
                .as_array()
                .expect("the diff has the domain")
                .iter()
                .filter(|change| change["kind"] == "added")
                .cloned()
                .collect()
        };
        let mut machine = Fake::default();
        for change in added("services") {
            machine.services.insert(
                change["name"].as_str().unwrap().to_ascii_lowercase(),
                Lookup::Found(ServiceStatus {
                    image: change["after"]["binary_path"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    stale: false,
                }),
            );
        }
        for change in added("registry") {
            let key = change["key"].as_str().unwrap();
            let view = if change["view"] == "32" {
                RegView::Bits32
            } else {
                RegView::Bits64
            };
            machine = machine.key(key, view);
            if let Some(name) = key
                .get(..SERVICES_KEY.len() + 1)
                .filter(|head| head.eq_ignore_ascii_case(&format!("{SERVICES_KEY}\\")))
                .map(|_| &key[SERVICES_KEY.len() + 1..])
                .filter(|name| !name.contains('\\'))
            {
                let value = |wanted: &str| -> Option<String> {
                    change["after"]["values"]
                        .as_array()?
                        .iter()
                        .find_map(|value| {
                            (value["name"] == wanted)
                                .then(|| value["data"].as_str().unwrap().to_owned())
                        })
                };
                machine.keys.insert(
                    name.to_ascii_lowercase(),
                    ServiceKey {
                        name: name.to_owned(),
                        image: value("ImagePath").unwrap_or_default(),
                        service_type: value("Type")
                            .and_then(|data| data.parse().ok())
                            .unwrap_or(0),
                    },
                );
            }
        }
        for change in added("files") {
            let path = change["path"].as_str().unwrap();
            let signature = change["signer"].as_str().map_or_else(
                || Signature::Unknown("the snapshot did not read it".to_owned()),
                |signer| Signature::Verified(signer.to_owned()),
            );
            machine = machine.file(path, signature);
            if let Some((folder, _)) = path.rsplit_once('\\') {
                machine = machine.directory(folder);
            }
        }
        machine
    }

    #[test]
    fn the_ea_install_is_found_by_its_own_draft() {
        // The draft, parsed by the real parser, against the machine its own
        // diff describes: the round trip from observation to detection.
        let draft = catalog(include_str!(
            "../../../observations/2026-10-09-ea-anticheat/draft.toml"
        ));

        let report = audit(&draft, &machine_from_ea_install(), &environment());

        assert!(!report.partial(), "{:?}", report.unreadable);
        assert_eq!(report.protected, [], "the draft passes the deny-list");
        let has = |wanted: &dyn Fn(&Artifact) -> bool| {
            report
                .findings
                .iter()
                .any(|finding| wanted(&finding.artifact))
        };
        assert!(has(&|artifact| matches!(
            artifact,
            Artifact::Service { name, registry_only: false, .. } if name == "EAAntiCheatService"
        )));
        // The minifilter SCM did not list until a restart.
        assert!(has(&|artifact| matches!(
            artifact,
            Artifact::Service { name, registry_only: true, .. } if name == "EAAntiCheat"
        )));
        // Its image is not on disk while no game runs, and it is still found.
        assert!(has(&|artifact| matches!(
            artifact,
            Artifact::Driver { file, service: Some(service), image_present: false, .. }
                if file == "eaanticheat.sys" && service == "EAAntiCheat"
        )));
        assert!(has(&|artifact| matches!(
            artifact,
            Artifact::RegistryKey { key, view: RegView::Bits64 } if key == "HKLM\\SOFTWARE\\EA\\AC"
        )));
        assert!(has(&|artifact| matches!(
            artifact,
            Artifact::Path { path, directory: true } if path == "C:\\Program Files\\EA\\AC"
        )));
    }

    #[test]
    fn service_images_are_read_the_way_windows_writes_them() {
        let root = "C:\\Windows";
        for (configured, expected) in [
            (
                "\"C:\\Program Files\\EA\\AC\\eaanticheat.gameservice.exe\"",
                "C:\\Program Files\\EA\\AC\\eaanticheat.gameservice.exe",
            ),
            (
                "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                "C:\\Windows\\system32\\svchost.exe",
            ),
            (
                "\\SystemRoot\\System32\\drivers\\vgk.sys",
                "C:\\Windows\\System32\\drivers\\vgk.sys",
            ),
            (
                "system32\\drivers\\eaanticheat.sys",
                "C:\\Windows\\system32\\drivers\\eaanticheat.sys",
            ),
            ("\\??\\D:\\Games\\x\\driver.sys", "D:\\Games\\x\\driver.sys"),
        ] {
            assert_eq!(
                image_file(configured, root).as_deref(),
                Some(expected),
                "{configured}"
            );
        }
        assert_eq!(image_file("   ", root), None);
    }
}
