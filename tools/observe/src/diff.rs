//! Comparing two snapshots.
//!
//! Pure logic, and the part worth getting right: everything downstream — the
//! draft catalog entry, the residue claim, the whole founding argument that
//! vendor uninstallers leave things behind — is only as good as what this
//! module decides counts as a change.
//!
//! # Nothing is discarded
//!
//! `docs/16-OBSERVATION-HARNESS.md` calls for a noise filter, and a filter that
//! silently drops things is a filter nobody can audit. So suppression here is
//! **relocation, not deletion**: a suppressed change moves to
//! [`Diff::suppressed`] with the name of the rule that moved it. The default
//! view is clean, and the question "what did the filter hide from me?" has an
//! answer in the same file.
//!
//! That matters more than it sounds. The failure mode for this tool is a noise
//! rule that quietly eats the one service the anti-cheat installed, and the
//! catalog entry is then wrong in the direction of missing something — which is
//! how a user ends up with a driver WardSweep said was gone.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::model::{Coverage, FileRecord, RegistryRecord, ServiceRecord, Snapshot};

/// Wire-format version of a diff file.
pub const DIFF_FORMAT_VERSION: u32 = 1;

/// What happened to one item between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Present in the later snapshot only.
    Added,
    /// Present in the earlier snapshot only.
    Removed,
    /// Present in both, with at least one field different.
    Modified,
}

/// One field that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldChange {
    /// Field name, matching the snapshot model.
    pub field: String,
    /// Value in the earlier snapshot.
    pub before: String,
    /// Value in the later snapshot.
    pub after: String,
}

/// A service or driver that differs between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceChange {
    /// Service key name.
    pub name: String,
    /// Added, removed, or modified.
    pub kind: ChangeKind,
    /// Whether the record involved describes a driver. Carried on the change so
    /// `suggest` need not go back to the snapshots to infer `kind = "kernel"`.
    pub is_driver: bool,
    /// Whether it loads at boot — `docs/16` maps this to `risk = "critical"`.
    pub is_boot_start: bool,
    /// The record as it was, when there was one.
    pub before: Option<ServiceRecord>,
    /// The record as it is, when there is one.
    pub after: Option<ServiceRecord>,
    /// Field-level differences, for a modification.
    #[serde(default)]
    pub fields: Vec<FieldChange>,
}

/// A file that differs between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    /// Full path.
    pub path: String,
    /// Added, removed, or modified.
    pub kind: ChangeKind,
    /// The signer of whichever record exists, carried so a reviewer can cluster
    /// by publisher without going back to the snapshots. `docs/16` calls this
    /// the single most useful signal there is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Whether the path names a kernel driver image.
    pub is_driver_image: bool,
    /// The record as it was, when there was one.
    pub before: Option<FileRecord>,
    /// The record as it is, when there is one.
    pub after: Option<FileRecord>,
    /// Field-level differences, for a modification.
    #[serde(default)]
    pub fields: Vec<FieldChange>,
}

/// A registry key that differs between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryChange {
    /// Full key path.
    pub key: String,
    /// Which WOW64 view. The same logical key can differ between the two, and
    /// `docs/05-DETECTION-ENGINE.md` treats them as distinct artifacts.
    pub view: String,
    /// Added, removed, or modified.
    pub kind: ChangeKind,
    /// The record as it was, when there was one.
    pub before: Option<RegistryRecord>,
    /// The record as it is, when there is one.
    pub after: Option<RegistryRecord>,
    /// Value-level differences, for a modification.
    #[serde(default)]
    pub fields: Vec<FieldChange>,
}

/// A change the noise filter moved out of the way, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppressed {
    /// The rule that matched. Named, so it can be argued with.
    pub rule: String,
    /// The change itself, unmodified.
    pub change: ServiceChange,
}

/// A file change the noise filter moved out of the way, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressedFile {
    /// The rule that matched.
    pub rule: String,
    /// The change itself, unmodified.
    pub change: FileChange,
}

/// The result of comparing two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diff {
    /// Wire-format version; see [`DIFF_FORMAT_VERSION`].
    pub format_version: u32,
    /// When the earlier snapshot was taken.
    pub before_taken_utc: String,
    /// When the later snapshot was taken.
    pub after_taken_utc: String,
    /// What both snapshots covered. A diff can speak only about these domains.
    pub coverage: Coverage,
    /// Service and driver changes that survived the noise filter.
    pub services: Vec<ServiceChange>,
    /// Changes the noise filter moved aside, each with its rule.
    pub suppressed: Vec<Suppressed>,
    /// File changes that survived the noise filter.
    #[serde(default)]
    pub files: Vec<FileChange>,
    /// File changes the noise filter moved aside.
    #[serde(default)]
    pub suppressed_files: Vec<SuppressedFile>,
    /// Registry changes.
    #[serde(default)]
    pub registry: Vec<RegistryChange>,
    /// Whether the two snapshots walked the registry under different rules.
    #[serde(default)]
    pub registry_policy_changed: bool,
    /// Whether the two snapshots walked the filesystem under different rules.
    ///
    /// When this is true every file difference below is suspect, because a
    /// change to the roots, the exclusions or the hash policy moves files in
    /// and out of the snapshot without anything happening on the machine.
    ///
    /// This is not hypothetical. The first two full snapshots taken during
    /// development were captured either side of a change to the exclusion list,
    /// and 86 of the 109 reported differences were the list, not the machine.
    /// A diff that cannot notice that is a diff that invents evidence.
    #[serde(default)]
    pub filesystem_policy_changed: bool,
    /// Signer common names seen among the surviving file changes, with counts.
    ///
    /// The clustering `docs/16` asks for, precomputed: everything an installer
    /// dropped shares a publisher, so a single unfamiliar name against a large
    /// count is usually the whole footprint.
    #[serde(default)]
    pub signers: BTreeMap<String, usize>,
}

impl Diff {
    /// Suppression counts by rule, for a summary line.
    #[must_use]
    pub fn suppression_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for entry in &self.suppressed {
            *counts.entry(entry.rule.clone()).or_insert(0) += 1;
        }
        for entry in &self.suppressed_files {
            *counts.entry(entry.rule.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// Why a snapshot could not be diffed.
#[derive(Debug)]
pub enum DiffError {
    /// A snapshot's format version is not implemented by this build.
    UnsupportedFormat {
        /// The version found in the file.
        found: u32,
        /// The version this build implements.
        supported: u32,
    },
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat { found, supported } => write!(
                f,
                "snapshot format version {found} is not supported by this build, which implements {supported}"
            ),
        }
    }
}

impl std::error::Error for DiffError {}

/// Compare two snapshots.
///
/// # Errors
/// If either snapshot's format version is not implemented.
pub fn compare(
    before: &Snapshot,
    after: &Snapshot,
    filter: &NoiseFilter,
) -> Result<Diff, DiffError> {
    for snapshot in [before, after] {
        if snapshot.format_version != crate::model::SNAPSHOT_FORMAT_VERSION {
            return Err(DiffError::UnsupportedFormat {
                found: snapshot.format_version,
                supported: crate::model::SNAPSHOT_FORMAT_VERSION,
            });
        }
    }

    let mut changes = compare_services(&before.services, &after.services, filter);
    changes.sort_by(|a, b| a.name.cmp(&b.name));

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();
    for change in changes {
        match filter.rule_for(&change) {
            Some(rule) => suppressed.push(Suppressed {
                rule: rule.to_owned(),
                change,
            }),
            None => kept.push(change),
        }
    }

    let coverage = before.coverage.intersect(&after.coverage);

    // Only diff a domain both sides actually captured. Comparing a snapshot
    // that walked the filesystem against one that did not would report every
    // file as removed, which is an artefact of the collection rather than
    // anything that happened on the machine.
    let (files, suppressed_files) = if coverage.covers(crate::model::Domain::Filesystem) {
        compare_files(&before.files, &after.files, filter)
    } else {
        (Vec::new(), Vec::new())
    };

    // Compared before the changes are read, because it decides whether they
    // mean anything.
    let filesystem_policy_changed = before.filesystem_policy != after.filesystem_policy;
    let registry_policy_changed = before.registry_policy != after.registry_policy;

    let registry = if coverage.covers(crate::model::Domain::Registry) {
        compare_registry(&before.registry, &after.registry)
    } else {
        Vec::new()
    };

    let mut signers: BTreeMap<String, usize> = BTreeMap::new();
    for change in &files {
        if let Some(signer) = &change.signer {
            *signers.entry(signer.clone()).or_insert(0) += 1;
        }
    }

    Ok(Diff {
        format_version: DIFF_FORMAT_VERSION,
        before_taken_utc: before.taken_utc.clone(),
        after_taken_utc: after.taken_utc.clone(),
        coverage,
        services: kept,
        suppressed,
        files,
        suppressed_files,
        filesystem_policy_changed,
        registry,
        registry_policy_changed,
        signers,
    })
}

fn compare_registry(before: &[RegistryRecord], after: &[RegistryRecord]) -> Vec<RegistryChange> {
    // Keyed by path *and* view: the same logical key read through the 32-bit
    // and 64-bit views is two artifacts, and collapsing them would report a
    // value present in one view and absent in the other as no change at all.
    let index = |records: &[RegistryRecord]| -> BTreeMap<(String, String), RegistryRecord> {
        records
            .iter()
            .map(|record| {
                (
                    (record.key.to_ascii_lowercase(), record.view.clone()),
                    record.clone(),
                )
            })
            .collect()
    };

    let before_index = index(before);
    let after_index = index(after);
    let identities: BTreeSet<&(String, String)> =
        before_index.keys().chain(after_index.keys()).collect();

    identities
        .into_iter()
        .filter_map(|identity| {
            let old = before_index.get(identity);
            let new = after_index.get(identity);
            match (old, new) {
                (None, Some(record)) => Some(RegistryChange {
                    key: record.key.clone(),
                    view: record.view.clone(),
                    kind: ChangeKind::Added,
                    before: None,
                    after: Some(record.clone()),
                    fields: Vec::new(),
                }),
                (Some(record), None) => Some(RegistryChange {
                    key: record.key.clone(),
                    view: record.view.clone(),
                    kind: ChangeKind::Removed,
                    before: Some(record.clone()),
                    after: None,
                    fields: Vec::new(),
                }),
                (Some(old), Some(new)) => {
                    let fields = value_changes(old, new);
                    if fields.is_empty() {
                        return None;
                    }
                    Some(RegistryChange {
                        key: new.key.clone(),
                        view: new.view.clone(),
                        kind: ChangeKind::Modified,
                        before: Some(old.clone()),
                        after: Some(new.clone()),
                        fields,
                    })
                }
                (None, None) => None,
            }
        })
        .collect()
}

fn value_changes(before: &RegistryRecord, after: &RegistryRecord) -> Vec<FieldChange> {
    let map = |record: &RegistryRecord| -> BTreeMap<String, String> {
        record
            .values
            .iter()
            .map(|value| (value.name.clone(), format!("{}:{}", value.kind, value.data)))
            .collect()
    };

    let old = map(before);
    let new = map(after);
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();

    names
        .into_iter()
        .filter_map(|name| {
            let was = old.get(name);
            let now = new.get(name);
            if was == now {
                return None;
            }
            Some(FieldChange {
                // Rendered as the value name so a reviewer sees which value
                // moved, not merely that the key did.
                field: if name.is_empty() {
                    "(default)".to_owned()
                } else {
                    name.clone()
                },
                before: was.cloned().unwrap_or_default(),
                after: now.cloned().unwrap_or_default(),
            })
        })
        .collect()
}

fn compare_files(
    before: &[FileRecord],
    after: &[FileRecord],
    filter: &NoiseFilter,
) -> (Vec<FileChange>, Vec<SuppressedFile>) {
    let index = |records: &[FileRecord]| -> BTreeMap<String, FileRecord> {
        records
            .iter()
            .map(|record| (record.path.to_ascii_lowercase(), record.clone()))
            .collect()
    };

    let before_index = index(before);
    let after_index = index(after);
    let paths: BTreeSet<&String> = before_index.keys().chain(after_index.keys()).collect();

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for path in paths {
        let old = before_index.get(path);
        let new = after_index.get(path);

        let change = match (old, new) {
            (None, Some(record)) => FileChange {
                path: record.path.clone(),
                kind: ChangeKind::Added,
                signer: record.signer.clone(),
                is_driver_image: record.is_driver_image(),
                before: None,
                after: Some(record.clone()),
                fields: Vec::new(),
            },
            (Some(record), None) => FileChange {
                path: record.path.clone(),
                kind: ChangeKind::Removed,
                signer: record.signer.clone(),
                is_driver_image: record.is_driver_image(),
                before: Some(record.clone()),
                after: None,
                fields: Vec::new(),
            },
            (Some(old), Some(new)) => {
                let fields = file_field_changes(old, new);
                if fields.is_empty() {
                    continue;
                }
                FileChange {
                    path: new.path.clone(),
                    kind: ChangeKind::Modified,
                    signer: new.signer.clone(),
                    is_driver_image: new.is_driver_image(),
                    before: Some(old.clone()),
                    after: Some(new.clone()),
                    fields,
                }
            }
            (None, None) => continue,
        };

        match filter.file_rule_for(&change) {
            Some(rule) => suppressed.push(SuppressedFile {
                rule: rule.to_owned(),
                change,
            }),
            None => kept.push(change),
        }
    }

    (kept, suppressed)
}

fn file_field_changes(before: &FileRecord, after: &FileRecord) -> Vec<FieldChange> {
    fn compare(changes: &mut Vec<FieldChange>, field: &str, old: &str, new: &str) {
        if old != new {
            changes.push(FieldChange {
                field: field.to_owned(),
                before: old.to_owned(),
                after: new.to_owned(),
            });
        }
    }

    let mut changes = Vec::new();
    compare(
        &mut changes,
        "size",
        &before.size.to_string(),
        &after.size.to_string(),
    );
    compare(
        &mut changes,
        "sha256",
        before.sha256.as_deref().unwrap_or_default(),
        after.sha256.as_deref().unwrap_or_default(),
    );
    compare(
        &mut changes,
        "signer",
        before.signer.as_deref().unwrap_or_default(),
        after.signer.as_deref().unwrap_or_default(),
    );
    // Reported only alongside something else. docs/16 asks for timestamp-only
    // changes to be ignored, and a file whose size and contents are identical
    // was not touched by an installer whatever its timestamp says.
    if !changes.is_empty() {
        compare(
            &mut changes,
            "modified_utc",
            &before.modified_utc,
            &after.modified_utc,
        );
    }

    changes
}

fn compare_services(
    before: &[ServiceRecord],
    after: &[ServiceRecord],
    filter: &NoiseFilter,
) -> Vec<ServiceChange> {
    let index = |records: &[ServiceRecord]| -> BTreeMap<String, ServiceRecord> {
        records
            .iter()
            .map(|record| (filter.canonical_name(&record.name), record.clone()))
            .collect()
    };

    let before_index = index(before);
    let after_index = index(after);

    let names: BTreeSet<&String> = before_index.keys().chain(after_index.keys()).collect();

    names
        .into_iter()
        .filter_map(|name| {
            let old = before_index.get(name);
            let new = after_index.get(name);
            match (old, new) {
                (None, Some(record)) => Some(ServiceChange {
                    name: name.clone(),
                    kind: ChangeKind::Added,
                    is_driver: record.is_driver(),
                    is_boot_start: record.is_boot_start(),
                    before: None,
                    after: Some(record.clone()),
                    fields: Vec::new(),
                }),
                (Some(record), None) => Some(ServiceChange {
                    name: name.clone(),
                    kind: ChangeKind::Removed,
                    is_driver: record.is_driver(),
                    is_boot_start: record.is_boot_start(),
                    before: Some(record.clone()),
                    after: None,
                    fields: Vec::new(),
                }),
                (Some(old), Some(new)) => {
                    let fields = field_changes(old, new);
                    if fields.is_empty() {
                        return None;
                    }
                    Some(ServiceChange {
                        name: name.clone(),
                        kind: ChangeKind::Modified,
                        is_driver: new.is_driver(),
                        is_boot_start: new.is_boot_start(),
                        before: Some(old.clone()),
                        after: Some(new.clone()),
                        fields,
                    })
                }
                (None, None) => None,
            }
        })
        .collect()
}

fn field_changes(before: &ServiceRecord, after: &ServiceRecord) -> Vec<FieldChange> {
    let mut changes = Vec::new();
    let mut compare = |field: &str, old: &str, new: &str| {
        if old != new {
            changes.push(FieldChange {
                field: field.to_owned(),
                before: old.to_owned(),
                after: new.to_owned(),
            });
        }
    };

    compare("display_name", &before.display_name, &after.display_name);
    compare("service_type", &before.service_type, &after.service_type);
    compare("start_type", &before.start_type, &after.start_type);
    compare("error_control", &before.error_control, &after.error_control);
    compare("binary_path", &before.binary_path, &after.binary_path);
    compare(
        "load_order_group",
        &before.load_order_group,
        &after.load_order_group,
    );
    compare("start_name", &before.start_name, &after.start_name);
    compare("description", &before.description, &after.description);
    compare(
        "dependencies",
        &before.dependencies.join(";"),
        &after.dependencies.join(";"),
    );
    compare(
        "delayed_auto_start",
        &before.delayed_auto_start.to_string(),
        &after.delayed_auto_start.to_string(),
    );

    changes
}

/// The noise filter from `docs/16-OBSERVATION-HARNESS.md`.
///
/// Shipped, versioned and reviewable, as that document requires — and every
/// rule it applies is named in the output rather than applied invisibly.
#[derive(Debug, Clone)]
pub struct NoiseFilter {
    ignored: Vec<String>,
    normalise_per_user_instances: bool,
}

impl Default for NoiseFilter {
    fn default() -> Self {
        Self::standard()
    }
}

impl NoiseFilter {
    /// The shipped rule set.
    ///
    /// Deliberately short. Every entry is a service whose *configuration*
    /// changes on its own — which is a much smaller set than the services whose
    /// running state changes, because the snapshot records configuration only.
    /// Windows Update and Defender are here because their binary paths carry a
    /// platform version that moves under them.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            ignored: [
                // Windows Update and its servicing stack.
                "wuauserv",
                "UsoSvc",
                "WaaSMedicSvc",
                "TrustedInstaller",
                "DoSvc",
                // Defender: the platform directory is versioned, so the image
                // path moves with every definition platform update.
                "WinDefend",
                "WdNisSvc",
                "Sense",
                "MsSecFlt",
                "webthreatdefsvc",
                // Third-party updaters that reinstall themselves.
                "edgeupdate",
                "edgeupdatem",
                "gupdate",
                "gupdatem",
                "MozillaMaintenance",
            ]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
            normalise_per_user_instances: true,
        }
    }

    /// A filter that suppresses nothing, for tests and for `--no-filter`.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            ignored: Vec::new(),
            normalise_per_user_instances: false,
        }
    }

    /// The name a service is indexed under.
    ///
    /// Per-user service instances get a per-logon-session suffix —
    /// `WpnUserService_5a1f2`, `cbdhsvc_5a1f2`, `OneSyncSvc_5a1f2`. The suffix
    /// changes on every logon, so without collapsing it a snapshot pair taken
    /// across a reboot reports every one of them as both removed and added,
    /// which is a dozen entries of pure noise and no information at all.
    ///
    /// The template name is what is stable, and it is what a catalog entry
    /// would ever name.
    #[must_use]
    pub fn canonical_name(&self, name: &str) -> String {
        if !self.normalise_per_user_instances {
            return name.to_owned();
        }

        match name.rsplit_once('_') {
            // At least four hex digits, and no non-hex characters: short enough
            // suffixes and word-like ones are ordinary parts of a service name.
            Some((stem, suffix))
                if suffix.len() >= 4
                    && !stem.is_empty()
                    && suffix.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                stem.to_owned()
            }
            _ => name.to_owned(),
        }
    }

    /// The rule that suppresses a file change, if any.
    ///
    /// The walk already refused to descend into the volatile directories, so
    /// little is left to do here. What remains is the case the walk cannot see:
    /// a file whose only difference is its timestamp, which `docs/16` asks to
    /// be ignored and which `file_field_changes` already declines to report on
    /// its own — this is the belt to that brace.
    #[must_use]
    pub fn file_rule_for(&self, change: &FileChange) -> Option<&str> {
        if !self.normalise_per_user_instances {
            return None;
        }
        if change.kind == ChangeKind::Modified
            && change.fields.len() == 1
            && change.fields[0].field == "modified_utc"
        {
            return Some("timestamp-only");
        }
        None
    }

    /// The rule that suppresses this change, if any.
    #[must_use]
    pub fn rule_for(&self, change: &ServiceChange) -> Option<&str> {
        self.ignored
            .iter()
            .find(|ignored| ignored.eq_ignore_ascii_case(&change.name))
            .map(|_| "volatile-service")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{Coverage, Domain, SNAPSHOT_FORMAT_VERSION};

    fn service(name: &str) -> ServiceRecord {
        ServiceRecord {
            name: name.to_owned(),
            display_name: name.to_owned(),
            service_type: "win32_own_process".to_owned(),
            start_type: "demand".to_owned(),
            error_control: "normal".to_owned(),
            binary_path: format!("C:\\Windows\\System32\\{name}.exe"),
            load_order_group: String::new(),
            start_name: "LocalSystem".to_owned(),
            dependencies: Vec::new(),
            description: String::new(),
            delayed_auto_start: false,
        }
    }

    fn snapshot(services: Vec<ServiceRecord>) -> Snapshot {
        Snapshot {
            format_version: SNAPSHOT_FORMAT_VERSION,
            taken_utc: "2026-08-19T00:00:00.000Z".to_owned(),
            harness_version: "test".to_owned(),
            label: String::new(),
            coverage: Coverage {
                captured: vec![Domain::Services],
                not_captured: Vec::new(),
                access_denied: Vec::new(),
            },
            services,
            files: Vec::new(),
            filesystem_policy: None,
            registry: Vec::new(),
            registry_policy: None,
        }
    }

    /// A diff carrying nothing but a set of added files, for other modules.
    pub(crate) fn diff_with_added_files(paths: &[&str]) -> Diff {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        before.coverage.captured.push(Domain::Filesystem);
        after.coverage.captured.push(Domain::Filesystem);
        after.files = paths
            .iter()
            .map(|path| crate::model::FileRecord {
                path: (*path).to_owned(),
                size: 1,
                modified_utc: String::new(),
                sha256: None,
                signer: None,
                not_hashed: None,
            })
            .collect();
        compare(&before, &after, &NoiseFilter::permissive()).expect("fixture diffs cleanly")
    }

    #[test]
    fn a_new_service_is_reported_as_added() {
        let before = snapshot(vec![]);
        let after = snapshot(vec![service("vgk")]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.services.len(), 1);
        assert_eq!(diff.services[0].kind, ChangeKind::Added);
        assert_eq!(diff.services[0].name, "vgk");
    }

    #[test]
    fn an_unchanged_service_produces_no_entry() {
        let before = snapshot(vec![service("spooler")]);
        let after = snapshot(vec![service("spooler")]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert!(diff.services.is_empty());
        assert!(diff.suppressed.is_empty());
    }

    #[test]
    fn a_changed_start_type_is_reported_field_by_field() {
        let before = snapshot(vec![service("vgk")]);
        let mut changed = service("vgk");
        changed.start_type = "boot".to_owned();
        let after = snapshot(vec![changed]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.services[0].kind, ChangeKind::Modified);
        assert_eq!(diff.services[0].fields.len(), 1);
        assert_eq!(diff.services[0].fields[0].field, "start_type");
        assert_eq!(diff.services[0].fields[0].after, "boot");
        assert!(diff.services[0].is_boot_start);
    }

    #[test]
    fn per_user_service_instances_collapse_to_their_template_name() {
        // The suffix changes on every logon. Without collapsing, this pair
        // reports one removal and one addition and says nothing.
        let before = snapshot(vec![service("cbdhsvc_5a1f2")]);
        let after = snapshot(vec![service("cbdhsvc_9c3e7")]);

        let diff = compare(&before, &after, &NoiseFilter::standard()).unwrap();

        // The binary path differs because the fixture builds it from the name,
        // so a modification is expected — but not an add plus a remove.
        assert!(diff.services.iter().all(|c| c.kind == ChangeKind::Modified));
        assert_eq!(diff.services.len(), 1);
        assert_eq!(diff.services[0].name, "cbdhsvc");
    }

    #[test]
    fn a_short_or_word_like_suffix_is_not_treated_as_a_session_id() {
        let filter = NoiseFilter::standard();
        // Real service names that must survive intact.
        assert_eq!(
            filter.canonical_name("EasyAntiCheat_EOS"),
            "EasyAntiCheat_EOS"
        );
        assert_eq!(filter.canonical_name("BEService_x64"), "BEService_x64");
        assert_eq!(filter.canonical_name("svc_abc"), "svc_abc");
        // And one that must not.
        assert_eq!(filter.canonical_name("OneSyncSvc_5a1f2"), "OneSyncSvc");
    }

    #[test]
    fn a_suppressed_change_is_relocated_and_named_never_dropped() {
        let before = snapshot(vec![]);
        let after = snapshot(vec![service("WinDefend")]);

        let diff = compare(&before, &after, &NoiseFilter::standard()).unwrap();

        assert!(diff.services.is_empty());
        assert_eq!(diff.suppressed.len(), 1);
        assert_eq!(diff.suppressed[0].rule, "volatile-service");
        // The change itself survives intact, so the filter can be argued with.
        assert_eq!(diff.suppressed[0].change.name, "WinDefend");
        assert_eq!(diff.suppression_counts()["volatile-service"], 1);
    }

    #[test]
    fn the_noise_filter_never_suppresses_an_unknown_service() {
        // The failure mode that matters: a rule quietly eating the one service
        // the anti-cheat installed.
        let before = snapshot(vec![]);
        let after = snapshot(vec![service("vgk"), service("EasyAntiCheat")]);

        let diff = compare(&before, &after, &NoiseFilter::standard()).unwrap();

        assert_eq!(diff.services.len(), 2);
        assert!(diff.suppressed.is_empty());
    }

    #[test]
    fn a_policy_change_between_snapshots_is_flagged() {
        use crate::model::FilesystemPolicy;

        let policy = |excluded: &str| {
            Some(FilesystemPolicy {
                roots: vec!["C:\\Program Files".to_owned()],
                excluded: vec![excluded.to_owned()],
                hashed_extensions: vec!["sys".to_owned()],
                max_hash_bytes: 1,
            })
        };

        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        before.coverage.captured.push(Domain::Filesystem);
        after.coverage.captured.push(Domain::Filesystem);
        before.filesystem_policy = policy("\\temp\\");
        after.filesystem_policy = policy("\\windows\\temp\\");

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert!(diff.filesystem_policy_changed);
    }

    #[test]
    fn an_unchanged_policy_is_not_flagged() {
        let mut before = snapshot(vec![]);
        let after = snapshot(vec![]);
        before.coverage.captured.push(Domain::Filesystem);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert!(!diff.filesystem_policy_changed);
    }

    #[test]
    fn coverage_is_carried_forward_as_the_intersection() {
        let mut before = snapshot(vec![]);
        before.coverage.captured = vec![Domain::Services, Domain::Registry];
        let after = snapshot(vec![]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.coverage.captured, vec![Domain::Services]);
        assert!(diff.coverage.not_captured.contains(&Domain::Registry));
    }

    #[test]
    fn a_snapshot_from_the_future_is_refused_rather_than_misread() {
        let mut before = snapshot(vec![]);
        before.format_version = SNAPSHOT_FORMAT_VERSION + 1;
        let after = snapshot(vec![]);

        let error = compare(&before, &after, &NoiseFilter::permissive()).unwrap_err();

        assert!(matches!(error, DiffError::UnsupportedFormat { .. }));
    }
}
