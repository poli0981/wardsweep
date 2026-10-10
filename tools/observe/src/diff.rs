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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::collect::filesystem;
use crate::model::{
    Coverage, Domain, FileRecord, OLDEST_SNAPSHOT_FORMAT, RegistryKeyRef, RegistryRecord,
    SNAPSHOT_FORMAT_VERSION, ServiceRecord, Snapshot,
};
use crate::policy::{Policy, is_excluded};

/// Wire-format version of a diff file.
///
/// Format 2 added [`Diff::emptied_keys`] and [`Diff::snapshot_format_version`],
/// and a registry modification now carries only the values that changed. A
/// format 1 diff is still read, and `refilter` upgrades one in place.
pub const DIFF_FORMAT_VERSION: u32 = 2;

/// The oldest diff format this build still reads.
pub const OLDEST_DIFF_FORMAT: u32 = 1;

/// The snapshot format every diff written before the field existed came from.
fn first_snapshot_format() -> u32 {
    1
}

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
    ///
    /// For a modification, only the values that differ: the rest of the key is
    /// not evidence of anything, and every value carried is one more chance to
    /// carry something personal into a file meant to be committed. A format 1
    /// diff carried both records whole.
    pub before: Option<RegistryRecord>,
    /// The record as it is, when there is one. Trimmed like `before`.
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

/// What this build's privacy policy removed before anything was compared.
///
/// See [`crate::policy`], and for files and directories the walk's exclusions
/// in [`crate::collect::filesystem`]. Every count is of something an older
/// build read and this one refuses to keep, so a non-zero value means at least
/// one snapshot predates a rule — and that the rule, not the snapshot, decided
/// what the diff may say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refiltered {
    /// Registry records dropped whole: an excluded key, or one whose every
    /// value was refused.
    #[serde(default)]
    pub registry_records: usize,
    /// Values dropped from registry records that were otherwise kept.
    #[serde(default)]
    pub registry_values: usize,
    /// `access_denied` items that named an excluded key or path.
    #[serde(default)]
    pub access_denied: usize,
    /// Emptied keys dropped because the key itself is excluded.
    #[serde(default)]
    pub emptied_keys: usize,
    /// File records dropped because their path is excluded: from both
    /// snapshots when comparing, from both sides of each change when
    /// refiltering. Absent when nothing was, so a diff that dropped no file
    /// still reads in a build that predates the count.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub files: usize,
    /// Emptied directories dropped because the directory itself is excluded.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub emptied_directories: usize,
}

/// For the counts that are written only when something was counted.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde hands the field over by reference
fn is_zero(count: &usize) -> bool {
    *count == 0
}

impl Refiltered {
    /// Whether nothing was removed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Add another count to this one.
    pub(crate) fn absorb(&mut self, other: Self) {
        self.registry_records += other.registry_records;
        self.registry_values += other.registry_values;
        self.access_denied += other.access_denied;
        self.emptied_keys += other.emptied_keys;
        self.files += other.files;
        self.emptied_directories += other.emptied_directories;
    }
}

/// One footprint an intersection was computed from.
///
/// Times and a count, never a path: a footprint's file name is whatever the
/// contributor called it, under whatever profile they keep it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Footprint {
    /// When that footprint's earlier snapshot was taken.
    pub before_taken_utc: String,
    /// When its later snapshot was taken.
    pub after_taken_utc: String,
    /// The changes it held, kept and suppressed, across every domain.
    pub changes: usize,
}

/// The result of comparing two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diff {
    /// Wire-format version; see [`DIFF_FORMAT_VERSION`].
    pub format_version: u32,
    /// The format of the two snapshots this was computed from.
    ///
    /// Not the same thing as `format_version`: `refilter` upgrades a diff's
    /// shape, and cannot upgrade what its snapshots recorded. A diff computed
    /// from format 1 snapshots holds no emptied keys and may list a 32-bit key
    /// twice, under both of its names, whatever its own format says. Absent
    /// from every format 1 diff, all of which came from format 1 snapshots.
    #[serde(default = "first_snapshot_format")]
    pub snapshot_format_version: u32,
    /// When the earlier snapshot was taken.
    pub before_taken_utc: String,
    /// When the later snapshot was taken.
    pub after_taken_utc: String,
    /// Whether the machine restarted between the two snapshots.
    ///
    /// `None` when either side predates [`crate::model::BootSession`] or was
    /// taken off Windows — *unknown*, which is not the same as `Some(false)`
    /// and must not be read as it.
    ///
    /// A restart is the single loudest cause of change in a diff: drivers load
    /// and unload, per-user service instances are recreated with fresh
    /// suffixes, and `PendingFileRenameOperations` is executed and cleared.
    /// Reading those as ordinary churn attributes them to whatever the
    /// observation happened to be about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebooted_between: Option<bool>,
    /// Directories that hold no file in the later snapshot and did in the
    /// earlier one, or that appeared already empty.
    ///
    /// This is how a diff sees an uninstaller that deleted everything it
    /// installed and left the folder it installed into. Riot Vanguard's does
    /// exactly that.
    ///
    /// `None` when either snapshot did not record directories — *not known*. An
    /// empty list would otherwise be read as "nothing was left behind", which
    /// is the one wrong answer this tool must never give.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emptied_directories: Option<Vec<String>>,
    /// Registry keys that hold no value in the later snapshot and did in the
    /// earlier one, or that appeared already empty — the registry twin of
    /// `emptied_directories`, and `None` under the same rule: unless both
    /// snapshots walked the registry and both recorded empty keys, which no
    /// snapshot older than format 2 did.
    ///
    /// Both lists hold only the topmost empty key of each chain and are
    /// compared exactly, so a subtree that was already empty is reported again
    /// if a value lands beside it and splits it. That errs towards saying too
    /// much, which a reviewer can see through, rather than too little, which
    /// nobody can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emptied_keys: Option<Vec<RegistryKeyRef>>,
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
    /// What this build's privacy policy removed from the snapshots, or from the
    /// diff itself, before anything was written. See [`Refiltered`].
    #[serde(default, skip_serializing_if = "Refiltered::is_empty")]
    pub refiltered: Refiltered,
    /// For an intersection of footprints, the footprints, in the order given;
    /// `None` for a diff of two snapshots. See [`crate::intersect`].
    ///
    /// An intersection is a diff like any other, so `suggest` drafts from it,
    /// and this is what tells a reader that it is one: its timestamps span
    /// every footprint, its changes are only those all of them hold, and its
    /// `refiltered` sums what the policy removed from each.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intersection_of: Option<Vec<Footprint>>,
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
        /// The oldest version this build reads.
        oldest: u32,
        /// The newest version this build reads, which is the one it writes.
        newest: u32,
    },
    /// The two snapshots were taken in different formats.
    ///
    /// Each format change alters what a snapshot holds without anything on the
    /// machine changing — see [`SNAPSHOT_FORMAT_VERSION`] — so a diff across
    /// one reports the harness, not the machine.
    MixedFormats {
        /// The earlier snapshot's format.
        before: u32,
        /// The later snapshot's format.
        after: u32,
    },
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat {
                found,
                oldest,
                newest,
            } => write!(
                f,
                "snapshot format version {found} is not supported by this build, which reads \
                 {oldest} to {newest}"
            ),
            Self::MixedFormats { before, after } => write!(
                f,
                "the snapshots are format {before} and format {after}, and a diff across formats \
                 reports what changed in the harness rather than on the machine; take both \
                 snapshots with the same build"
            ),
        }
    }
}

impl std::error::Error for DiffError {}

/// Compare two snapshots.
///
/// # Errors
/// If either snapshot's format version is not implemented, or the two differ.
pub fn compare(
    before: &Snapshot,
    after: &Snapshot,
    filter: &NoiseFilter,
) -> Result<Diff, DiffError> {
    for snapshot in [before, after] {
        if !(OLDEST_SNAPSHOT_FORMAT..=SNAPSHOT_FORMAT_VERSION).contains(&snapshot.format_version) {
            return Err(DiffError::UnsupportedFormat {
                found: snapshot.format_version,
                oldest: OLDEST_SNAPSHOT_FORMAT,
                newest: SNAPSHOT_FORMAT_VERSION,
            });
        }
    }
    if before.format_version != after.format_version {
        return Err(DiffError::MixedFormats {
            before: before.format_version,
            after: after.format_version,
        });
    }

    // Applied to both sides before anything is compared. A snapshot taken by an
    // older build may hold what this build refuses to read — an account's
    // e-mail address in a key name, a host name, a record of every program the
    // user ran — and a diff is written to be committed.
    let policy = Policy::current();
    let mut refiltered = Refiltered::default();

    let mut coverage = before.coverage.intersect(&after.coverage);
    refiltered.access_denied = drop_excluded_denials(&mut coverage);

    // Services answer to coverage like every other domain. A snapshot whose
    // service enumeration failed, compared with one whose did not, would report
    // every service on the machine as added or removed.
    let changes = if coverage.covers(Domain::Services) {
        compare_services(&before.services, &after.services, filter)
    } else {
        Vec::new()
    };

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

    // Only diff a domain both sides actually captured. Comparing a snapshot
    // that walked the filesystem against one that did not would report every
    // file as removed, which is an artefact of the collection rather than
    // anything that happened on the machine.
    let (files, suppressed_files) = if coverage.covers(crate::model::Domain::Filesystem) {
        compare_files(&before.files, &after.files, filter, &mut refiltered)
    } else {
        (Vec::new(), Vec::new())
    };

    // Compared before the changes are read, because it decides whether they
    // mean anything.
    let filesystem_policy_changed = before.filesystem_policy != after.filesystem_policy;
    let registry_policy_changed = before.registry_policy != after.registry_policy;

    let registry = if coverage.covers(crate::model::Domain::Registry) {
        compare_registry(&before.registry, &after.registry, &policy, &mut refiltered)
    } else {
        Vec::new()
    };

    // Directories are part of the filesystem domain, so they answer to the same
    // coverage rule the file list does. Empty keys likewise to the registry's.
    let emptied_directories = emptied_directories(before, after, &coverage, &mut refiltered);
    let emptied_keys = emptied_keys(before, after, &coverage, &mut refiltered);
    let signers = signer_counts(&files);

    Ok(Diff {
        format_version: DIFF_FORMAT_VERSION,
        snapshot_format_version: before.format_version,
        before_taken_utc: before.taken_utc.clone(),
        after_taken_utc: after.taken_utc.clone(),
        rebooted_between: rebooted_between(before, after),
        emptied_directories,
        emptied_keys,
        coverage,
        services: kept,
        suppressed,
        files,
        suppressed_files,
        filesystem_policy_changed,
        registry,
        registry_policy_changed,
        signers,
        refiltered,
        intersection_of: None,
    })
}

/// The same diff read the other way round: what it removed, added.
///
/// For a diff taken from an installed machine to an uninstalled one — the
/// first half of the uninstall-and-reinstall cycle, and the only half of the
/// committed `AntiCheatExpert` observation — the footprint is what was
/// *removed*, and `suggest` drafts from additions. Every change swaps its kind, its two
/// records and each field's two values; flags and signers are read again from
/// the record that is now the later one.
///
/// The emptied lists become `None`: the reverse of "emptied" — empty before,
/// gone or occupied after — is not something either snapshot recorded, and an
/// empty list would claim it was.
#[must_use]
pub fn reversed(diff: &Diff) -> Diff {
    fn kind(kind: ChangeKind) -> ChangeKind {
        match kind {
            ChangeKind::Added => ChangeKind::Removed,
            ChangeKind::Removed => ChangeKind::Added,
            ChangeKind::Modified => ChangeKind::Modified,
        }
    }
    fn fields(fields: &[FieldChange]) -> Vec<FieldChange> {
        fields
            .iter()
            .map(|field| FieldChange {
                field: field.field.clone(),
                before: field.after.clone(),
                after: field.before.clone(),
            })
            .collect()
    }
    fn service(change: &ServiceChange) -> ServiceChange {
        let later = change.before.as_ref().or(change.after.as_ref());
        ServiceChange {
            name: change.name.clone(),
            kind: kind(change.kind),
            is_driver: later.map_or(change.is_driver, ServiceRecord::is_driver),
            is_boot_start: later.map_or(change.is_boot_start, ServiceRecord::is_boot_start),
            before: change.after.clone(),
            after: change.before.clone(),
            fields: fields(&change.fields),
        }
    }
    fn file(change: &FileChange) -> FileChange {
        let later = change.before.as_ref().or(change.after.as_ref());
        FileChange {
            path: change.path.clone(),
            kind: kind(change.kind),
            signer: later.map_or_else(|| change.signer.clone(), |record| record.signer.clone()),
            is_driver_image: change.is_driver_image,
            before: change.after.clone(),
            after: change.before.clone(),
            fields: fields(&change.fields),
        }
    }

    let files: Vec<FileChange> = diff.files.iter().map(file).collect();
    let signers = signer_counts(&files);

    Diff {
        format_version: diff.format_version,
        snapshot_format_version: diff.snapshot_format_version,
        before_taken_utc: diff.after_taken_utc.clone(),
        after_taken_utc: diff.before_taken_utc.clone(),
        rebooted_between: diff.rebooted_between,
        emptied_directories: None,
        emptied_keys: None,
        coverage: diff.coverage.clone(),
        services: diff.services.iter().map(service).collect(),
        suppressed: diff
            .suppressed
            .iter()
            .map(|entry| Suppressed {
                rule: entry.rule.clone(),
                change: service(&entry.change),
            })
            .collect(),
        files,
        suppressed_files: diff
            .suppressed_files
            .iter()
            .map(|entry| SuppressedFile {
                rule: entry.rule.clone(),
                change: file(&entry.change),
            })
            .collect(),
        registry: diff
            .registry
            .iter()
            .map(|change| RegistryChange {
                key: change.key.clone(),
                view: change.view.clone(),
                kind: kind(change.kind),
                before: change.after.clone(),
                after: change.before.clone(),
                fields: fields(&change.fields),
            })
            .collect(),
        registry_policy_changed: diff.registry_policy_changed,
        filesystem_policy_changed: diff.filesystem_policy_changed,
        signers,
        refiltered: diff.refiltered,
        intersection_of: diff.intersection_of.clone(),
    }
}

/// Apply this build's privacy policy to a diff that already exists.
///
/// The same rule [`compare`] applies to snapshots, for a diff produced before
/// the rule existed: drop every change under an excluded key or path, drop
/// refused values from the records that remain, and recompute what is left — a
/// modification whose only differences were refused values is no longer a
/// change at all. This is what makes cleaning a committed diff reproducible from
/// committed code rather than from a script nobody kept.
///
/// It also brings the diff to the current format: a modification keeps only
/// the values that changed. What the snapshots recorded cannot be upgraded, and
/// [`Diff::snapshot_format_version`] keeps saying which format that was.
pub fn refilter(diff: &mut Diff, policy: &Policy) -> Refiltered {
    let mut report = Refiltered {
        access_denied: drop_excluded_denials(&mut diff.coverage),
        ..Refiltered::default()
    };
    if let Some(keys) = diff.emptied_keys.as_mut() {
        let listed = keys.len();
        keys.retain(|key| !is_excluded(&key.key));
        report.emptied_keys = listed - keys.len();
    }
    if let Some(directories) = diff.emptied_directories.as_mut() {
        let listed = directories.len();
        directories.retain(|directory| !filesystem::is_excluded(Path::new(directory)));
        report.emptied_directories = listed - directories.len();
    }
    report.files = drop_excluded_files(diff);

    let upgrading = diff.format_version != DIFF_FORMAT_VERSION;
    let mut kept = Vec::with_capacity(diff.registry.len());
    for change in std::mem::take(&mut diff.registry) {
        // A change the policy has nothing to say about stays as written, unless
        // the format is being upgraded. Recomputing it would compare what
        // `redact` left behind — an identifier masked on both sides reads as
        // unchanged — and drop evidence without counting it.
        if !upgrading && untouched(policy, &change) {
            kept.push(change);
            continue;
        }
        let before = admit_owned(policy, change.before, &mut report);
        let after = admit_owned(policy, change.after, &mut report);
        let rebuilt = match (before, after) {
            (None, None) => None,
            (None, Some(record)) => Some(RegistryChange {
                key: record.key.clone(),
                view: record.view.clone(),
                kind: ChangeKind::Added,
                before: None,
                after: Some(record),
                fields: Vec::new(),
            }),
            (Some(record), None) => Some(RegistryChange {
                key: record.key.clone(),
                view: record.view.clone(),
                kind: ChangeKind::Removed,
                before: Some(record),
                after: None,
                fields: Vec::new(),
            }),
            (Some(old), Some(new)) => modification(&old, &new),
        };
        kept.extend(rebuilt);
    }
    diff.registry = kept;
    diff.format_version = DIFF_FORMAT_VERSION;

    diff.refiltered.absorb(report);
    report
}

/// Whether the policy keeps both sides of a registry change exactly as written.
fn untouched(policy: &Policy, change: &RegistryChange) -> bool {
    [&change.before, &change.after]
        .into_iter()
        .flatten()
        .all(|record| matches!(policy.admit(record).record, Some(Cow::Borrowed(_))))
}

/// One side of a registry change, as the policy allows it.
fn admit_owned(
    policy: &Policy,
    record: Option<RegistryRecord>,
    report: &mut Refiltered,
) -> Option<RegistryRecord> {
    let record = record?;
    let admitted = policy.admit(&record);
    report.registry_values += admitted.refused_values;
    let replacement = match admitted.record {
        None => {
            report.registry_records += 1;
            return None;
        }
        Some(Cow::Borrowed(_)) => None,
        Some(Cow::Owned(owned)) => Some(owned),
    };
    Some(replacement.unwrap_or(record))
}

/// Remove file changes, kept or suppressed, whose path is excluded, and recount
/// the signers from what is left. Returns the records the dropped changes held.
fn drop_excluded_files(diff: &mut Diff) -> usize {
    let mut dropped = 0;
    let mut keep = |change: &FileChange| {
        let excluded = filesystem::is_excluded(Path::new(&change.path));
        if excluded {
            dropped += usize::from(change.before.is_some()) + usize::from(change.after.is_some());
        }
        !excluded
    };
    diff.files.retain(&mut keep);
    diff.suppressed_files.retain(|entry| keep(&entry.change));
    if dropped > 0 {
        diff.signers = signer_counts(&diff.files);
    }
    dropped
}

/// Signer common names among file changes, with counts.
pub(crate) fn signer_counts(files: &[FileChange]) -> BTreeMap<String, usize> {
    let mut signers = BTreeMap::new();
    for change in files {
        if let Some(signer) = &change.signer {
            *signers.entry(signer.clone()).or_insert(0) += 1;
        }
    }
    signers
}

/// Remove `access_denied` items that name an excluded registry key or path.
///
/// The item itself can be the identity: the Microsoft account cache names its
/// keys after the account's e-mail address, Windows Timeline names its folder
/// after the account's identifier, and an item that could not be read is
/// recorded by its full path.
fn drop_excluded_denials(coverage: &mut Coverage) -> usize {
    let before = coverage.access_denied.len();
    coverage.access_denied.retain(|item| match item.domain {
        Domain::Registry => !crate::policy::excludes_denied_item(&item.item),
        Domain::Filesystem => !filesystem::is_excluded(Path::new(&item.item)),
        _ => true,
    });
    before - coverage.access_denied.len()
}

/// Directories that hold no file now and held one before.
///
/// `None` unless both snapshots walked the filesystem *and* both recorded
/// directories. Comparing a snapshot that recorded them against one that did
/// not would report every empty directory on the machine as freshly emptied —
/// the same class of artefact `filesystem_policy_changed` exists to catch, and
/// just as convincing to a reader who does not know to look. A directory the
/// current exclusions cover is dropped and counted, as a file would be.
fn emptied_directories(
    before: &Snapshot,
    after: &Snapshot,
    coverage: &Coverage,
    refiltered: &mut Refiltered,
) -> Option<Vec<String>> {
    if !coverage.covers(crate::model::Domain::Filesystem) {
        return None;
    }
    let was: BTreeSet<&String> = before.file_empty_directories.as_ref()?.iter().collect();
    let (excluded, kept): (Vec<&String>, Vec<&String>) = after
        .file_empty_directories
        .as_ref()?
        .iter()
        .filter(|directory| !was.contains(directory))
        .partition(|directory| filesystem::is_excluded(Path::new(directory)));
    refiltered.emptied_directories += excluded.len();
    Some(kept.into_iter().cloned().collect())
}

/// Registry keys that hold no value now and held one before, or did not exist.
///
/// `None` unless both snapshots walked the registry *and* both recorded empty
/// keys, for the reason [`emptied_directories`] gives. A key the current policy
/// excludes is dropped and counted, as a record would be.
fn emptied_keys(
    before: &Snapshot,
    after: &Snapshot,
    coverage: &Coverage,
    refiltered: &mut Refiltered,
) -> Option<Vec<RegistryKeyRef>> {
    if !coverage.covers(Domain::Registry) {
        return None;
    }
    let was: BTreeSet<&RegistryKeyRef> = before.registry_empty_keys.as_ref()?.iter().collect();
    let (excluded, kept): (Vec<&RegistryKeyRef>, Vec<&RegistryKeyRef>) = after
        .registry_empty_keys
        .as_ref()?
        .iter()
        .filter(|key| !was.contains(key))
        .partition(|key| is_excluded(&key.key));
    refiltered.emptied_keys += excluded.len();
    Some(kept.into_iter().cloned().collect())
}

/// How far two derived boot instants may differ and still be the same boot.
///
/// The instant is wall clock minus uptime and both halves drift: the tick count
/// against the system clock, and the system clock whenever it is adjusted.
/// Measured across two real captures seven minutes apart, the drift was **7
/// ms** — so the tolerance is not there for drift, it is there for a clock
/// step such as a time sync, which can move the derived instant by seconds or
/// minutes at once.
///
/// It cannot hide a restart, and that is provable rather than hopeful. If a
/// machine reboots between two snapshots, the boot instant moves forward by
/// exactly its uptime at the moment it rebooted — and it had to survive the
/// whole of the earlier capture, which takes minutes. So a genuine restart
/// always shows a difference larger than a snapshot's own duration, and the
/// tolerance sits an order of magnitude below that.
const SAME_BOOT_TOLERANCE_MS: u64 = 120_000;

/// Whether the machine restarted between two snapshots.
///
/// `None` means *not known* — one of the snapshots does not carry a boot
/// session. Callers must not collapse that into "no".
fn rebooted_between(before: &Snapshot, after: &Snapshot) -> Option<bool> {
    let earlier = before.boot_session.as_ref()?;
    let later = after.boot_session.as_ref()?;
    Some(earlier.started_unix_ms.abs_diff(later.started_unix_ms) > SAME_BOOT_TOLERANCE_MS)
}

/// Index registry records by key and view, keeping only what the policy allows.
fn admitted_index<'a>(
    records: &'a [RegistryRecord],
    policy: &Policy,
    refiltered: &mut Refiltered,
) -> BTreeMap<(String, String), Cow<'a, RegistryRecord>> {
    let mut index = BTreeMap::new();
    for record in records {
        let admitted = policy.admit(record);
        refiltered.registry_values += admitted.refused_values;
        match admitted.record {
            Some(record) => {
                index.insert(
                    (record.key.to_ascii_lowercase(), record.view.clone()),
                    record,
                );
            }
            None => refiltered.registry_records += 1,
        }
    }
    index
}

fn compare_registry(
    before: &[RegistryRecord],
    after: &[RegistryRecord],
    policy: &Policy,
    refiltered: &mut Refiltered,
) -> Vec<RegistryChange> {
    // Keyed by path *and* view: the same logical key read through the 32-bit
    // and 64-bit views is two artifacts, and collapsing them would report a
    // value present in one view and absent in the other as no change at all.
    let before_index = admitted_index(before, policy, refiltered);
    let after_index = admitted_index(after, policy, refiltered);
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
                    after: Some(record.as_ref().clone()),
                    fields: Vec::new(),
                }),
                (Some(record), None) => Some(RegistryChange {
                    key: record.key.clone(),
                    view: record.view.clone(),
                    kind: ChangeKind::Removed,
                    before: Some(record.as_ref().clone()),
                    after: None,
                    fields: Vec::new(),
                }),
                (Some(old), Some(new)) => modification(old, new),
                (None, None) => None,
            }
        })
        .collect()
}

/// A modification of one key, as a diff records it: the values that differ and
/// nothing else. `None` when nothing differs.
fn modification(old: &RegistryRecord, new: &RegistryRecord) -> Option<RegistryChange> {
    let (differing, fields) = value_differences(old, new);
    if fields.is_empty() {
        return None;
    }
    let only_differing = |record: &RegistryRecord| RegistryRecord {
        key: record.key.clone(),
        view: record.view.clone(),
        values: record
            .values
            .iter()
            .filter(|value| differing.contains(value.name.as_str()))
            .cloned()
            .collect(),
    };
    Some(RegistryChange {
        key: new.key.clone(),
        view: new.view.clone(),
        kind: ChangeKind::Modified,
        before: Some(only_differing(old)),
        after: Some(only_differing(new)),
        fields,
    })
}

/// The names of the values that differ between two records of one key, and a
/// field change for each.
fn value_differences<'a>(
    before: &'a RegistryRecord,
    after: &'a RegistryRecord,
) -> (BTreeSet<&'a str>, Vec<FieldChange>) {
    // What is compared is type and data, or type and size for a value too large
    // to record — see `RegistryValue::comparable`.
    let comparable = |record: &'a RegistryRecord| -> BTreeMap<&'a str, String> {
        record
            .values
            .iter()
            .map(|value| (value.name.as_str(), value.comparable()))
            .collect()
    };

    let old = comparable(before);
    let new = comparable(after);
    let names: BTreeSet<&str> = old.keys().chain(new.keys()).copied().collect();

    let mut differing = BTreeSet::new();
    let mut fields = Vec::new();
    for name in names {
        let was = old.get(name);
        let now = new.get(name);
        if was == now {
            continue;
        }
        differing.insert(name);
        fields.push(FieldChange {
            // Rendered as the value name so a reviewer sees which value moved,
            // not merely that the key did.
            field: if name.is_empty() {
                "(default)".to_owned()
            } else {
                name.to_owned()
            },
            before: was.cloned().unwrap_or_default(),
            after: now.cloned().unwrap_or_default(),
        });
    }
    (differing, fields)
}

fn compare_files<'a>(
    before: &'a [FileRecord],
    after: &'a [FileRecord],
    filter: &NoiseFilter,
    refiltered: &mut Refiltered,
) -> (Vec<FileChange>, Vec<SuppressedFile>) {
    // By reference. A real snapshot holds three quarters of a million file
    // records, and cloning both sides into the index doubled the memory the
    // comparison needed in order to copy the few that changed.
    //
    // And through this build's exclusions, which an older collector did not
    // apply: a directory now known to hold an account's identifier or its
    // activity history must not reach a diff because a snapshot predates the
    // rule.
    let mut index = |records: &'a [FileRecord]| -> BTreeMap<String, &'a FileRecord> {
        let mut indexed = BTreeMap::new();
        for record in records {
            if filesystem::is_excluded(Path::new(&record.path)) {
                refiltered.files += 1;
            } else {
                indexed.insert(record.path.to_ascii_lowercase(), record);
            }
        }
        indexed
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
                after: Some((*record).clone()),
                fields: Vec::new(),
            },
            (Some(record), None) => FileChange {
                path: record.path.clone(),
                kind: ChangeKind::Removed,
                signer: record.signer.clone(),
                is_driver_image: record.is_driver_image(),
                before: Some((*record).clone()),
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
                    before: Some((*old).clone()),
                    after: Some((*new).clone()),
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

fn compare_services<'a>(
    before: &'a [ServiceRecord],
    after: &'a [ServiceRecord],
    filter: &NoiseFilter,
) -> Vec<ServiceChange> {
    // A per-user instance is indexed under its template name only when that
    // name is unambiguous on *both* sides. With two users logged on, a snapshot
    // holds two instances of the same template, and collapsing both onto one
    // key kept whichever happened to be indexed last and dropped the other
    // without a trace — the one thing this module promises never to do.
    let crowded: BTreeSet<String> = [before, after]
        .into_iter()
        .flat_map(|records| {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for record in records {
                *counts
                    .entry(filter.canonical_name(&record.name))
                    .or_insert(0) += 1;
            }
            counts
                .into_iter()
                .filter(|(_, count)| *count > 1)
                .map(|(name, _)| name)
        })
        .collect();
    let key = |name: &str| -> String {
        let canonical = filter.canonical_name(name);
        if crowded.contains(&canonical) {
            name.to_owned()
        } else {
            canonical
        }
    };
    let index = |records: &'a [ServiceRecord]| -> BTreeMap<String, &'a ServiceRecord> {
        records
            .iter()
            .map(|record| (key(&record.name), record))
            .collect()
    };

    let before_index = index(before);
    let after_index = index(after);

    let names: BTreeSet<&String> = before_index.keys().chain(after_index.keys()).collect();

    names
        .into_iter()
        .filter_map(|name| {
            let old = before_index.get(name).copied();
            let new = after_index.get(name).copied();
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

/// A display name without the instance suffix its service name carries.
///
/// The service control manager reports a per-user instance's display name as
/// the instance name itself — `cbdhsvc_b1161` — so two instances of one
/// template, matched across a reboot, always differ in display name by exactly
/// the part that is supposed to be ignored.
fn without_instance_suffix<'a>(display_name: &'a str, service_name: &str) -> &'a str {
    service_name
        .rsplit_once('_')
        .and_then(|(_, suffix)| display_name.strip_suffix(suffix))
        .and_then(|rest| rest.strip_suffix('_'))
        .unwrap_or(display_name)
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

    // Two records with different names were matched as instances of one
    // per-user template, and their display names carry their own suffixes.
    let (old_display, new_display) = if before.name == after.name {
        (before.display_name.as_str(), after.display_name.as_str())
    } else {
        (
            without_instance_suffix(&before.display_name, &before.name),
            without_instance_suffix(&after.display_name, &after.name),
        )
    };
    compare("display_name", old_display, new_display);
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
            domain_started_utc: std::collections::BTreeMap::new(),
            boot_session: None,
            services,
            files: Vec::new(),
            filesystem_policy: None,
            file_empty_directories: None,
            registry: Vec::new(),
            registry_policy: None,
            registry_empty_keys: None,
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

    /// A diff in which each `(key, view)` pair appears as an added key.
    ///
    /// The view matters: `HKLM\SOFTWARE` is WOW64-redirected and
    /// `HKLM\SYSTEM` is not, so the same anti-cheat writes some keys into both
    /// views and some into one.
    pub(crate) fn diff_with_added_registry_keys(keys: &[(&str, &str)]) -> Diff {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        before.coverage.captured.push(Domain::Registry);
        after.coverage.captured.push(Domain::Registry);
        after.registry = keys
            .iter()
            .map(|(key, view)| crate::model::RegistryRecord {
                key: (*key).to_owned(),
                view: (*view).to_owned(),
                values: Vec::new(),
            })
            .collect();
        compare(&before, &after, &NoiseFilter::permissive()).expect("fixture diffs cleanly")
    }

    fn boot(started_unix_ms: u64) -> crate::model::BootSession {
        crate::model::BootSession {
            started_utc: crate::clock::from_unix_millis(u128::from(started_unix_ms)),
            started_unix_ms,
            uptime_ms: 0,
        }
    }

    #[test]
    fn an_unknown_restart_is_not_reported_as_no_restart() {
        let before = snapshot(vec![]);
        let after = snapshot(vec![]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        // The distinction the whole field exists for. A snapshot taken before
        // `boot_session` existed cannot say the machine stayed up, and a reader
        // who takes `None` for `false` will attribute a reboot's churn to
        // whatever the observation was about.
        assert_eq!(diff.rebooted_between, None);
    }

    #[test]
    fn a_restart_between_snapshots_is_reported() {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        before.boot_session = Some(boot(1_787_126_327_000));
        after.boot_session = Some(boot(1_787_145_469_000));

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.rebooted_between, Some(true));
    }

    #[test]
    fn a_derived_boot_instant_drifting_by_a_second_is_still_the_same_boot() {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        before.boot_session = Some(boot(1_787_126_327_000));
        // Wall clock minus uptime, computed twice, never lands on the same
        // millisecond. Equality would report a reboot on every diff.
        after.boot_session = Some(boot(1_787_126_328_000));

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.rebooted_between, Some(false));
    }

    #[test]
    fn a_directory_left_standing_with_nothing_in_it_is_reported() {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        for side in [&mut before, &mut after] {
            side.coverage.captured.push(Domain::Filesystem);
        }
        // Present in both, so it was already empty and is not news.
        before.file_empty_directories = Some(vec![r"C:\ProgramData\Packages".to_owned()]);
        // Held files before, holds none now, still exists.
        after.file_empty_directories = Some(vec![
            r"C:\ProgramData\Packages".to_owned(),
            r"C:\Program Files\Riot Vanguard".to_owned(),
        ]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(
            diff.emptied_directories,
            Some(vec![r"C:\Program Files\Riot Vanguard".to_owned()])
        );
    }

    #[test]
    fn an_emptied_directory_is_not_reported_when_the_filesystem_was_not_walked() {
        let before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        after.file_empty_directories = Some(vec![r"C:\Program Files\Riot Vanguard".to_owned()]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        // Neither side captured the filesystem, so the difference is an
        // artefact of what was collected rather than of the machine — the same
        // rule the file list answers to.
        assert_eq!(diff.emptied_directories, None);
    }

    #[test]
    fn an_older_snapshot_without_directories_makes_the_answer_unknown_not_empty() {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        for side in [&mut before, &mut after] {
            side.coverage.captured.push(Domain::Filesystem);
        }
        // The earlier snapshot predates directory recording, so every empty
        // directory on the machine is new to the later one and none of them is
        // news. Reporting them would be inventing residue.
        after.file_empty_directories = Some(vec![r"C:\ProgramData\Packages".to_owned()]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.emptied_directories, None);
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

    fn instance(name: &str) -> ServiceRecord {
        // As the service control manager reports one: the display name is the
        // instance name, and every instance shares the template's image.
        let mut record = service(name);
        record.binary_path = r"C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p".to_owned();
        record
    }

    #[test]
    fn a_reboot_does_not_turn_a_per_user_instance_into_a_change() {
        let before = snapshot(vec![instance("cbdhsvc_5a1f2")]);
        let after = snapshot(vec![instance("cbdhsvc_9c3e7")]);

        let diff = compare(&before, &after, &NoiseFilter::standard()).unwrap();

        assert!(diff.services.is_empty(), "{:?}", diff.services);
    }

    #[test]
    fn two_instances_of_one_template_are_never_merged() {
        // Two users logged on: two instances of the same template in one
        // snapshot. Collapsing both onto the template name used to keep one and
        // drop the other silently.
        let before = snapshot(vec![instance("cbdhsvc_5a1f2")]);
        let after = snapshot(vec![instance("cbdhsvc_5a1f2"), instance("cbdhsvc_9c3e7")]);

        let diff = compare(&before, &after, &NoiseFilter::standard()).unwrap();

        assert_eq!(diff.services.len(), 1, "{:?}", diff.services);
        assert_eq!(diff.services[0].kind, ChangeKind::Added);
        assert_eq!(diff.services[0].name, "cbdhsvc_9c3e7");
    }

    #[test]
    fn services_are_not_compared_unless_both_sides_captured_them() {
        let before = snapshot(vec![service("vgk"), service("spooler")]);
        let mut after = snapshot(vec![]);
        after.coverage.captured.clear();

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        // Not "two services removed": the later snapshot never looked.
        assert!(diff.services.is_empty());
        assert!(diff.coverage.not_captured.contains(&Domain::Services));
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

    fn record(key: &str, values: &[(&str, &str)]) -> RegistryRecord {
        RegistryRecord {
            key: key.to_owned(),
            view: "64".to_owned(),
            values: values
                .iter()
                .map(|(name, data)| crate::model::RegistryValue {
                    name: (*name).to_owned(),
                    kind: "sz".to_owned(),
                    data: (*data).to_owned(),
                    oversized_bytes: None,
                })
                .collect(),
        }
    }

    fn registry_snapshot(records: Vec<RegistryRecord>) -> Snapshot {
        let mut side = snapshot(vec![]);
        side.coverage.captured.push(Domain::Registry);
        side.registry = records;
        side
    }

    const ACCOUNT_KEY: &str =
        r"HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\someone@example.invalid";
    const TCPIP_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

    #[test]
    fn what_this_build_refuses_never_reaches_a_diff_of_older_snapshots() {
        // Both snapshots predate the policy, so both hold the account cache and
        // the host name — which is exactly how a committed diff came to carry
        // an e-mail address. Neither may reach the diff.
        let before = registry_snapshot(vec![
            record(ACCOUNT_KEY, &[("cid", "1")]),
            record(TCPIP_KEY, &[("Domain", "a"), ("Hostname", "host-before")]),
        ]);
        let mut after = registry_snapshot(vec![
            record(ACCOUNT_KEY, &[("cid", "2")]),
            record(TCPIP_KEY, &[("Domain", "b"), ("Hostname", "host-after")]),
            record(r"HKLM\SOFTWARE\Riot Vanguard", &[("Version", "1")]),
        ]);
        after
            .coverage
            .access_denied
            .push(crate::model::AccessDenied {
                domain: Domain::Registry,
                item: format!("{ACCOUNT_KEY} [view 64]"),
                reason: "RegOpenKeyExW returned 5".to_owned(),
            });

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        let text = serde_json::to_string(&diff).unwrap();
        for needle in ["someone@example.invalid", "host-before", "host-after"] {
            assert!(!text.contains(needle), "{needle} reached the diff: {text}");
        }
        // The footprint and the ordinary change both survive.
        assert_eq!(diff.registry.len(), 2, "{:?}", diff.registry);
        let tcpip = diff.registry.iter().find(|c| c.key == TCPIP_KEY).unwrap();
        assert_eq!(tcpip.fields.len(), 1);
        assert_eq!(tcpip.fields[0].field, "Domain");
        // And the removal is counted, never silent.
        assert_eq!(
            diff.refiltered,
            Refiltered {
                registry_records: 2,
                registry_values: 2,
                access_denied: 1,
                ..Refiltered::default()
            }
        );
    }

    #[test]
    fn refiltering_a_written_diff_drops_what_compare_now_refuses() {
        // A diff written by a build that had no policy: start from a clean one
        // and add what that build would have recorded.
        let mut diff = compare(
            &registry_snapshot(vec![]),
            &registry_snapshot(vec![record(
                r"HKLM\SOFTWARE\Riot Vanguard",
                &[("Version", "1")],
            )]),
            &NoiseFilter::permissive(),
        )
        .unwrap();
        // Records whole, as format 1 wrote a modification.
        let modified = |old: RegistryRecord, new: RegistryRecord| RegistryChange {
            key: new.key.clone(),
            view: new.view.clone(),
            kind: ChangeKind::Modified,
            fields: value_differences(&old, &new).1,
            before: Some(old),
            after: Some(new),
        };
        diff.registry.push(modified(
            record(ACCOUNT_KEY, &[("cid", "1")]),
            record(ACCOUNT_KEY, &[("cid", "2")]),
        ));
        // Only the host name moved: no change at all once it is refused.
        diff.registry.push(modified(
            record(TCPIP_KEY, &[("Domain", "a"), ("Hostname", "host-before")]),
            record(TCPIP_KEY, &[("Domain", "a"), ("Hostname", "host-after")]),
        ));
        diff.coverage
            .access_denied
            .push(crate::model::AccessDenied {
                domain: Domain::Registry,
                item: format!("{ACCOUNT_KEY} :: cid [view 32]"),
                reason: "refused".to_owned(),
            });

        let report = refilter(&mut diff, &Policy::current());

        let text = serde_json::to_string(&diff).unwrap();
        for needle in ["someone@example.invalid", "host-before", "host-after"] {
            assert!(!text.contains(needle), "{needle} survived: {text}");
        }
        assert_eq!(diff.registry.len(), 1);
        assert_eq!(diff.registry[0].key, r"HKLM\SOFTWARE\Riot Vanguard");
        assert_eq!(
            report,
            Refiltered {
                registry_records: 2,
                registry_values: 2,
                access_denied: 1,
                ..Refiltered::default()
            }
        );
        assert_eq!(
            diff.refiltered, report,
            "the diff records what was done to it"
        );

        // Running it again finds nothing more, so it is safe to repeat.
        assert!(refilter(&mut diff, &Policy::current()).is_empty());
    }

    /// A Steam account's own folder, named after the account's identifier.
    const STEAM_ACCOUNT_FILE: &str =
        r"C:\Program Files (x86)\Steam\userdata\7654321\config\localconfig.vdf";
    const TIMELINE_FOLDER: &str =
        r"C:\Users\x\AppData\Local\ConnectedDevicesPlatform\0123456789abcdef";
    const EA_LAUNCHER: &str = r"C:\Program Files\EA\AC\EAAntiCheat.GameServiceLauncher.exe";

    fn file_record(path: &str, size: u64) -> FileRecord {
        FileRecord {
            path: path.to_owned(),
            size,
            modified_utc: String::new(),
            sha256: None,
            signer: None,
            not_hashed: None,
        }
    }

    #[test]
    fn files_this_build_excludes_never_reach_a_diff_of_older_snapshots() {
        // Both snapshots predate the exclusions, so both walked the Steam
        // account's folder and Windows Timeline's, each named after an
        // account identifier. Neither may reach the diff.
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        for side in [&mut before, &mut after] {
            side.coverage.captured.push(Domain::Filesystem);
            side.file_empty_directories = Some(Vec::new());
        }
        before.files = vec![file_record(STEAM_ACCOUNT_FILE, 1)];
        after.files = vec![
            file_record(STEAM_ACCOUNT_FILE, 2),
            file_record(EA_LAUNCHER, 1),
        ];
        after.file_empty_directories = Some(vec![
            r"C:\Program Files (x86)\Steam\userdata\7654321\760".to_owned(),
            r"C:\Program Files\EA\AC\Logs".to_owned(),
        ]);
        after
            .coverage
            .access_denied
            .push(crate::model::AccessDenied {
                domain: Domain::Filesystem,
                item: TIMELINE_FOLDER.to_owned(),
                reason: "Access is denied. (os error 5)".to_owned(),
            });

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        let text = serde_json::to_string(&diff).unwrap();
        for needle in ["7654321", "0123456789abcdef"] {
            assert!(!text.contains(needle), "{needle} reached the diff: {text}");
        }
        // The footprint survives.
        assert_eq!(diff.files.len(), 1);
        assert_eq!(diff.files[0].path, EA_LAUNCHER);
        assert_eq!(
            diff.emptied_directories,
            Some(vec![r"C:\Program Files\EA\AC\Logs".to_owned()])
        );
        // And the removal is counted: a record from each snapshot, the emptied
        // directory, the unreadable folder.
        assert_eq!(
            diff.refiltered,
            Refiltered {
                access_denied: 1,
                files: 2,
                emptied_directories: 1,
                ..Refiltered::default()
            }
        );
    }

    #[test]
    fn refiltering_a_written_diff_drops_excluded_files_and_recounts_signers() {
        let mut diff = diff_with_added_files(&[EA_LAUNCHER]);
        // What a build without the exclusions wrote: a kept change, a
        // suppressed one and an emptied directory inside the Steam account's
        // folder, and a signer counted for the kept one.
        let mut account = file_record(STEAM_ACCOUNT_FILE, 2);
        account.signer = Some("Valve Corp.".to_owned());
        diff.files.push(FileChange {
            path: STEAM_ACCOUNT_FILE.to_owned(),
            kind: ChangeKind::Modified,
            signer: account.signer.clone(),
            is_driver_image: false,
            before: Some(file_record(STEAM_ACCOUNT_FILE, 1)),
            after: Some(account),
            fields: Vec::new(),
        });
        diff.signers.insert("Valve Corp.".to_owned(), 1);
        diff.suppressed_files.push(SuppressedFile {
            rule: "test".to_owned(),
            change: FileChange {
                path: format!("{TIMELINE_FOLDER}\\ActivitiesCache.db"),
                kind: ChangeKind::Added,
                signer: None,
                is_driver_image: false,
                before: None,
                after: Some(file_record(
                    &format!("{TIMELINE_FOLDER}\\ActivitiesCache.db"),
                    1,
                )),
                fields: Vec::new(),
            },
        });
        diff.emptied_directories = Some(vec![
            r"C:\Program Files (x86)\Steam\userdata\7654321\760".to_owned(),
        ]);

        let report = refilter(&mut diff, &Policy::current());

        let text = serde_json::to_string(&diff).unwrap();
        for needle in ["7654321", "0123456789abcdef", "Valve Corp."] {
            assert!(!text.contains(needle), "{needle} survived: {text}");
        }
        assert_eq!(diff.files.len(), 1);
        assert!(diff.suppressed_files.is_empty());
        assert_eq!(diff.emptied_directories, Some(Vec::new()));
        assert_eq!(
            report,
            Refiltered {
                files: 3,
                emptied_directories: 1,
                ..Refiltered::default()
            }
        );
        assert_eq!(diff.refiltered, report);
        assert!(refilter(&mut diff, &Policy::current()).is_empty());
    }

    #[test]
    fn refiltering_a_redacted_diff_keeps_a_masked_identifier_change() {
        // `redact` masks an identifier on both sides of a change, so the two
        // sides read the same afterwards. The change still happened, and a
        // refilter with nothing to remove must leave the diff as it found it.
        const KEY: &str = r"HKCU\SOFTWARE\EA\AC";
        let mut diff = compare(
            &registry_snapshot(vec![record(KEY, &[("LastSessionId", "a1"), ("Mode", "1")])]),
            &registry_snapshot(vec![record(KEY, &[("LastSessionId", "b2"), ("Mode", "2")])]),
            &NoiseFilter::permissive(),
        )
        .unwrap();
        let mut document = serde_json::to_value(&diff).unwrap();
        crate::redact::redact_document(&mut document, &crate::redact::Extra::default());
        diff = serde_json::from_value(document).unwrap();
        let redacted = serde_json::to_string(&diff).unwrap();
        assert!(redacted.contains("sz:%ID%"), "{redacted}");

        let report = refilter(&mut diff, &Policy::current());

        assert!(report.is_empty(), "{report:?}");
        assert_eq!(serde_json::to_string(&diff).unwrap(), redacted);
        assert_eq!(diff.registry[0].fields.len(), 2);
    }

    #[test]
    fn a_count_this_build_added_is_not_written_when_nothing_was_counted() {
        // So a diff that dropped no file still reads in an older build, which
        // refuses fields it does not know.
        let counts = Refiltered {
            registry_records: 1,
            ..Refiltered::default()
        };
        let text = serde_json::to_string(&counts).unwrap();
        assert!(!text.contains("files"), "{text}");
        assert!(!text.contains("emptied_directories"), "{text}");
        let read: Refiltered = serde_json::from_str(&text).unwrap();
        assert_eq!(read, counts);
    }

    #[test]
    fn a_diff_read_the_other_way_round_turns_removals_into_additions() {
        let installed = snapshot(vec![service("ACE-BASE")]);
        let uninstalled = snapshot(vec![]);

        let removal = compare(&installed, &uninstalled, &NoiseFilter::permissive()).unwrap();
        let read_back = reversed(&removal);

        assert_eq!(removal.services[0].kind, ChangeKind::Removed);
        assert_eq!(read_back.services[0].kind, ChangeKind::Added);
        assert!(read_back.services[0].before.is_none());
        assert_eq!(read_back.before_taken_utc, removal.after_taken_utc);
        // And back again, to the letter.
        assert_eq!(
            serde_json::to_value(reversed(&read_back)).unwrap(),
            serde_json::to_value(&removal).unwrap()
        );
    }

    #[test]
    fn reading_a_diff_backwards_does_not_invent_emptied_lists() {
        let mut before = snapshot(vec![]);
        let mut after = snapshot(vec![]);
        for side in [&mut before, &mut after] {
            side.coverage.captured.push(Domain::Filesystem);
            side.file_empty_directories = Some(Vec::new());
        }

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.emptied_directories, Some(Vec::new()));
        // Empty before and gone after is not what either snapshot recorded.
        assert_eq!(reversed(&diff).emptied_directories, None);
    }

    #[test]
    fn a_snapshot_from_the_future_is_refused_rather_than_misread() {
        let mut before = snapshot(vec![]);
        before.format_version = SNAPSHOT_FORMAT_VERSION + 1;
        let after = snapshot(vec![]);

        let error = compare(&before, &after, &NoiseFilter::permissive()).unwrap_err();

        assert!(matches!(error, DiffError::UnsupportedFormat { .. }));
    }

    #[test]
    fn snapshots_of_different_formats_are_never_compared() {
        // Format 2 relabels per-user service types and stops walking
        // WOW6432Node twice. Across the change every per-user service would
        // read as modified and every 32-bit key as removed.
        let mut before = snapshot(vec![]);
        before.format_version = 1;
        let after = snapshot(vec![]);

        let error = compare(&before, &after, &NoiseFilter::permissive()).unwrap_err();

        assert!(matches!(
            error,
            DiffError::MixedFormats {
                before: 1,
                after: SNAPSHOT_FORMAT_VERSION
            }
        ));
    }

    #[test]
    fn two_older_snapshots_still_compare_and_say_what_they_were() {
        let mut before = registry_snapshot(vec![]);
        let mut after = registry_snapshot(vec![]);
        before.format_version = 1;
        after.format_version = 1;

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.format_version, DIFF_FORMAT_VERSION);
        assert_eq!(diff.snapshot_format_version, 1);
        // Format 1 recorded no empty keys, so the answer is unknown.
        assert_eq!(diff.emptied_keys, None);
    }

    fn key(path: &str) -> RegistryKeyRef {
        RegistryKeyRef {
            key: path.to_owned(),
            view: "64".to_owned(),
        }
    }

    #[test]
    fn a_key_left_standing_with_no_values_is_reported() {
        // The registry shape of the Vanguard directory residue: values gone,
        // keys left. Format 1 could not see it at all.
        let mut before = registry_snapshot(vec![]);
        let mut after = registry_snapshot(vec![]);
        before.registry_empty_keys = Some(vec![key(r"HKCU\SOFTWARE\Already Empty")]);
        after.registry_empty_keys = Some(vec![
            key(r"HKCU\SOFTWARE\Already Empty"),
            key(r"HKLM\SOFTWARE\Vendor\Product"),
        ]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(
            diff.emptied_keys,
            Some(vec![key(r"HKLM\SOFTWARE\Vendor\Product")])
        );
    }

    #[test]
    fn emptied_keys_are_unknown_unless_both_sides_recorded_them() {
        let before = registry_snapshot(vec![]);
        let mut after = registry_snapshot(vec![]);
        after.registry_empty_keys = Some(vec![key(r"HKLM\SOFTWARE\Vendor")]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        // Every empty key on the machine is new to a list that was never
        // made, and none of them is news.
        assert_eq!(diff.emptied_keys, None);
    }

    #[test]
    fn an_emptied_key_the_policy_excludes_is_dropped_and_counted() {
        let mut before = registry_snapshot(vec![]);
        let mut after = registry_snapshot(vec![]);
        before.registry_empty_keys = Some(Vec::new());
        // A key name can itself be the identity.
        after.registry_empty_keys = Some(vec![key(ACCOUNT_KEY)]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        assert_eq!(diff.emptied_keys, Some(Vec::new()));
        assert_eq!(diff.refiltered.emptied_keys, 1);
    }

    #[test]
    fn a_modification_carries_only_the_values_that_changed() {
        let before = registry_snapshot(vec![record(
            TCPIP_KEY,
            &[
                ("Domain", "a"),
                ("SearchList", "x"),
                ("UseDomainNameDevolution", "1"),
            ],
        )]);
        let after = registry_snapshot(vec![record(
            TCPIP_KEY,
            &[
                ("Domain", "b"),
                ("SearchList", "x"),
                ("UseDomainNameDevolution", "1"),
            ],
        )]);

        let diff = compare(&before, &after, &NoiseFilter::permissive()).unwrap();

        let change = &diff.registry[0];
        assert_eq!(change.kind, ChangeKind::Modified);
        for side in [&change.before, &change.after] {
            let names: Vec<&str> = side
                .as_ref()
                .unwrap()
                .values
                .iter()
                .map(|value| value.name.as_str())
                .collect();
            assert_eq!(names, ["Domain"]);
        }
    }

    #[test]
    fn a_value_too_large_to_record_is_compared_by_size() {
        let oversized = |bytes: u64| {
            let mut side = record(r"HKLM\SOFTWARE\Vendor", &[]);
            side.values.push(crate::model::RegistryValue {
                name: "Blob".to_owned(),
                kind: "binary".to_owned(),
                data: String::new(),
                oversized_bytes: Some(bytes),
            });
            side
        };

        let same = compare(
            &registry_snapshot(vec![oversized(5000)]),
            &registry_snapshot(vec![oversized(5000)]),
            &NoiseFilter::permissive(),
        )
        .unwrap();
        let grown = compare(
            &registry_snapshot(vec![oversized(5000)]),
            &registry_snapshot(vec![oversized(6000)]),
            &NoiseFilter::permissive(),
        )
        .unwrap();

        assert!(same.registry.is_empty());
        assert_eq!(grown.registry.len(), 1);
        assert_eq!(
            grown.registry[0].fields[0].after,
            "binary:<6000 bytes, not recorded>"
        );
    }

    #[test]
    fn refiltering_an_older_diff_trims_it_to_the_current_format() {
        let old = record(TCPIP_KEY, &[("Domain", "a"), ("SearchList", "x")]);
        let new = record(TCPIP_KEY, &[("Domain", "b"), ("SearchList", "x")]);
        let mut diff = compare(
            &registry_snapshot(vec![]),
            &registry_snapshot(vec![]),
            &NoiseFilter::permissive(),
        )
        .unwrap();
        diff.format_version = 1;
        diff.snapshot_format_version = 1;
        // As format 1 wrote it: both records whole.
        diff.registry.push(RegistryChange {
            key: TCPIP_KEY.to_owned(),
            view: "64".to_owned(),
            kind: ChangeKind::Modified,
            fields: value_differences(&old, &new).1,
            before: Some(old),
            after: Some(new),
        });

        let report = refilter(&mut diff, &Policy::current());

        // Trimming is not a privacy removal, and is not counted as one.
        assert!(report.is_empty());
        assert_eq!(diff.format_version, DIFF_FORMAT_VERSION);
        // What the snapshots recorded cannot be upgraded, and says so.
        assert_eq!(diff.snapshot_format_version, 1);
        assert_eq!(diff.registry[0].after.as_ref().unwrap().values.len(), 1);
    }

    #[test]
    fn a_diff_without_the_newer_fields_reads_as_format_one_snapshots() {
        let diff = compare(
            &registry_snapshot(vec![]),
            &registry_snapshot(vec![]),
            &NoiseFilter::permissive(),
        )
        .unwrap();
        let mut json = serde_json::to_value(&diff).unwrap();
        let object = json.as_object_mut().unwrap();
        object.remove("snapshot_format_version");
        object.insert("format_version".to_owned(), 1.into());

        let read: Diff = serde_json::from_value(json).unwrap();

        assert_eq!(read.snapshot_format_version, 1);
        assert_eq!(read.emptied_keys, None);
    }
}
