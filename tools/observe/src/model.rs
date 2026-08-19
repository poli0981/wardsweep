//! The snapshot data model.
//!
//! Mirrors `docs/16-OBSERVATION-HARNESS.md`. Pure logic: no Win32 here, so the
//! model, the differ and the redactor are all testable on Linux, which is where
//! the CI lint job builds this crate.
//!
//! # Why coverage is part of the file
//!
//! A snapshot that captured half the machine and did not say so is worse than
//! no snapshot at all: the diff against it looks complete, and every domain it
//! skipped reads as "nothing changed there". That is the same failure
//! `docs/03-ARCHITECTURE.md` guards against when it insists an unelevated scan
//! is marked `partial` — *never report "clean" from a scan that could not see
//! everything.*
//!
//! So [`Coverage`] is mandatory, it names what was **not** captured as well as
//! what was, and [`Diff`] carries the intersection forward. A catalog entry
//! derived from a diff can therefore be traced back to whether the evidence for
//! it was ever collected.

use serde::{Deserialize, Serialize};

/// Wire-format version of a snapshot file.
///
/// Bumped when the shape changes incompatibly. `diff` refuses a snapshot it
/// does not implement rather than silently misreading it.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// One of the capture domains in `docs/16-OBSERVATION-HARNESS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// Services and drivers, via the service control manager.
    Services,
    /// `HKLM\SOFTWARE` in both WOW64 views, the services key, `Run` keys,
    /// uninstall keys, and `HKCU\SOFTWARE`.
    Registry,
    /// Program files, program data, per-user application data, `System32\drivers`,
    /// and launcher libraries.
    Filesystem,
    /// Full XML export of every scheduled task.
    ScheduledTasks,
    /// Every firewall rule.
    Firewall,
    /// Event log sources registered under `EventLog\Application`.
    EventSources,
    /// Windows build, locale, and installed launchers.
    Environment,
}

impl Domain {
    /// Every domain `docs/16` specifies, in a stable order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::Services,
            Self::Registry,
            Self::Filesystem,
            Self::ScheduledTasks,
            Self::Firewall,
            Self::EventSources,
            Self::Environment,
        ]
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Services => "services",
            Self::Registry => "registry",
            Self::Filesystem => "filesystem",
            Self::ScheduledTasks => "scheduled_tasks",
            Self::Firewall => "firewall",
            Self::EventSources => "event_sources",
            Self::Environment => "environment",
        };
        f.write_str(name)
    }
}

/// What a snapshot did and did not manage to look at.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// Domains this snapshot captured.
    pub captured: Vec<Domain>,
    /// Domains it did not. Recorded explicitly so a diff cannot present their
    /// absence as "nothing changed".
    pub not_captured: Vec<Domain>,
    /// Individual items that were refused, with the reason. A snapshot taken
    /// without administrator rights will have entries here.
    pub access_denied: Vec<AccessDenied>,
}

impl Coverage {
    /// Whether a domain's evidence is present.
    #[must_use]
    pub fn covers(&self, domain: Domain) -> bool {
        self.captured.contains(&domain)
    }

    /// The domains both snapshots captured.
    ///
    /// A diff can only speak about these. Anything captured by one side and not
    /// the other would show every item as added or removed, which is an
    /// artefact of the collection rather than a change on the machine.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let captured: Vec<Domain> = self
            .captured
            .iter()
            .copied()
            .filter(|domain| other.covers(*domain))
            .collect();
        let not_captured = Domain::all()
            .into_iter()
            .filter(|domain| !captured.contains(domain))
            .collect();

        let mut access_denied = self.access_denied.clone();
        access_denied.extend(other.access_denied.iter().cloned());
        access_denied.sort_by(|a, b| a.item.cmp(&b.item));
        access_denied.dedup_by(|a, b| a.item == b.item);

        Self {
            captured,
            not_captured,
            access_denied,
        }
    }
}

/// Something the harness tried to read and could not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessDenied {
    /// Which domain the item belongs to.
    pub domain: Domain,
    /// What was refused — a service name, a key, a path.
    pub item: String,
    /// Why, in whatever terms the platform gave.
    pub reason: String,
}

/// A point-in-time record of the machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Wire-format version; see [`SNAPSHOT_FORMAT_VERSION`].
    pub format_version: u32,
    /// When the capture started, ISO-8601 UTC.
    ///
    /// **Not an instant.** See [`Snapshot::domain_started_utc`].
    pub taken_utc: String,
    /// When each domain's capture began, ISO-8601 UTC.
    ///
    /// A snapshot is not atomic: the services are enumerated, then the
    /// filesystem is walked for minutes, then the registry. A value that
    /// changes during the walk is captured inconsistently *across domains, in
    /// one file*.
    ///
    /// That is not hypothetical. A Vanguard baseline recorded
    /// `vgk start_type = system` in the services domain and `Start = 3`
    /// (demand) on the same service's registry key four minutes later, because
    /// the anti-cheat raised its own driver's start type while its client ran
    /// and lowered it again. Both readings were correct; the file implied they
    /// were simultaneous.
    ///
    /// Recording the skew does not remove it. It lets a reader see it.
    #[serde(default)]
    pub domain_started_utc: std::collections::BTreeMap<String, String>,
    /// Version of the harness that took it.
    pub harness_version: String,
    /// Free-text label, so a directory of snapshots is readable.
    #[serde(default)]
    pub label: String,
    /// What was and was not looked at.
    pub coverage: Coverage,
    /// Service and driver configuration, keyed by service name.
    #[serde(default)]
    pub services: Vec<ServiceRecord>,
    /// Files under the roots named by [`Snapshot::filesystem_policy`].
    #[serde(default)]
    pub files: Vec<FileRecord>,
    /// Registry keys under the roots named by [`Snapshot::registry_policy`].
    #[serde(default)]
    pub registry: Vec<RegistryRecord>,
    /// What the registry walk was told to do, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_policy: Option<RegistryPolicy>,
    /// What the filesystem walk was told to do, when it ran.
    ///
    /// Recorded for the same reason [`Coverage`] is: a file list means nothing
    /// without knowing which roots produced it, what was excluded, and which
    /// files were hashed. Two snapshots taken under different policies are not
    /// comparable, and only the file can say so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_policy: Option<FilesystemPolicy>,
}

/// What the filesystem walk covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Roots walked, already expanded from their environment variables.
    pub roots: Vec<String>,
    /// Path fragments that stopped the walk, case-insensitively.
    pub excluded: Vec<String>,
    /// Extensions whose contents were hashed. Everything else is recorded by
    /// path, size and timestamp only.
    pub hashed_extensions: Vec<String>,
    /// Files larger than this were not hashed, and say so individually.
    pub max_hash_bytes: u64,
}

/// What the registry walk covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPolicy {
    /// Roots walked, as `HIVE\Subkey`.
    pub roots: Vec<String>,
    /// WOW64 views read, as `"32"` and `"64"`.
    pub views: Vec<String>,
    /// Key path fragments that stopped the walk, case-insensitively.
    pub excluded: Vec<String>,
    /// Values larger than this were skipped rather than truncated.
    pub max_value_bytes: u64,
}

/// One registry key, in one WOW64 view, with the values it holds.
///
/// **No timestamp.** `docs/16-OBSERVATION-HARNESS.md` asks for
/// `LastWriteTime`-only changes with unchanged values to be ignored; not
/// reading it at all is the same answer arrived at earlier, and cannot be
/// forgotten by a later noise rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRecord {
    /// Full key path, as `HIVE\Sub\Key`.
    pub key: String,
    /// Which WOW64 view this was read through.
    ///
    /// `docs/05-DETECTION-ENGINE.md` treats the two views as distinct
    /// artifacts: the same logical key can hold different values in each, and a
    /// catalog entry has to say which one it meant.
    pub view: String,
    /// The values under this key, sorted by name.
    pub values: Vec<RegistryValue>,
}

/// One registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValue {
    /// Value name. Empty for the key's default value.
    pub name: String,
    /// `sz`, `dword`, `binary`, `multi_sz`, and so on.
    pub kind: String,
    /// Data rendered as text — hex for binary, semicolon-joined for
    /// `REG_MULTI_SZ` so ordering differences are visible.
    pub data: String,
}

/// One file, as the walk found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// Full path.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Last-modified time, ISO-8601 UTC. Empty when the platform would not say.
    #[serde(default)]
    pub modified_utc: String,
    /// SHA-256 of the contents, when the policy called for hashing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Authenticode signer common name, when the file carries an embedded
    /// signature.
    ///
    /// `docs/16-OBSERVATION-HARNESS.md` calls signer clustering "the single
    /// most useful signal": everything an installer dropped shares a publisher,
    /// which separates it from Windows Update noise without an ignore list.
    ///
    /// Absent means *no embedded signature was found*, which is not the same as
    /// unsigned — most Windows binaries are signed through a catalog file
    /// instead. Anti-cheat binaries are embedded-signed in practice, which is
    /// what makes this worth collecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Why the contents were not hashed, when they were not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_hashed: Option<String>,
}

impl FileRecord {
    /// Whether this file is a kernel driver by extension.
    #[must_use]
    pub fn is_driver_image(&self) -> bool {
        self.path.to_ascii_lowercase().ends_with(".sys")
    }
}

/// The configuration of one service or driver.
///
/// **Configuration, not state.** `docs/16` asks for `QueryServiceConfigW` and
/// `QueryServiceConfig2W`, and deliberately not the current running state:
/// whether a service happens to be running changes constantly and on an idle
/// machine accounts for most of what a naive differ would report. Capturing
/// only what an installer *wrote* removes that noise at the source rather than
/// filtering it out afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    /// Service key name — the identity, and the diff key.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// `SERVICE_KERNEL_DRIVER`, `SERVICE_WIN32_OWN_PROCESS`, and so on, as text.
    pub service_type: String,
    /// `boot`, `system`, `auto`, `demand` or `disabled`.
    pub start_type: String,
    /// `ignore`, `normal`, `severe` or `critical`.
    pub error_control: String,
    /// Image path exactly as the SCM holds it, before any expansion.
    pub binary_path: String,
    /// Load-ordering group, when the service names one.
    #[serde(default)]
    pub load_order_group: String,
    /// Account the service runs as.
    #[serde(default)]
    pub start_name: String,
    /// Services and groups this one depends on.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Description text, when one is registered.
    #[serde(default)]
    pub description: String,
    /// Whether an automatic-start service is delayed.
    #[serde(default)]
    pub delayed_auto_start: bool,
}

impl ServiceRecord {
    /// Whether this record describes a kernel or filesystem driver.
    ///
    /// `observe suggest` infers `kind = "kernel"` from this, per the inference
    /// table in `docs/16`.
    #[must_use]
    pub fn is_driver(&self) -> bool {
        self.service_type.contains("driver")
    }

    /// Whether this driver loads at boot, which `docs/16` maps to
    /// `risk = "critical"` and `docs/13` makes spike S1's whole subject.
    #[must_use]
    pub fn is_boot_start(&self) -> bool {
        self.start_type == "boot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(captured: &[Domain]) -> Coverage {
        Coverage {
            captured: captured.to_vec(),
            not_captured: Domain::all()
                .into_iter()
                .filter(|domain| !captured.contains(domain))
                .collect(),
            access_denied: Vec::new(),
        }
    }

    #[test]
    fn intersecting_coverage_keeps_only_what_both_sides_saw() {
        let before = coverage(&[Domain::Services, Domain::Registry]);
        let after = coverage(&[Domain::Services, Domain::Filesystem]);

        let both = before.intersect(&after);

        assert_eq!(both.captured, vec![Domain::Services]);
        assert!(both.not_captured.contains(&Domain::Registry));
        assert!(both.not_captured.contains(&Domain::Filesystem));
    }

    #[test]
    fn every_domain_is_accounted_for_after_intersecting() {
        let both = coverage(&[Domain::Services]).intersect(&coverage(&[Domain::Services]));
        assert_eq!(
            both.captured.len() + both.not_captured.len(),
            Domain::all().len()
        );
    }

    #[test]
    fn access_denied_entries_from_both_sides_survive_and_deduplicate() {
        let denied = AccessDenied {
            domain: Domain::Services,
            item: "vgk".to_owned(),
            reason: "access denied".to_owned(),
        };
        let mut before = coverage(&[Domain::Services]);
        let mut after = coverage(&[Domain::Services]);
        before.access_denied.push(denied.clone());
        after.access_denied.push(denied);

        let both = before.intersect(&after);

        // Losing these would let a diff claim a service is absent when it was
        // only unreadable.
        assert_eq!(both.access_denied.len(), 1);
    }

    #[test]
    fn a_kernel_driver_is_recognised_as_one() {
        let record = ServiceRecord {
            name: "example".to_owned(),
            display_name: "Example".to_owned(),
            service_type: "kernel_driver".to_owned(),
            start_type: "boot".to_owned(),
            error_control: "normal".to_owned(),
            binary_path: "\\??\\C:\\Windows\\System32\\drivers\\example.sys".to_owned(),
            load_order_group: String::new(),
            start_name: String::new(),
            dependencies: Vec::new(),
            description: String::new(),
            delayed_auto_start: false,
        };

        assert!(record.is_driver());
        assert!(record.is_boot_start());
    }
}
