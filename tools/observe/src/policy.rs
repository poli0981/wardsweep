//! What the harness refuses to read, and refuses to keep.
//!
//! One module, because two places have to agree about it. The registry
//! collector uses it to decide what to walk and which values to drop. The
//! differ applies it again, to *both* snapshots, before comparing them — so a
//! snapshot taken by an older build, before a rule existed, cannot carry what
//! the rule now forbids into a diff that is about to be committed to a public
//! repository. `observe refilter` applies it to a diff that already exists.
//!
//! Pure logic, with no Win32 in it, so it is tested on Linux like the differ.
//!
//! # Three reasons to refuse
//!
//! **Safety Gate G3 — hardware identity.** `docs/02-SAFETY-GATE.md` forbids
//! reading machine identifiers, disk serials, MAC addresses, TPM state and
//! volume GUIDs "including for reporting". Refused by key, and by matching the
//! terms in `collect/g3-identity-terms.txt` against every value's name and data.
//!
//! **Personal identity.** Who the user is, and what the machine is called: a
//! Microsoft account's e-mail address and identifiers, the host name, the
//! registered owner. None of it is footprint an installer wrote, and the
//! committed Riot Vanguard diffs carried all of it until it was found by
//! reading them — `redact` had nothing that recognised an e-mail address, and
//! the account name sat in a key name glued to digits.
//!
//! **Activity history.** What the user ran, typed, opened and switched to:
//! Program Compatibility Assistant's store, `FeatureUsage`, `UserAssist`,
//! `TypedPaths`, jump lists, background-activity timestamps. It churns between
//! any two snapshots, so it reaches every diff, and it is a record of somebody's
//! day rather than of an installer.
//!
//! The cost of the last is real and is accepted knowingly: an observation once
//! found the harness itself had left the anti-cheat's directory in Explorer's
//! `TypedPaths`, which is exactly the kind of artefact a name-matching residue
//! scanner would misattribute. That class of evidence is now out of view by
//! design, and `docs/16-OBSERVATION-HARNESS.md` says so.

use std::borrow::Cow;

use crate::model::RegistryRecord;

/// Safety Gate G3 terms, loaded as data rather than written as a constant.
///
/// See the file itself for why. In short: `core/tests/no_destructive_code.rs`
/// fails the build if any of these strings appears in a `.rs` file under a
/// shipped `src/`, and it cannot tell code that *reads* an identifier from a
/// deny-list that *refuses* one — so a list written in Rust would be rejected
/// by the very gate it enforces.
const G3_TERMS_FILE: &str = include_str!("collect/g3-identity-terms.txt");

/// The G3 terms, lower-cased, comments and blanks removed.
#[must_use]
pub fn hardware_identity_terms() -> Vec<String> {
    G3_TERMS_FILE
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Whether a value must be refused under Safety Gate G3.
///
/// Matched against the value **name and the rendered data**, not only against
/// the key it lives under. A real snapshot found the machine identifier copied
/// into three unrelated application keys, and a motherboard model inside a
/// telemetry URL — neither of which any key-path exclusion would have caught.
#[must_use]
pub fn is_hardware_identity(terms: &[String], name: &str, data: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let data = data.to_ascii_lowercase();

    if terms.iter().any(|term| name.contains(term.as_str())) {
        return true;
    }

    // A shell property list is a schema, not a value: `prop:System.ItemTypeText;
    // System.Devices.SerialNumber;…` names properties, it does not hold one.
    // Measured on a real machine, 184 of 243 refusals were these — three
    // quarters of the list, none of them an identifier. Skipping the data check
    // for them is precise rather than a loosening: the *name* check still
    // applies, and a genuine identifier is never stored under a `prop:` list.
    if data.starts_with("prop:") {
        return false;
    }

    terms.iter().any(|term| data.contains(term.as_str()))
}

/// Value names whose data says who the machine or its user is.
///
/// Matched exactly, ignoring case. These names are common enough that a
/// substring rule would refuse half the registry, and specific enough that an
/// exact one refuses nothing else: the host name is what a committed diff
/// carried, twice per view, in `Services\Tcpip\Parameters`.
const PERSONAL_IDENTITY_VALUE_NAMES: &[&str] = &[
    "hostname",
    "nv hostname",
    "computername",
    "registeredowner",
    "registeredorganization",
    "useremail",
    // Steam's remembered sign-in name and the signed-in account's identifier,
    // kept beside its own settings in `HKCU\SOFTWARE\Valve\Steam`, and the
    // persona name some clients keep there too.
    "autologinuser",
    "activeuser",
    "lastgamenameused",
];

/// Whether a value's name marks it as personal identity.
#[must_use]
pub fn is_personal_identity_value(name: &str) -> bool {
    PERSONAL_IDENTITY_VALUE_NAMES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name.trim()))
}

/// Key path fragments that stop the walk, matched case-insensitively.
///
/// A fragment names a whole subtree, so nothing under it is read at all: a
/// value that is never read cannot be recorded by accident, and the fragment
/// never has to spell out the value it is protecting.
pub const EXCLUDED_FRAGMENTS: &[&str] = &[
    // --- Safety Gate G3: hardware identity -------------------------------
    // Machine identity. Excluded as a whole key so the individual value never
    // has to be named here.
    "\\microsoft\\cryptography\\",
    // PnP device instance data, which carries device and disk serials.
    "\\enum\\",
    // TPM state. The service's configuration is still captured through the
    // service control manager; its registry subtree is not walked.
    "\\services\\tpm\\",
    // Paired Bluetooth devices are keyed by their MAC addresses.
    "\\services\\bthport\\parameters\\",
    // Keyed by volume GUID.
    "\\explorer\\mountpoints2\\",
    // Network signatures record the default gateway's MAC address.
    "\\networklist\\signatures\\",
    // --- Personal identity -----------------------------------------------
    // The Microsoft account cache: the account's e-mail address as a key name,
    // and its account identifiers as values.
    "\\microsoft\\identitycrl\\",
    // OneDrive keeps the host, domain and account names it has seen.
    "\\microsoft\\onedrive\\",
    // The user's full name and initials.
    "\\microsoft\\office\\common\\userinfo\\",
    // Names of every network the machine has joined.
    "\\networklist\\profiles\\",
    // Windows' cache of the identities signed in to the machine, keyed by
    // their security identifiers.
    "\\microsoft\\identitystore\\",
    // --- Activity history --------------------------------------------------
    // Every program run, keyed by its path.
    "\\appcompatflags\\compatibility assistant\\",
    "\\explorer\\featureusage\\",
    "\\explorer\\userassist\\",
    // What was typed into Explorer's address bar, the Run box and its search.
    "\\explorer\\typedpaths\\",
    "\\explorer\\runmru\\",
    "\\explorer\\wordwheelquery\\",
    // Recently opened documents and the folders of file dialogs.
    "\\explorer\\recentdocs\\",
    "\\explorer\\comdlg32\\",
    // Which application windows were open.
    "\\explorer\\sessioninfo\\",
    "\\search\\jumplistdata\\",
    // Folder view history, and the display name of every program run.
    "\\shell\\bagmru\\",
    "\\shell\\bags\\",
    "\\shell\\muicache\\",
    // Background activity moderator: last-run time of every executable.
    "\\services\\bam\\state\\",
    "\\services\\dam\\state\\",
    // Which programs used the camera, microphone, location or screen capture,
    // and when.
    "\\capabilityaccessmanager\\consentstore\\",
    // How often each application raised a notification and when it last did;
    // the last program to run full screen; the last program to open a game
    // controller, and when.
    "\\currentversion\\notifications\\settings\\",
    "\\notifications\\quiethours\\",
    "\\directinput\\mostrecentapplication\\",
    // Windows Backup's lists of installed applications and pinned tiles, a
    // Steam game's launch link among them.
    "\\currentversion\\applistbackup\\",
    // Start's rotating record of recently added shortcuts and the command
    // lines they launch: a slot the observed install takes still names the
    // program that held it before. Its machine-wide twin, `UFH\ARP`, names
    // uninstall keys and is footprint: an uninstaller removes its own entry.
    "\\currentversion\\ufh\\shc\\",
    // Display strings resolved for the programs and items Explorer showed.
    "\\local settings\\muicache\\",
    // The files and folders each Store application keeps lasting access to,
    // as shell links that carry their full paths — the account name among
    // them, in bytes no text rule reads.
    "\\persistedstorageitemtable\\",
    // Host Activity Manager: how long each application was in use, kept per
    // package under AppModel\SystemAppData\<package>\HAM and as a commit history.
    "\\ham\\",
    "\\hostactivitymanager\\",
    // The settings and start-menu sync store: which applications, and which
    // Steam games by their app ids, the account has used.
    "\\currentversion\\cloudstore\\",
    // Telemetry state: upload times and heartbeat counters, and Visual
    // Studio's per-machine telemetry identifiers.
    "\\diagnostics\\diagtrack\\",
    "\\visualstudio\\telemetry\\",
    // Steam's state for each application in the signed-in account's library —
    // installed, running, updating — which lists the library. Named from its
    // hive: the machine-wide key of the same shape is footprint, Steam's record
    // of which install-script steps a game has run, and an anti-cheat
    // installer is one of those steps.
    "\\hkcu\\software\\valve\\steam\\apps\\",
    // --- Credentials ---------------------------------------------------------
    // Microsoft account authentication cookies.
    "\\microsoft\\authcookies\\",
    // The keyed hashes a Chromium browser keeps over its own preferences.
    "\\preferencemacs\\",
    // Windows licensing state, which keeps the product key in plain text. On
    // a machine activated by digital licence that is the edition's published
    // generic key; on one activated by a retail or OEM key, it is the key.
    "\\currentversion\\softwareprotectionplatform\\",
    // --- Volume without information ----------------------------------------
    // Component servicing manifests and the installer database are enormous
    // and describe Windows, not an install.
    "\\microsoft\\windows\\currentversion\\component based servicing\\",
    "\\classes\\clsid\\",
    "\\classes\\interface\\",
    "\\classes\\typelib\\",
    "\\classes\\wow6432node\\clsid\\",
    "\\classes\\wow6432node\\interface\\",
    "\\installer\\",
];

/// Whether a key path falls inside an excluded fragment.
#[must_use]
pub fn is_excluded(key: &str) -> bool {
    // A separator at each end, so a fragment can name a subtree from its hive
    // as well as from anywhere below it.
    let lowered = format!("\\{}\\", key.to_ascii_lowercase());
    EXCLUDED_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

/// Why a value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Safety Gate G3.
    HardwareIdentity,
    /// Who the user is, or what the machine is called.
    PersonalIdentity,
}

/// The policy this build applies, with its term list loaded once.
#[derive(Debug, Clone)]
pub struct Policy {
    terms: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::current()
    }
}

impl Policy {
    /// The policy compiled into this build.
    #[must_use]
    pub fn current() -> Self {
        Self {
            terms: hardware_identity_terms(),
        }
    }

    /// Whether a value must be dropped, and why.
    #[must_use]
    pub fn refusal(&self, name: &str, data: &str) -> Option<Refusal> {
        if is_hardware_identity(&self.terms, name, data) {
            Some(Refusal::HardwareIdentity)
        } else if is_personal_identity_value(name) {
            Some(Refusal::PersonalIdentity)
        } else {
            None
        }
    }

    /// A registry record as this policy would have captured it.
    ///
    /// `None` when the key is excluded, or when every value it held is refused:
    /// the collector never records a key with no values, so a record emptied
    /// here becomes what the collector would have produced. Borrowed when
    /// nothing had to change, which on a real snapshot is almost every record.
    #[must_use]
    pub fn admit<'a>(&self, record: &'a RegistryRecord) -> Admitted<'a> {
        const DROPPED: Admitted<'static> = Admitted {
            record: None,
            refused_values: 0,
        };

        if is_excluded(&record.key) {
            return DROPPED;
        }

        let refused_values = record
            .values
            .iter()
            .filter(|value| self.refusal(&value.name, &value.data).is_some())
            .count();
        if refused_values == 0 {
            return Admitted {
                record: Some(Cow::Borrowed(record)),
                refused_values,
            };
        }

        let values: Vec<_> = record
            .values
            .iter()
            .filter(|value| self.refusal(&value.name, &value.data).is_none())
            .cloned()
            .collect();
        if values.is_empty() {
            return DROPPED;
        }
        Admitted {
            record: Some(Cow::Owned(RegistryRecord {
                key: record.key.clone(),
                view: record.view.clone(),
                values,
            })),
            refused_values,
        }
    }
}

/// Whether an `access_denied` item names an excluded key.
///
/// Registry items are recorded as `KEY [view N]` or `KEY :: VALUE [view N]`.
/// The key part is what matters: an excluded key's *name* can itself be the
/// identity — the Microsoft account cache names its keys after the account's
/// e-mail address.
#[must_use]
pub fn excludes_denied_item(item: &str) -> bool {
    let without_view = item.rsplit_once(" [view ").map_or(item, |(key, _)| key);
    let key = without_view
        .split_once(" :: ")
        .map_or(without_view, |(key, _)| key);
    is_excluded(key)
}

/// What [`Policy::admit`] made of one record.
#[derive(Debug)]
pub struct Admitted<'a> {
    /// The record as the policy allows it, if anything of it is allowed.
    pub record: Option<Cow<'a, RegistryRecord>>,
    /// Values dropped from a record that was kept. A record dropped whole
    /// counts as one record, not as its values.
    pub refused_values: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RegistryValue;

    fn record(key: &str, values: &[(&str, &str)]) -> RegistryRecord {
        RegistryRecord {
            key: key.to_owned(),
            view: "64".to_owned(),
            values: values
                .iter()
                .map(|(name, data)| RegistryValue {
                    name: (*name).to_owned(),
                    kind: "sz".to_owned(),
                    data: (*data).to_owned(),
                    oversized_bytes: None,
                })
                .collect(),
        }
    }

    #[test]
    fn the_cryptography_key_is_excluded_because_g3_forbids_reading_it() {
        // Safety Gate G3 names the machine identifier under this key first.
        // Excluding the parent means the walk never reaches it, and means this
        // file never has to name the value.
        assert!(is_excluded("HKLM\\SOFTWARE\\Microsoft\\Cryptography"));
        assert!(is_excluded(
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults"
        ));
    }

    #[test]
    fn device_enumeration_keys_are_excluded() {
        // PnP instance data carries device and disk serials.
        assert!(is_excluded(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\disk\\Enum"
        ));
    }

    #[test]
    fn hardware_identity_subtrees_are_excluded() {
        for key in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices\\0a1b2c3d4e5f",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\{0000}",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\x",
        ] {
            assert!(is_excluded(key), "{key} must not be walked");
        }
        // The fragment is a whole component: a different service survives.
        assert!(!is_excluded(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPMVSC"
        ));
    }

    #[test]
    fn personal_identity_and_activity_history_are_excluded() {
        for key in [
            "HKCU\\SOFTWARE\\Microsoft\\IdentityCRL\\UserExtendedProperties\\someone@example.invalid",
            "HKLM\\SOFTWARE\\Microsoft\\IdentityCRL\\NegativeCache\\0000",
            "HKCU\\SOFTWARE\\Microsoft\\OneDrive",
            "HKCU\\SOFTWARE\\Microsoft\\OneDrive\\Accounts\\Personal",
            "HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo\\1",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-%REDACTED%",
            "HKCU\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\HAM",
            "HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HostActivityManager\\CommitHistory\\x",
            "HKCU\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            // Found in the 2026-10-09 EA AntiCheat install diff.
            "HKCU\\SOFTWARE\\Microsoft\\AuthCookies\\Live\\Default",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\DefaultAccount\\Cloud",
            "HKCU\\SOFTWARE\\Chromium\\PreferenceMACs\\Default",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\HeartBeats\\Default",
            "HKCU\\SOFTWARE\\Microsoft\\VisualStudio\\Telemetry\\PersistentPropertyBag",
            "HKCU\\SOFTWARE\\Valve\\Steam\\Apps\\1234",
            "HKLM\\SOFTWARE\\Microsoft\\IdentityStore\\Cache\\S-1-5-21-%REDACTED%\\IdentityCache",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged\\x",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Some.App",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\QuietHours",
            "HKCU\\SOFTWARE\\Microsoft\\DirectInput\\MostRecentApplication",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppListBackup\\ListOfTaskBackedUpTiles_1",
            "HKCU\\SOFTWARE\\Classes\\Local Settings\\MuiCache\\2ee\\52C64B7E",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC",
            "HKCU\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Some.App_x\\PersistedStorageItemTable\\System\\x",
        ] {
            assert!(is_excluded(key), "{key} must not be walked");
        }
    }

    #[test]
    fn an_anti_cheat_key_is_never_excluded() {
        // The failure that matters, again: a privacy or volume rule swallowing
        // the thing we came for.
        for key in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vgk",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AntiCheatExpert Protection",
            "HKLM\\SOFTWARE\\EasyAntiCheat",
            "HKLM\\SOFTWARE\\Riot Vanguard",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Valorant",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\appdatalow\\AntiCheatExpert\\{4324E6D9-BA90-499E-9B3A-A7DAB216C94E}",
            "HKLM\\SOFTWARE\\EA\\AC",
            "HKCU\\SOFTWARE\\EA\\AC",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EAAntiCheat",
            // Where Steam records that a game's install script ran EA's
            // anti-cheat installer, under both of the names the 32-bit view
            // goes by. Only the per-account state beside it is excluded.
            "HKLM\\SOFTWARE\\Valve\\Steam\\Apps\\3405690",
            "HKLM\\SOFTWARE\\WOW6432Node\\Valve\\Steam\\Apps\\3405690",
            "HKCU\\SOFTWARE\\Valve\\Steam",
            // A game's own controller settings are left behind when it goes,
            // beside the record of the last program to open a controller.
            "HKCU\\SOFTWARE\\Microsoft\\DirectInput\\FC26.EXE6A6AC0701B12BB70",
            // Windows' notification state data, not a per-application record.
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data",
            // Where an installer's uninstall key is recorded for Start, which
            // Vanguard's uninstaller removes along with its own key.
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UFH\\ARP",
        ] {
            assert!(!is_excluded(key), "{key} is footprint and must be walked");
        }
    }

    #[test]
    fn every_fragment_names_whole_components_in_lower_case() {
        // A fragment without its separators would match inside a longer name,
        // which is how a noise rule eats footprint; an upper-case one would
        // match nothing, because keys are lowered before comparison.
        for fragment in EXCLUDED_FRAGMENTS {
            assert!(
                fragment.starts_with('\\') && fragment.ends_with('\\'),
                "{fragment}"
            );
            assert_eq!(*fragment, fragment.to_ascii_lowercase(), "{fragment}");
        }
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_excluded("HKLM\\software\\MICROSOFT\\CRYPTOGRAPHY\\x"));
    }

    #[test]
    fn the_g3_term_list_loads_and_is_not_empty() {
        let terms = hardware_identity_terms();
        assert!(terms.len() >= 10, "the G3 list looks truncated: {terms:?}");
        assert!(terms.iter().all(|term| !term.starts_with('#')));
        assert!(terms.iter().all(|term| term == &term.to_ascii_lowercase()));
    }

    #[test]
    fn every_listed_term_is_refused_in_both_a_value_name_and_value_data() {
        // Driven from the list rather than from spelled-out examples, for two
        // reasons. It covers every term instead of the one someone thought to
        // write, and this file cannot name them: the G3 check in
        // core/tests/no_destructive_code.rs scans it, and cannot tell a
        // deny-list from a reader.
        let terms = hardware_identity_terms();
        for term in &terms {
            assert!(
                is_hardware_identity(&terms, term, ""),
                "a value named after {term} must be refused"
            );
            assert!(
                is_hardware_identity(&terms, "SomeName", term),
                "{term} appearing in value data must be refused"
            );
            // Real cases from a development machine: the identifier reached the
            // snapshot as a *suffixed* value name in one application key, and
            // buried mid-string in a telemetry URL in another. Substring
            // matching on both name and data is what catches those.
            assert!(is_hardware_identity(
                &terms,
                &format!("{term}Collection"),
                ""
            ));
            assert!(is_hardware_identity(
                &terms,
                "RequestUri",
                &format!("https://example.invalid/?a=1&{term}dm=X&b=2")
            ));
        }
    }

    #[test]
    fn a_shell_property_schema_is_not_mistaken_for_an_identifier() {
        // These name properties rather than holding one, and on a real machine
        // they were three quarters of every refusal.
        let terms = hardware_identity_terms();
        let schema = format!("prop:System.ItemTypeText;System.Devices.{}", terms[2]);
        assert!(!is_hardware_identity(&terms, "FullDetails", &schema));
        // But a value *named* after an identifier is still refused, whatever
        // its data looks like.
        assert!(is_hardware_identity(&terms, &terms[0], &schema));
    }

    #[test]
    fn ordinary_footprint_is_not_refused_as_identity() {
        let policy = Policy::current();
        for (name, data) in [
            ("ImagePath", "C:\\Program Files\\Riot Vanguard\\vgk.sys"),
            ("DisplayName", "Riot Vanguard"),
            ("Start", "3"),
            (
                "UninstallString",
                "\"C:\\Program Files\\Riot Vanguard\\uninstall.exe\"",
            ),
        ] {
            assert_eq!(policy.refusal(name, data), None, "{name}");
        }
    }

    #[test]
    fn personal_identity_values_are_refused_by_exact_name() {
        let policy = Policy::current();
        assert_eq!(
            policy.refusal("NV HostName", "x"),
            Some(Refusal::PersonalIdentity)
        );
        assert_eq!(
            policy.refusal("registeredOwner", "x"),
            Some(Refusal::PersonalIdentity)
        );
        for steam in ["AutoLoginUser", "ActiveUser", "LastGameNameUsed"] {
            assert_eq!(
                policy.refusal(steam, "x"),
                Some(Refusal::PersonalIdentity),
                "{steam}"
            );
        }
        // Exact, not substring: a value that merely mentions a host is footprint.
        assert_eq!(policy.refusal("HostNameResolutionTimeout", "5"), None);
    }

    #[test]
    fn admitting_a_record_drops_excluded_keys_and_refused_values() {
        let policy = Policy::current();

        let excluded = record("HKCU\\SOFTWARE\\Microsoft\\OneDrive", &[("Version", "1")]);
        let admitted = policy.admit(&excluded);
        assert!(admitted.record.is_none());
        assert_eq!(admitted.refused_values, 0, "a whole record counts once");

        let mixed = record(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            &[("Hostname", "x"), ("NV Hostname", "x"), ("Domain", "")],
        );
        let admitted = policy.admit(&mixed);
        let kept = admitted.record.expect("one value survives");
        assert_eq!(admitted.refused_values, 2);
        assert_eq!(kept.values.len(), 1);
        assert_eq!(kept.values[0].name, "Domain");

        // Nothing left means no record, which is what the collector would have
        // produced for a key with no values.
        let only_identity = record("HKLM\\SOFTWARE\\Example", &[("ComputerName", "x")]);
        assert!(policy.admit(&only_identity).record.is_none());

        // And an untouched record is borrowed rather than copied.
        let ordinary = record("HKLM\\SOFTWARE\\Riot Vanguard", &[("Version", "1")]);
        assert!(matches!(
            policy.admit(&ordinary).record,
            Some(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn a_denied_item_is_judged_by_its_key() {
        assert!(excludes_denied_item(
            "HKCU\\SOFTWARE\\Microsoft\\IdentityCRL\\UserExtendedProperties\\someone@example.invalid [view 64]"
        ));
        assert!(excludes_denied_item(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\State :: x [view 32]"
        ));
        assert!(!excludes_denied_item(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vgk [view 64]"
        ));
    }
}
