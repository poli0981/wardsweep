//! Catalog data model, mirroring `docs/04-CATALOG-SCHEMA.md`.
//!
//! Every struct uses `deny_unknown_fields`. A misspelled key in a catalog must
//! be an error: silently ignoring `divers = [...]` would mean a driver never
//! gets found, and the user would be told their machine is clean.

use serde::{Deserialize, Serialize};

/// The only schema version this build implements.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// A parsed catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Wire-format version. The broker refuses a catalog it does not implement.
    pub schema_version: u32,
    /// Catalog data version, independent of the application version.
    pub catalog_version: String,
    /// Lowest application version this catalog expects.
    pub minimum_app_version: String,
    /// Anti-cheat definitions.
    #[serde(default)]
    pub anticheat: Vec<AntiCheat>,
    /// Game definitions.
    #[serde(default)]
    pub game: Vec<Game>,
    /// Launcher definitions.
    #[serde(default)]
    pub launcher: Vec<Launcher>,
}

/// Whether an anti-cheat runs in the kernel, in user mode, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Ships a driver, and therefore implies a reboot stage.
    Kernel,
    /// User-mode only.
    Usermode,
    /// Both a driver and user-mode components.
    Hybrid,
}

/// How much damage removing this wrongly would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Ordinary user-mode files.
    Low,
    /// User-mode services or shared directories.
    Medium,
    /// A driver that is not boot-start.
    High,
    /// A boot-start driver. Requires typed confirmation in the UI.
    Critical,
}

/// What a path or registry key holds, which drives its default tick state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Installed program files.
    Install,
    /// Persistent application data. Unticked pending review.
    Data,
    /// Configuration.
    Config,
    /// Service registration state.
    Service,
    /// Regenerable cache. Ticked by default.
    Cache,
    /// Logs. Ticked by default.
    Log,
    /// Save data. Never removed by default, always archived.
    Save,
}

/// Which WOW64 view of a registry key an entry refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum View {
    /// The 32-bit view, i.e. `WOW6432Node`.
    #[serde(rename = "32")]
    Bits32,
    /// The 64-bit view.
    #[serde(rename = "64")]
    Bits64,
    /// Both views. Almost always the right answer.
    #[serde(rename = "both")]
    Both,
}

/// A filesystem path with its classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathEntry {
    /// The path, possibly containing `%VAR%` placeholders.
    pub path: String,
    /// What lives there.
    pub class: Class,
}

/// A registry key with its view and classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    /// The key, e.g. `HKLM\SOFTWARE\EasyAntiCheat`.
    pub key: String,
    /// Which WOW64 view.
    pub view: View,
    /// What the key holds.
    pub class: Class,
}

/// How an anti-cheat's own uninstaller is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UninstallKind {
    /// An executable at `command`.
    Exe,
    /// An MSI product code in `command`.
    Msi,
    /// Nothing separate to call; removed with the game.
    None,
}

/// The vendor's own uninstall entry point, always attempted before manual removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialUninstall {
    /// Which invocation style applies.
    pub kind: UninstallKind,
    /// Executable path or MSI product code, depending on `kind`.
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments passed verbatim; never shell-interpreted.
    #[serde(default)]
    pub args: Vec<String>,
    /// How long to wait before treating the uninstaller as stuck.
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

/// Evidence supporting a `shared = false` claim.
///
/// `docs/16-OBSERVATION-HARNESS.md` requires `shared` to be confirmed against
/// at least two titles or left at `true`, and a wrong `shared = false` is the
/// G1 failure mode this project exists to prevent. The CI job
/// `wardsweep-catalog audit-shared --require-evidence` enforces that this is
/// present and substantiated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedEvidence {
    /// Titles observed to use, or not use, this anti-cheat. At least two.
    pub titles_observed: Vec<String>,
    /// Observation directory names the claim was derived from. At least one.
    pub observation_ids: Vec<String>,
    /// Anything the structured fields cannot capture.
    #[serde(default)]
    pub note: Option<String>,
}

/// An anti-cheat product and its footprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiCheat {
    /// Stable kebab-case identifier. Permanent; never renamed or reused.
    pub id: String,
    /// Human-readable name.
    pub display: String,
    /// Vendor name.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Kernel, user-mode, or hybrid.
    pub kind: Kind,
    /// Whether multiple titles may share this anti-cheat. Defaults to `true`
    /// when unknown; `false` requires [`SharedEvidence`].
    pub shared: bool,
    /// Evidence for a `shared = false` claim.
    #[serde(default)]
    pub shared_evidence: Option<SharedEvidence>,
    /// Consequence of removing this wrongly.
    pub risk: Risk,
    /// Authenticode common names that confirm identity.
    #[serde(default)]
    pub authenticode_cn: Vec<String>,
    /// Optional SHA-256 pins for known builds, lowercase hex.
    #[serde(default)]
    pub file_hashes: Vec<String>,
    /// Service names.
    #[serde(default)]
    pub services: Vec<String>,
    /// Driver filenames, base name only.
    #[serde(default)]
    pub drivers: Vec<String>,
    /// Filesystem footprint.
    #[serde(default)]
    pub paths: Vec<PathEntry>,
    /// Registry footprint.
    #[serde(default)]
    pub registry: Vec<RegistryEntry>,
    /// Scheduled task paths.
    #[serde(default)]
    pub tasks: Vec<String>,
    /// Firewall rule name patterns.
    #[serde(default)]
    pub firewall_rules: Vec<String>,
    /// Event log source names.
    #[serde(default)]
    pub event_sources: Vec<String>,
    /// The vendor's own uninstaller.
    #[serde(default)]
    pub official_uninstall: Option<OfficialUninstall>,
}

/// A game and the anti-cheat it references.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Game {
    /// Stable kebab-case identifier.
    pub id: String,
    /// Human-readable name.
    pub display: String,
    /// Publisher name.
    #[serde(default)]
    pub publisher: Option<String>,
    /// Anti-cheat ids this game references. Ordering is irrelevant.
    #[serde(default)]
    pub anticheat: Vec<String>,
    /// Launcher ids this game ships on.
    #[serde(default)]
    pub platforms: Vec<String>,
    /// Steam application id, when the game is on Steam.
    #[serde(default)]
    pub steam_appid: Option<u64>,
    /// Epic application name, when the game is on Epic.
    #[serde(default)]
    pub epic_app_name: Option<String>,
    /// Where the game is likely installed.
    #[serde(default)]
    pub install_hints: Vec<PathEntry>,
    /// What the game leaves behind.
    #[serde(default)]
    pub residue: Vec<PathEntry>,
    /// Save data. A protection list, never a removal list.
    #[serde(default)]
    pub saves: Vec<PathEntry>,
    /// Registry footprint.
    #[serde(default)]
    pub registry: Vec<RegistryEntry>,
}

/// How a launcher uninstalls one of its games.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherUninstallKind {
    /// A URL protocol handler, e.g. `steam://uninstall/{appid}`.
    Protocol,
    /// An MSI product code held in `command`.
    Msi,
    /// An MSI product code read from the launcher's own manifest.
    MsiFromManifest,
    /// An executable at `command`.
    Exe,
    /// No launcher-driven path; fall back to the uninstall registry entry.
    None,
}

/// How to uninstall through a launcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherUninstall {
    /// Which invocation style applies.
    pub kind: LauncherUninstallKind,
    /// Command or protocol template, depending on `kind`.
    #[serde(default)]
    pub command: Option<String>,
    /// Whether the launcher can do this without user interaction.
    #[serde(default)]
    pub silent: bool,
}

/// A game launcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launcher {
    /// Stable kebab-case identifier, referenced by `game.platforms`.
    pub id: String,
    /// Human-readable name.
    pub display: String,
    /// Registry key proving the launcher is installed.
    #[serde(default)]
    pub detect_registry: Option<String>,
    /// Relative path to the launcher's library index.
    #[serde(default)]
    pub library_index: Option<String>,
    /// Glob matching the launcher's per-game manifests.
    #[serde(default)]
    pub manifest_glob: Option<String>,
    /// How to uninstall through this launcher.
    #[serde(default)]
    pub uninstall: Option<LauncherUninstall>,
}
