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
//! Services and drivers answer to the same rule, and are decided *first*,
//! because they feed it: an attributed service's image and name become evidence
//! for paths and keys. Taking every service and every `.sys` file added between
//! two snapshots — a driver update from Windows Update, a second program
//! installed at the same time — made them part of the entry, unlocked them in
//! the deny-list check, and let their names attribute paths of their own. An
//! item that cannot be attributed is left out and named, never kept quietly:
//! the inference table resolves towards the entry that removes less.
//!
//! # A third observation, and what the first two had hidden
//!
//! EA's anti-cheat, observed beside the EA app it is installed with, broke the
//! rules above in four places at once. Its service binary is too large to have
//! its signature read, so nothing signed sat at its image — only beside it. Its
//! kernel driver is registered in the registry and nowhere else, invisible to
//! the service control manager. The EA app is a large program whose folders are
//! called `settings` and `universal`, and every folder name used to become an
//! identifier. And one publisher signs both. So: a file beside a signed one is
//! attributed; identifiers come from the product's own folder, not from every
//! folder inside it; a driver found only in the registry is found, named, and
//! counted; and `--only` narrows a draft to one product when a publisher ships
//! two.
//!
//! And the draft is checked against the **same deny-list the broker enforces at
//! runtime**, not a copy of its intent. A generator that proposes a path the
//! runtime would refuse has produced an entry that cannot work, and the person
//! reviewing it has no way to know that by reading it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use wardsweep_core::catalog::schema::{
    AntiCheat, Class, Kind, PathEntry, RegistryEntry, Risk, View,
};

use wardsweep_core::safety::denylist::{Exceptions, Stage, check_path, check_registry_key};
use wardsweep_core::safety::paths::{canonicalise_reg_key, canonicalise_syntactic};

use crate::diff::{ChangeKind, Diff, FileChange, RegistryChange, ServiceChange};

/// Machine-wide prefixes replaced by the `%VAR%` templates `docs/04` allows.
///
/// Longest first: `C:\Program Files (x86)` begins with `C:\Program Files`. A
/// prefix matches only up to a separator, so `C:\Program FilesX` is left alone.
const MACHINE_VARIABLES: &[(&str, &str)] = &[
    ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
    ("ProgramFiles", "C:\\Program Files"),
    ("ProgramData", "C:\\ProgramData"),
    ("SystemRoot", "C:\\Windows"),
];

/// Locations below a profile directory, tried before `%USERPROFILE%` itself.
const PROFILE_VARIABLES: &[(&str, &str)] = &[
    ("LOCALAPPDATA", "AppData\\Local"),
    ("APPDATA", "AppData\\Roaming"),
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
#[cfg(test)]
#[must_use]
pub fn draft(footprint: &Diff, residue: Option<&Diff>, signer: Option<&str>) -> Draft {
    draft_scoped(footprint, residue, signer, &[])
}

/// A draft, limited to what mentions one of `only` when any are given.
///
/// One publisher often signs a launcher as well as its anti-cheat, and a
/// signature cannot tell them apart. Every path, key and service the draft
/// takes must then also contain one of these texts, compared without regard to
/// case: `--only eaanticheat` keeps EA's anti-cheat and leaves the EA app out.
#[must_use]
pub fn draft_scoped(
    footprint: &Diff,
    residue: Option<&Diff>,
    signer: Option<&str>,
    only: &[String],
) -> Draft {
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

    let only: Vec<String> = only
        .iter()
        .map(|text| text.trim().to_ascii_lowercase())
        .filter(|text| !text.is_empty())
        .collect();
    note_scope(footprint, residue, chosen.as_deref(), &only, &mut review);

    // Services first: an attributed service's image and name are evidence for
    // everything after it, so an unattributed one must not get that far.
    let mut attribution =
        Attribution::from_signed_files(footprint, residue, chosen.as_deref(), only);
    let (services, unattributed_services): (Vec<&ServiceChange>, Vec<&ServiceChange>) = footprint
        .services
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .partition(|change| attribution.claims_service(change));
    attribution.add_services(&services);

    // Drivers the service control manager never listed. Judged after the
    // listed services, whose images and names are evidence for them.
    let (registry_kept, registry_left_out): (Vec<RegistryDriver>, Vec<RegistryDriver>) =
        registry_only_drivers(footprint)
            .into_iter()
            .partition(|driver| attribution.claims_registry_driver(driver, chosen.as_deref()));
    for driver in &registry_kept {
        attribution.tokens.insert(driver.name.to_ascii_lowercase());
    }

    let mut drivers = driver_files(footprint, &attribution, &services);
    for driver in &registry_kept {
        if let Some(name) = file_name(&driver.image).filter(|name| !name.is_empty()) {
            drivers
                .kept
                .entry(name.to_ascii_lowercase())
                .or_insert(name);
        }
    }

    // docs/16 inference table, over what could be attributed.
    let has_driver = services.iter().any(|change| change.is_driver)
        || !drivers.kept.is_empty()
        || !registry_kept.is_empty();
    let boot_start = services.iter().any(|change| change.is_boot_start)
        || registry_kept.iter().any(|driver| driver.boot_start);

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

    note_left_out(
        &unattributed_services,
        &drivers.left_out,
        chosen.as_deref(),
        &mut review,
    );
    note_registry_drivers(
        &registry_kept,
        &registry_left_out,
        chosen.as_deref(),
        &mut review,
    );

    let left_out_a_driver = !drivers.left_out.is_empty()
        || !registry_left_out.is_empty()
        || unattributed_services.iter().any(|change| change.is_driver);
    note_kind(has_driver, boot_start, left_out_a_driver, &mut review);

    // The deny-list allows a service key only when the catalog declares that
    // service, and a driver file only when the catalog names it. Those are the
    // two carve-outs `Exceptions` exists for, so the draft is validated with
    // exactly the exceptions its own fields would unlock at runtime — not with
    // `Exceptions::none()`, which refuses the entry for declaring the very
    // services it is about.
    let service_names: Vec<String> = services
        .iter()
        .map(|change| change.name.clone())
        .chain(registry_kept.iter().map(|driver| driver.name.clone()))
        .collect();
    let exceptions = Exceptions::new(drivers.kept.values(), service_names.iter());

    let paths = path_entries(footprint, residue, &attribution, &exceptions, &mut review);
    let registry = registry_entries(footprint, &attribution, &exceptions, &mut review);
    let event_sources = event_sources(footprint, &attribution, chosen.as_deref(), &mut review);

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
            services: service_names,
            drivers: drivers.kept.into_values().collect(),
            paths,
            registry,
            tasks: Vec::new(),
            firewall_rules: Vec::new(),
            event_sources,
            official_uninstall: None,
        },
        signers,
        review,
    }
}

/// What ties a file, a service or a key to the chosen publisher.
///
/// Attribution is by publisher signature, or by living where this anti-cheat's
/// own files live. Without it a draft picks up whatever else the machine did
/// between the two snapshots — the first real run produced
/// `%SystemRoot%\System32\drivers`, a running application's `leveldb`
/// directory, and a token-broker cache.
#[derive(Default)]
struct Attribution {
    /// Lower-cased paths of added files the publisher signed, and of the images
    /// of the services attributed to it.
    files: BTreeSet<String>,
    /// Lower-cased directories holding a file the publisher signed. A file
    /// beside a signed one is attributed: EA's 190 MB service binary is too
    /// large to have its signature read, and only the files next to it carry
    /// one.
    directories: BTreeSet<String>,
    /// Lower-cased product folders below their root with at least two
    /// components — `ea\ac` — which installers mirror under
    /// `HKLM\SOFTWARE` and `HKCU\SOFTWARE`.
    products: BTreeSet<String>,
    /// Lower-cased file names of every attributed file, so a copy of an
    /// attributed image somewhere else — `System32\drivers` — is recognised.
    names: BTreeSet<String>,
    /// Lower-cased names that identify this anti-cheat in a path or a key.
    tokens: BTreeSet<String>,
    /// `--only`, lower-cased: what everything attributed must also mention.
    only: Vec<String>,
}

impl Attribution {
    /// The publisher's signed files, and the directory names they live in.
    fn from_signed_files(
        footprint: &Diff,
        residue: Option<&Diff>,
        signer: Option<&str>,
        only: Vec<String>,
    ) -> Self {
        let added = || {
            footprint
                .files
                .iter()
                .chain(residue.into_iter().flat_map(|diff| diff.files.iter()))
                .filter(|change| change.kind == ChangeKind::Added)
        };

        let files: BTreeSet<String> = added()
            .filter(|change| {
                matches!(
                    (signer, change.signer.as_deref()),
                    (Some(want), Some(have)) if have.eq_ignore_ascii_case(want)
                )
            })
            .map(|change| change.path.to_ascii_lowercase())
            .collect();
        let tokens = directory_tokens(&files);
        let directories: BTreeSet<String> = files
            .iter()
            .filter_map(|path| parent_of(path))
            .filter(|directory| identifies_something(directory))
            .collect();
        let products: BTreeSet<String> = directories
            .iter()
            .filter_map(|directory| {
                let below = below_root(directory);
                (below.len() >= 2).then(|| below[..2].join("\\"))
            })
            .collect();

        let mut attribution = Self {
            files,
            directories,
            products,
            names: BTreeSet::new(),
            tokens,
            only,
        };
        // Every added file that the evidence so far claims lends its name, so
        // an unsigned copy of a claimed binary is recognised elsewhere.
        let names: BTreeSet<String> = added()
            .filter(|change| attribution.claims_path(&change.path.to_ascii_lowercase()))
            .filter_map(|change| file_name(&change.path))
            .map(|name| name.to_ascii_lowercase())
            .collect();
        attribution.names = names;
        attribution
    }

    /// Whether a lower-cased text is inside what `--only` allows.
    fn in_scope(&self, lowered: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|text| lowered.contains(text.as_str()))
    }

    /// Whether a lower-cased path or key belongs to this anti-cheat.
    fn claims_path(&self, lowered: &str) -> bool {
        self.in_scope(lowered) && self.claims_unscoped(lowered)
    }

    /// [`Attribution::claims_path`] without `--only`.
    fn claims_unscoped(&self, lowered: &str) -> bool {
        self.files.contains(lowered)
            || parent_of(lowered).is_some_and(|parent| self.directories.contains(&parent))
            || self
                .tokens
                .iter()
                .any(|token| contains_token(lowered, token))
    }

    /// Whether a lower-cased registry key belongs to this anti-cheat: as a
    /// path does, or as the `SOFTWARE\<vendor>\<product>` an installer writes
    /// for a product folder it laid down.
    fn claims_key(&self, lowered: &str) -> bool {
        if !self.in_scope(lowered) {
            return false;
        }
        if self.claims_unscoped(lowered) {
            return true;
        }
        let Some(below) = SOFTWARE_ROOTS
            .iter()
            .find_map(|root| lowered.strip_prefix(root))
        else {
            return false;
        };
        self.products.iter().any(|product| {
            below
                .strip_prefix(product.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
        })
    }

    /// Whether an added service belongs to this anti-cheat.
    ///
    /// A driver is attestation-signed by Microsoft rather than by its vendor.
    /// Measured on a real machine: every `.sys` in the ACE
    /// footprint carried "Microsoft Windows Hardware Compatibility Publisher"
    /// and only the two user-mode binaries carried the vendor. So a service is
    /// claimed by its image's location or file name, or by its own name, not
    /// only by its image's signature.
    fn claims_service(&self, change: &ServiceChange) -> bool {
        let name = change.name.to_ascii_lowercase();
        let image = change
            .after
            .as_ref()
            .map(|record| normalise_image(&record.binary_path).to_ascii_lowercase());
        if !(self.in_scope(&name) || image.as_deref().is_some_and(|image| self.in_scope(image))) {
            return false;
        }
        if self.tokens.iter().any(|token| contains_token(&name, token)) {
            return true;
        }
        let Some(image) = image else {
            return false;
        };
        self.claims_unscoped(&image)
            || file_name(&image).is_some_and(|file| self.names.contains(&file))
    }

    /// Whether a driver found only in the registry belongs to this anti-cheat:
    /// by its key or its image, as anything else is, or because its own
    /// description names the publisher — EA's reads "Electronic Arts AntiCheat
    /// Driver", and its image is not on disk between game sessions.
    fn claims_registry_driver(&self, driver: &RegistryDriver, publisher: Option<&str>) -> bool {
        let key = driver.key.to_ascii_lowercase();
        let image = driver.image.to_ascii_lowercase();
        if !(self.in_scope(&key) || self.in_scope(&image) || self.in_scope(&driver.describes)) {
            return false;
        }
        self.claims_unscoped(&key)
            || self.claims_unscoped(&image)
            || file_name(&image).is_some_and(|file| self.names.contains(&file))
            || publisher
                .and_then(publisher_name)
                .is_some_and(|name| driver.describes.contains(&name))
    }

    /// Admit attributed services as evidence: their images and their names.
    fn add_services(&mut self, services: &[&ServiceChange]) {
        for service in services {
            if let Some(record) = &service.after {
                let image = normalise_image(&record.binary_path).to_ascii_lowercase();
                if let Some(file) = file_name(&image) {
                    self.names.insert(file);
                }
                self.files.insert(image);
            }
            self.tokens.insert(service.name.to_ascii_lowercase());
        }
    }
}

/// Whether `token` occurs in `text` with no ASCII letter or digit either side.
///
/// A substring match let a three-letter name claim every path containing it
/// inside a longer word. Both arguments are lower-cased by the caller.
fn contains_token(text: &str, token: &str) -> bool {
    !token.is_empty()
        && text.match_indices(token).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + token.len()..].chars().next();
            !before.is_some_and(|c| c.is_ascii_alphanumeric())
                && !after.is_some_and(|c| c.is_ascii_alphanumeric())
        })
}

/// Directory names that identify this anti-cheat, from the files it signed.
///
/// `%ProgramData%\AntiCheatExpert` holds one unsigned `.dat` file and nothing
/// else, so nothing about the file attributes it — but the directory carries
/// the same name as `%ProgramFiles%\AntiCheatExpert`, which the signed files
/// anchor. Almost every installer lays itself out that way.
///
/// Only the product's own folders count: the first two below their root,
/// `Program Files\<vendor>\<product>`. Every folder name used to, and the EA app
/// — a large program with folders called `settings`, `universal` and
/// `platforms` — then claimed `Local Settings` and the speech platform's keys.
fn directory_tokens(files: &BTreeSet<String>) -> BTreeSet<String> {
    files
        .iter()
        .flat_map(|path| {
            let below = below_root(path);
            // The last component is the file itself.
            let folders = below.len().saturating_sub(1);
            below
                .into_iter()
                .take(folders.min(2))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        // A shared system directory names nothing in particular. Without this,
        // `System32\drivers` would make `drivers` an identifier and match half
        // the machine.
        .filter(|leaf| leaf.len() >= 4 && !SHARED_DIRECTORIES.contains(&leaf.as_str()))
        .collect()
}

/// The roots a product's folder sits directly below, lower-cased.
///
/// Longest first, so `windows\system32\drivers` is tried before `windows`.
const ROOTS: &[&str] = &[
    "windows\\system32\\drivers",
    "windows\\system32",
    "windows\\syswow64",
    "program files (x86)",
    "program files",
    "programdata",
    "windows",
];

/// Registry roots an installer mirrors its folders under, lower-cased.
const SOFTWARE_ROOTS: &[&str] = &[
    "hklm\\software\\wow6432node\\",
    "hkcu\\software\\wow6432node\\",
    "hklm\\software\\",
    "hkcu\\software\\",
];

/// The components of a lower-cased path below its root, product first.
///
/// `c:\program files\ea\ac\x.exe` gives `["ea", "ac", "x.exe"]`;
/// `c:\users\<name>\appdata\local\riot games\x` gives `["riot games", "x"]`; a
/// path outside every root keeps all its components below the drive.
fn below_root(path: &str) -> Vec<&str> {
    let Some(rest) = path.get(3..).filter(|_| path.get(1..3) == Some(":\\")) else {
        return Vec::new();
    };
    let parts: Vec<&str> = rest.split('\\').filter(|part| !part.is_empty()).collect();
    if parts.first() == Some(&"users") && parts.len() > 2 {
        let profile = &parts[2..];
        if profile.len() > 2
            && profile[0] == "appdata"
            && matches!(profile[1], "local" | "locallow" | "roaming")
        {
            return profile[2..].to_vec();
        }
        return profile.to_vec();
    }
    for root in ROOTS {
        let root_parts: Vec<&str> = root.split('\\').collect();
        if parts.len() > root_parts.len() && parts[..root_parts.len()] == root_parts[..] {
            return parts[root_parts.len()..].to_vec();
        }
    }
    parts
}

/// Whether a lower-cased directory can identify a product: not a root itself,
/// and not one of the folders every program shares.
fn identifies_something(directory: &str) -> bool {
    let leaf = directory.rsplit('\\').next().unwrap_or_default();
    !SHARED_DIRECTORIES.contains(&leaf) && !below_root(directory).is_empty()
}

/// A publisher's name as prose would write it: `Electronic Arts, Inc.` as
/// `electronic arts`, `ACEVILLE PTE LTD` as `aceville`. `None` when what is
/// left is too short to mean anything.
fn publisher_name(signer: &str) -> Option<String> {
    const SUFFIXES: &[&str] = &[
        "inc.",
        "inc",
        "ltd.",
        "ltd",
        "pte.",
        "pte",
        "llc",
        "corp.",
        "corp",
        "corporation",
        "gmbh",
        "limited",
        "co.",
        "co",
    ];
    let lowered = signer.to_ascii_lowercase();
    let mut name = lowered
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    while let Some(rest) = SUFFIXES.iter().find_map(|suffix| {
        name.strip_suffix(suffix)
            .filter(|rest| rest.ends_with(' '))
            .map(|rest| rest.trim_end().to_owned())
    }) {
        name = rest;
    }
    (name.len() >= 4).then_some(name)
}

/// A driver registered under `Services` that the service control manager did
/// not list.
///
/// SCM builds its list when Windows starts. A driver key written straight into
/// the registry afterwards — EA's minifilter is — or one missing a value SCM
/// requires — Neverness To Everness's `PGameProtectDriver` has no
/// `ErrorControl` — is not in it, and a scan that trusts SCM alone never sees
/// either. The registry does.
struct RegistryDriver {
    name: String,
    key: String,
    image: String,
    boot_start: bool,
    /// `Description` and `DisplayName`, lower-cased.
    describes: String,
}

/// The `Services` key every driver registration lives under.
const SERVICES_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\";

/// Drivers added to the registry that the services domain does not list.
fn registry_only_drivers(footprint: &Diff) -> Vec<RegistryDriver> {
    let listed: BTreeSet<String> = footprint
        .services
        .iter()
        .map(|change| change.name.to_ascii_lowercase())
        .collect();
    let mut found: BTreeMap<String, RegistryDriver> = BTreeMap::new();
    for change in &footprint.registry {
        if change.kind != ChangeKind::Added {
            continue;
        }
        let Some(name) = service_key_name(change) else {
            continue;
        };
        if listed.contains(&name.to_ascii_lowercase()) {
            continue;
        }
        let Some(record) = &change.after else {
            continue;
        };
        let value = |wanted: &str| {
            record
                .values
                .iter()
                .find(|value| value.name.eq_ignore_ascii_case(wanted))
                .map(|value| value.data.clone())
        };
        // SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER and
        // SERVICE_RECOGNIZER_DRIVER: the three that load into the kernel.
        let Some(kind) = value("Type").and_then(|data| data.parse::<u32>().ok()) else {
            continue;
        };
        if !matches!(kind, 1 | 2 | 8) {
            continue;
        }
        found
            .entry(name.to_ascii_lowercase())
            .or_insert_with(|| RegistryDriver {
                name: name.to_owned(),
                key: change.key.clone(),
                image: normalise_image(&value("ImagePath").unwrap_or_default()),
                boot_start: value("Start").is_some_and(|start| start == "0"),
                describes: [value("Description"), value("DisplayName")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase(),
            });
    }
    found.into_values().collect()
}

/// The service a `Services\<name>` key is for, when the key is exactly that.
fn service_key_name(change: &RegistryChange) -> Option<&str> {
    let head = change.key.get(..SERVICES_KEY.len())?;
    let name = change.key.get(SERVICES_KEY.len()..)?;
    (head.eq_ignore_ascii_case(SERVICES_KEY) && !name.is_empty() && !name.contains('\\'))
        .then_some(name)
}

/// The `EventLog` key every event source registration lives under.
const EVENT_LOG_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\";

/// Event log sources the footprint registered: kept when attributed, named in
/// the review notes either way.
///
/// A source's own key carries little to attribute it by — EA's names Windows'
/// generic `EventCreate.exe` as its message file — so it is kept only when its
/// name carries one of this anti-cheat's identifiers or the publisher's name,
/// and otherwise named for a person to decide, never dropped quietly.
fn event_sources(
    footprint: &Diff,
    attribution: &Attribution,
    signer: Option<&str>,
    review: &mut Vec<String>,
) -> Vec<String> {
    let publisher = signer.and_then(publisher_name);
    let mut kept: BTreeMap<String, String> = BTreeMap::new();
    let mut left_out: BTreeMap<String, String> = BTreeMap::new();
    for change in footprint
        .registry
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
    {
        let Some(head) = change.key.get(..EVENT_LOG_KEY.len()) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(EVENT_LOG_KEY) {
            continue;
        }
        let Some((log, source)) = change.key[EVENT_LOG_KEY.len()..].split_once('\\') else {
            continue;
        };
        if source.is_empty() || source.contains('\\') {
            continue;
        }
        let lowered = source.to_ascii_lowercase();
        let claimed = attribution.in_scope(&change.key.to_ascii_lowercase())
            && (attribution
                .tokens
                .iter()
                .any(|token| contains_token(&lowered, token))
                || publisher
                    .as_deref()
                    .is_some_and(|name| lowered.contains(name)));
        let into = if claimed { &mut kept } else { &mut left_out };
        into.entry(lowered)
            .or_insert_with(|| format!("{log}\\{source}"));
    }
    for (lowered, place) in &left_out {
        if kept.contains_key(lowered) {
            continue;
        }
        review.push(format!(
            "event log source `{place}` was registered and nothing ties its name to this \
             anti-cheat, so it is not in `event_sources`. Add it if it is this anti-cheat's."
        ));
    }
    kept.into_values()
        .map(|place| {
            place
                .split_once('\\')
                .map_or(place.clone(), |(_, source)| source.to_owned())
        })
        .collect()
}

/// Name every driver found only in the registry, kept or not.
fn note_registry_drivers(
    kept: &[RegistryDriver],
    left_out: &[RegistryDriver],
    signer: Option<&str>,
    review: &mut Vec<String>,
) {
    let publisher = signer.unwrap_or("the chosen publisher");
    for driver in kept {
        review.push(format!(
            "`{}` is a driver registered in the registry (`{}`, image `{}`) that the service \
             control manager does not list, so a scan that trusts SCM alone never finds it \
             (docs/05). It is in `services` and `drivers` so the entry names it; confirm it is \
             this anti-cheat's.",
            driver.name, driver.key, driver.image
        ));
    }
    for driver in left_out {
        review.push(format!(
            "driver `{}` is registered in the registry only (`{}`, image `{}`), unknown to the \
             service control manager, and nothing ties it to {publisher}, so it was left out. \
             Add it to `services` and `drivers` only if it is this anti-cheat's.",
            driver.name, driver.key, driver.image
        ));
    }
}

/// Say how far attribution reached: limited by `--only`, or — when it was not —
/// whether the publisher's files span more than one product.
fn note_scope(
    footprint: &Diff,
    residue: Option<&Diff>,
    signer: Option<&str>,
    only: &[String],
    review: &mut Vec<String>,
) {
    if only.is_empty() {
        note_several_products(footprint, residue, signer, review);
        return;
    }
    review.push(format!(
        "attribution was limited with --only to what mentions {}. Everything else this \
         publisher signed was left out on purpose; check that nothing of the anti-cheat's was \
         among it.",
        only.iter()
            .map(|text| format!("`{text}`"))
            .collect::<Vec<_>>()
            .join(" or ")
    ));
}

/// The notes that go with the inferred `kind`.
fn note_kind(
    has_driver: bool,
    boot_start: bool,
    left_out_a_driver: bool,
    review: &mut Vec<String>,
) {
    if !has_driver && left_out_a_driver {
        review.push(
            "no driver could be attributed to this publisher, so `kind` is `usermode` — but a \
             driver *was* added and left out, named above. If it is this anti-cheat's, add it \
             and make `kind` \"kernel\"."
                .to_owned(),
        );
    } else if !has_driver {
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
}

/// Point out a publisher whose signed files span several products.
///
/// A signature attributes everything the publisher signed, and a publisher
/// that ships a launcher beside its anti-cheat — EA does — gets both in one
/// draft. Nothing in a diff can tell them apart; a person can, with `--only`.
fn note_several_products(
    footprint: &Diff,
    residue: Option<&Diff>,
    signer: Option<&str>,
    review: &mut Vec<String>,
) {
    let Some(signer) = signer else {
        return;
    };
    let mut products: BTreeMap<String, String> = BTreeMap::new();
    for change in footprint
        .files
        .iter()
        .chain(residue.into_iter().flat_map(|diff| diff.files.iter()))
        .filter(|change| change.kind == ChangeKind::Added)
        .filter(|change| {
            change
                .signer
                .as_deref()
                .is_some_and(|have| have.eq_ignore_ascii_case(signer))
        })
    {
        let lowered = change.path.to_ascii_lowercase();
        let below = below_root(&lowered);
        if below.len() < 2 {
            continue;
        }
        // The product folder, or the vendor folder and the product below it
        // when the first is shared or says nothing on its own.
        let depth = if below[0].len() < 4 || SHARED_DIRECTORIES.contains(&below[0]) {
            2
        } else {
            1
        };
        if below.len() <= depth {
            continue;
        }
        let tail: usize = below[depth..].iter().map(|part| part.len() + 1).sum();
        let original = &change.path[..change.path.len() - tail];
        products
            .entry(original.to_ascii_lowercase())
            .or_insert_with(|| templated(original));
    }
    if products.len() > 1 {
        review.push(format!(
            "{signer} signed files in {} separate product folders: {}. One publisher often \
             ships a launcher beside its anti-cheat, and a signature cannot tell them apart; if \
             any of these is not the anti-cheat, re-run with --only naming the anti-cheat's \
             folder or service.",
            products.len(),
            products
                .values()
                .map(|product| format!("`{product}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
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
    "package cache",
];

/// Driver file names the draft keeps, and those it leaves out.
struct Drivers {
    /// Keyed by lower-cased name, so one driver reached two ways is listed once.
    kept: BTreeMap<String, String>,
    /// Added `.sys` files nothing attributes.
    left_out: Vec<String>,
}

/// Every driver the evidence attributes: added `.sys` files it claims, and the
/// images of attributed driver services.
fn driver_files(
    footprint: &Diff,
    attribution: &Attribution,
    services: &[&ServiceChange],
) -> Drivers {
    let mut kept = BTreeMap::new();
    let mut left_out = Vec::new();

    for change in footprint
        .files
        .iter()
        .filter(|change| change.kind == ChangeKind::Added && change.is_driver_image)
    {
        let Some(name) = file_name(&change.path) else {
            continue;
        };
        let lowered = name.to_ascii_lowercase();
        if attribution.claims_path(&change.path.to_ascii_lowercase())
            || attribution.names.contains(&lowered)
        {
            kept.insert(lowered, name);
        } else {
            left_out.push(change.path.clone());
        }
    }

    for service in services.iter().filter(|service| service.is_driver) {
        if let Some(name) = service
            .after
            .as_ref()
            .and_then(|record| file_name(&normalise_image(&record.binary_path)))
        {
            kept.entry(name.to_ascii_lowercase()).or_insert(name);
        }
    }

    Drivers { kept, left_out }
}

/// Name every service and driver the draft left out, one note each.
///
/// Never a bare count. A service or driver dropped here is either someone
/// else's — the reason for dropping it — or this anti-cheat's, in which case
/// the entry is missing it and WardSweep will never find it. Only a person can
/// tell which, and only if the note says what it was.
fn note_left_out(
    services: &[&ServiceChange],
    drivers: &[String],
    signer: Option<&str>,
    review: &mut Vec<String>,
) {
    let publisher = signer.unwrap_or("the chosen publisher");
    for service in services {
        let image = service
            .after
            .as_ref()
            .map(|record| normalise_image(&record.binary_path))
            .unwrap_or_default();
        let what = if service.is_driver {
            "KERNEL DRIVER service"
        } else {
            "service"
        };
        review.push(format!(
            "{what} `{}` (image `{image}`) was added but nothing ties it to {publisher}, so it \
             was left out. Add it back only if it is this anti-cheat's.",
            service.name
        ));
    }
    for path in drivers {
        review.push(format!(
            "driver file `{path}` was added but nothing ties it to {publisher}, so it was left \
             out. Add it to `drivers` only if it is this anti-cheat's."
        ));
    }
}

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
    attribution: &Attribution,
    exceptions: &Exceptions,
    review: &mut Vec<String>,
) -> Vec<PathEntry> {
    let mut directories: BTreeSet<String> = BTreeSet::new();
    let mut dropped = 0usize;

    let gather =
        |changes: &[FileChange], directories: &mut BTreeSet<String>, dropped: &mut usize| {
            for change in changes {
                if change.kind != ChangeKind::Added {
                    continue;
                }
                // Signed by the publisher, or living in a directory this
                // anti-cheat names. The second is what keeps an unsigned data file
                // under `%ProgramData%\<Product>` in the footprint.
                if !attribution.claims_path(&change.path.to_ascii_lowercase()) {
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
            "{dropped} added file(s) could not be attributed to this publisher and were left \
             out. That is ordinary machine churn between the two snapshots; check the diff if \
             the footprint looks short."
        ));
    }

    // Collapse a directory whose parent is also listed: `…\Vanguard\Logs` adds
    // nothing over `…\Vanguard`, and the class of the parent covers it.
    let collapsed: Vec<String> = directories
        .iter()
        .filter(|candidate| !has_listed_ancestor(candidate, &directories))
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

/// Whether some proper ancestor of `candidate` is also in `listed`.
///
/// Walks the candidate's own separators rather than comparing it with every
/// other entry, so collapsing is linear in the number of entries rather than
/// quadratic.
fn has_listed_ancestor(candidate: &str, listed: &BTreeSet<String>) -> bool {
    candidate
        .match_indices('\\')
        .any(|(at, _)| listed.contains(&candidate[..at]))
}

/// A registry key as the native view names it.
///
/// The walk reads `HKLM\SOFTWARE` through both WOW64 views, and in the 64-bit
/// view it also descends into `WOW6432Node` — which *is* the 32-bit view under
/// another name. So one physical key reached the diff twice, as
/// `HKLM\SOFTWARE\X` in view 32 and `HKLM\SOFTWARE\WOW6432Node\X` in view 64,
/// and a draft listed both. Fold the second spelling into the first.
fn native_view(key: &str, view: &str) -> (String, String) {
    const ALIAS: &str = "HKLM\\SOFTWARE\\WOW6432Node\\";
    if view == "64"
        && key.len() > ALIAS.len()
        && key
            .get(..ALIAS.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(ALIAS))
    {
        return (
            format!("HKLM\\SOFTWARE\\{}", &key[ALIAS.len()..]),
            "32".to_owned(),
        );
    }
    (key.to_owned(), view.to_owned())
}

/// Registry keys that were added, deduplicated to their shallowest ancestor.
///
/// Filtered the same way paths are: a key the deny-list refuses is dropped with
/// a note, rather than proposed for a reviewer to discover later.
fn registry_entries(
    footprint: &Diff,
    attribution: &Attribution,
    exceptions: &Exceptions,
    review: &mut Vec<String>,
) -> Vec<RegistryEntry> {
    let mut unattributed = 0usize;
    // Keyed by the key, valued by the WOW64 views it was actually seen added
    // in. The harness opens both views explicitly and stamps every change with
    // the one it came from, so a draft can record what was observed instead of
    // assuming.
    let mut added: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for change in &footprint.registry {
        if change.kind != ChangeKind::Added {
            continue;
        }
        // Registry needs the same attribution as the filesystem. Without it the
        // first real draft carried a shell session key that had nothing to do
        // with the anti-cheat.
        if !attribution.claims_key(&change.key.to_ascii_lowercase()) {
            unattributed += 1;
            continue;
        }
        let (key, view) = native_view(&change.key, &change.view);
        added.entry(key).or_default().insert(view);
    }

    if unattributed > 0 {
        review.push(format!(
            "{unattributed} added registry key(s) could not be attributed to this anti-cheat \
             and were left out."
        ));
    }

    let keys: BTreeSet<String> = added.keys().cloned().collect();
    let mut narrowed = Vec::new();
    let mut undetermined = Vec::new();
    let entries: Vec<RegistryEntry> = added
        .keys()
        .filter(|candidate| !has_listed_ancestor(candidate, &keys))
        .filter(|key| {
            let allowed = canonicalise_reg_key(key)
                .ok()
                .is_some_and(|canonical| check_registry_key(&canonical, exceptions).is_ok());
            if !allowed {
                review.push(format!("`{key}` was dropped: the deny-list refuses it."));
            }
            allowed
        })
        .map(|key| {
            // An entry covers every key folded into it, so it has to cover
            // their views too. EA writes `EA\AC` through the 64-bit view and
            // `EA\AC\Installs\fc26` through the 32-bit one; an entry that kept
            // only the first view would miss the second.
            let mut views = added[key].clone();
            let prefix = format!("{key}\\");
            for (descendant, seen) in added.range(prefix.clone()..) {
                if !descendant.starts_with(&prefix) {
                    break;
                }
                views.extend(seen.iter().cloned());
            }
            let view = match (views.contains("32"), views.contains("64")) {
                (true, true) => View::Both,
                (true, false) => {
                    narrowed.push(format!("`{key}` (32-bit view only)"));
                    View::Bits32
                }
                (false, true) => {
                    narrowed.push(format!("`{key}` (64-bit view only)"));
                    View::Bits64
                }
                // No recognised view on any change for this key. Falling back
                // to `both` is the wider claim, so it is named rather than made
                // quietly.
                (false, false) => {
                    undetermined.push(format!("`{key}`"));
                    View::Both
                }
            };
            RegistryEntry {
                key: key.clone(),
                view,
                class: Class::Config,
            }
        })
        .collect();

    if !narrowed.is_empty() {
        review.push(format!(
            "{} key(s) were seen in one WOW64 view only and are recorded that way rather than \
             as `both`: {}. `HKLM\\SOFTWARE` is redirected and `HKLM\\SYSTEM` is not, so a \
             single view is usually a fact about redirection — but confirm it, because widening \
             to `both` claims a key the observation never saw.",
            narrowed.len(),
            narrowed.join(", ")
        ));
    }
    if !undetermined.is_empty() {
        review.push(format!(
            "{} key(s) carried no recognised WOW64 view and defaulted to `both`, which is the \
             wider claim: {}. Check the diff before submitting.",
            undetermined.len(),
            undetermined.join(", ")
        ));
    }

    entries
}

/// Replace a known prefix with its `%VAR%` template.
///
/// A path below a profile directory never keeps the directory's name: it is
/// either a real account name, which identifies someone, or the redactor's
/// `%USER%`, which is not a variable the schema expands. Either way the draft
/// would not load, or would publish the name.
fn templated(path: &str) -> String {
    if let Some((profile, rest)) = split_profile(path) {
        if profile.eq_ignore_ascii_case("public") {
            return format!("%PUBLIC%{rest}");
        }
        let inner = rest.strip_prefix('\\').unwrap_or(rest);
        for (variable, location) in PROFILE_VARIABLES {
            if let Some(tail) = strip_component_prefix(inner, location) {
                return format!("%{variable}%{tail}");
            }
        }
        return format!("%USERPROFILE%{rest}");
    }
    for (variable, prefix) in MACHINE_VARIABLES {
        if let Some(tail) = strip_component_prefix(path, prefix) {
            return format!("%{variable}%{tail}");
        }
    }
    path.to_owned()
}

/// `X:\Users\<name>\rest` as `(<name>, \rest)`.
fn split_profile(path: &str) -> Option<(&str, &str)> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let below_users = strip_component_prefix(&path[3..], "Users")?.strip_prefix('\\')?;
    let (profile, rest) = below_users
        .find('\\')
        .map_or((below_users, ""), |at| below_users.split_at(at));
    (!profile.is_empty()).then_some((profile, rest))
}

/// `path` without `prefix`, matched case-insensitively and only up to a
/// separator, so `C:\Program FilesX` does not lose `C:\Program Files`.
fn strip_component_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let head = path.get(..prefix.len())?;
    let tail = &path[prefix.len()..];
    (head.eq_ignore_ascii_case(prefix) && (tail.is_empty() || tail.starts_with('\\')))
        .then_some(tail)
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
        let emitted = MACHINE_VARIABLES
            .iter()
            .chain(PROFILE_VARIABLES)
            .map(|(variable, _)| *variable)
            .chain(["USERPROFILE", "PUBLIC"]);
        for variable in emitted {
            assert!(
                KNOWN_VARIABLES.contains(&variable),
                "%{variable}% is not in the schema's KNOWN_VARIABLES"
            );
        }
    }

    #[test]
    fn a_profile_name_never_reaches_a_draft() {
        // LocalLow used to become `%LOCALAPPDATA%Low\…`, and anything else under
        // a profile kept the account name — or the redactor's `%USER%`, which
        // the schema cannot expand.
        assert_eq!(
            templated("C:\\Users\\%USER%\\AppData\\LocalLow\\Studio\\Game"),
            "%USERPROFILE%\\AppData\\LocalLow\\Studio\\Game"
        );
        assert_eq!(
            templated("C:\\Users\\someone\\Documents\\My Games\\X"),
            "%USERPROFILE%\\Documents\\My Games\\X"
        );
        assert_eq!(
            templated("C:\\Users\\Public\\Documents\\X"),
            "%PUBLIC%\\Documents\\X"
        );
    }

    #[test]
    fn a_prefix_only_matches_up_to_a_separator() {
        assert_eq!(templated("C:\\Program FilesX\\Y"), "C:\\Program FilesX\\Y");
        assert_eq!(
            templated("D:\\Backup\\AppData\\Local\\X"),
            "D:\\Backup\\AppData\\Local\\X",
            "an AppData directory outside a profile is not %LOCALAPPDATA%"
        );
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
        // Signed the way the real files are: every Vanguard binary, the driver
        // included, carries the vendor's own certificate.
        let diff = signed(
            crate::diff::tests::diff_with_added_files(&[
                r"C:\Program Files\Riot Vanguard\vgk.sys",
                r"C:\Program Files\Riot Vanguard\vgc.exe",
            ]),
            "Riot Games, Inc.",
        );
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
        let with_driver = signed(
            crate::diff::tests::diff_with_added_files(&[r"C:\Program Files\X\thing.sys"]),
            "X Vendor",
        );
        let generated = draft(&with_driver, None, Some("X Vendor"));
        assert!(matches!(generated.entry.kind, Kind::Kernel));
        // No service record, so boot start is unknown: high, never low.
        assert!(matches!(generated.entry.risk, Risk::High));

        let no_driver = signed(
            crate::diff::tests::diff_with_added_files(&[r"C:\Program Files\X\thing.exe"]),
            "X Vendor",
        );
        let generated = draft(&no_driver, None, Some("X Vendor"));
        assert!(matches!(generated.entry.kind, Kind::Usermode));
        assert!(matches!(generated.entry.risk, Risk::Medium));
    }

    /// A diff whose added files all carry `signer`.
    fn signed(mut diff: Diff, signer: &str) -> Diff {
        for change in &mut diff.files {
            change.signer = Some(signer.to_owned());
        }
        diff
    }

    /// Give the one added file ending in `file` a signer.
    fn sign_one(diff: &mut Diff, file: &str, signer: &str) {
        let change = diff
            .files
            .iter_mut()
            .find(|change| change.path.ends_with(file))
            .expect("the fixture names this file");
        change.signer = Some(signer.to_owned());
    }

    /// `path_entries` with everything the caller would normally derive.
    fn entries_for(
        diff: &Diff,
        attributable: &BTreeSet<String>,
        services: &[String],
        review: &mut Vec<String>,
    ) -> Vec<PathEntry> {
        let mut tokens = directory_tokens(attributable);
        tokens.extend(services.iter().map(|name| name.to_ascii_lowercase()));
        let attribution = Attribution {
            files: attributable.clone(),
            tokens,
            ..Attribution::default()
        };
        let exceptions = Exceptions::new(Vec::<String>::new(), services.to_vec());
        path_entries(diff, None, &attribution, &exceptions, review)
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
    fn the_view_comes_from_the_observation_rather_than_from_both_by_default() {
        // Measured on a real Riot Vanguard install. The two service keys exist
        // in both views because `HKLM\SYSTEM` is not WOW64-redirected; the
        // uninstall entry exists only in the 64-bit view because
        // `HKLM\SOFTWARE` is. A draft that said `both` for all three would be
        // claiming a key the observation never saw.
        let mut review: Vec<String> = Vec::new();
        let diff = crate::diff::tests::diff_with_added_registry_keys(&[
            (r"HKLM\SYSTEM\CurrentControlSet\Services\vgk", "32"),
            (r"HKLM\SYSTEM\CurrentControlSet\Services\vgk", "64"),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Riot Vanguard",
                "64",
            ),
        ]);
        let attribution = Attribution {
            tokens: ["vgk", "riot vanguard"]
                .iter()
                .map(|t| (*t).to_owned())
                .collect(),
            ..Attribution::default()
        };
        let exceptions = Exceptions::new(Vec::<String>::new(), vec!["vgk".to_owned()]);

        let entries = registry_entries(&diff, &attribution, &exceptions, &mut review);

        let view_of = |needle: &str| {
            entries
                .iter()
                .find(|entry| entry.key.contains(needle))
                .map(|entry| entry.view)
        };
        assert_eq!(view_of("Services\\vgk"), Some(View::Both));
        assert_eq!(view_of("Uninstall"), Some(View::Bits64));
        assert!(
            review.iter().any(|note| note.contains("64-bit view only")),
            "narrowing must be explained, not silent: {review:?}"
        );
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
    fn a_token_matches_whole_words_only() {
        assert!(contains_token(
            "c:\\program files\\riot vanguard\\vgc.exe",
            "riot vanguard"
        ));
        assert!(contains_token(
            "hklm\\system\\currentcontrolset\\services\\vgc",
            "vgc"
        ));
        assert!(contains_token("c:\\x\\vgk.sys", "vgk"));
        // The failure a substring match had: a short name inside a longer word.
        assert!(!contains_token("c:\\src\\react\\index.js", "eac"));
        assert!(!contains_token("c:\\x\\vgkernel.dll", "vgk"));
    }

    fn added_service(name: &str, image: &str, driver: bool) -> ServiceChange {
        ServiceChange {
            name: name.to_owned(),
            kind: ChangeKind::Added,
            is_driver: driver,
            is_boot_start: false,
            before: None,
            after: Some(crate::model::ServiceRecord {
                name: name.to_owned(),
                display_name: name.to_owned(),
                service_type: if driver {
                    "kernel_driver"
                } else {
                    "win32_own_process"
                }
                .to_owned(),
                start_type: "demand".to_owned(),
                error_control: "normal".to_owned(),
                binary_path: image.to_owned(),
                load_order_group: String::new(),
                start_name: String::new(),
                dependencies: Vec::new(),
                description: String::new(),
                delayed_auto_start: false,
            }),
            fields: Vec::new(),
        }
    }

    /// A `Services` registration as the registry walk records it.
    fn registry_service(name: &str, values: &[(&str, &str, &str)]) -> crate::diff::RegistryChange {
        let key = format!("{SERVICES_KEY}{name}");
        crate::diff::RegistryChange {
            key: key.clone(),
            view: "64".to_owned(),
            kind: ChangeKind::Added,
            before: None,
            after: Some(crate::model::RegistryRecord {
                key,
                view: "64".to_owned(),
                values: values
                    .iter()
                    .map(|(name, kind, data)| crate::model::RegistryValue {
                        name: (*name).to_owned(),
                        kind: (*kind).to_owned(),
                        data: (*data).to_owned(),
                        oversized_bytes: None,
                    })
                    .collect(),
            }),
            fields: Vec::new(),
        }
    }

    /// EA's anti-cheat as the 2026-10-09 observation found it, beside the EA
    /// app, which the same publisher signs.
    fn ea_like() -> Diff {
        let mut diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\EA\AC\EAAntiCheat.GameService.dll",
            // 190 MB in the real thing: too large to have its signature read.
            r"C:\Program Files\EA\AC\EAAntiCheat.GameService.exe",
            r"C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EABackgroundService.exe",
            r"C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\qml\Settings\plugin.dll",
            r"C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\qml\Universal\plugin.dll",
        ]);
        for file in [
            "GameService.dll",
            "EABackgroundService.exe",
            "Settings\\plugin.dll",
            "Universal\\plugin.dll",
        ] {
            sign_one(&mut diff, file, "Electronic Arts, Inc.");
        }
        diff.services = vec![
            added_service(
                "EAAntiCheatService",
                r#""C:\Program Files\EA\AC\eaanticheat.gameservice.exe""#,
                false,
            ),
            added_service(
                "EABackgroundService",
                r#""C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EABackgroundService.exe""#,
                false,
            ),
        ];
        let mut keys = crate::diff::tests::diff_with_added_registry_keys(&[
            (r"HKLM\SOFTWARE\EA\AC", "64"),
            (r"HKLM\SOFTWARE\EA\AC\Installs\fc26", "32"),
            (
                r"HKCU\SOFTWARE\Classes\Local Settings\MuiCache\2ef\52C64B7E",
                "64",
            ),
            (
                r"HKCU\SOFTWARE\Microsoft\Speech_OneCore\Isolated\x\Universal",
                "64",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\EA Javelin Anticheat",
                "64",
            ),
        ])
        .registry;
        keys.push(registry_service(
            "EAAntiCheat",
            &[
                ("Type", "dword", "2"),
                ("Start", "dword", "3"),
                (
                    "ImagePath",
                    "expand_sz",
                    r"system32\drivers\eaanticheat.sys",
                ),
                ("Description", "sz", "Electronic Arts AntiCheat Driver"),
            ],
        ));
        keys.push(registry_service(
            "EAAntiCheatService",
            &[("Type", "dword", "16"), ("Start", "dword", "3")],
        ));
        diff.registry = keys;
        diff.coverage.captured.push(crate::model::Domain::Registry);
        diff
    }

    #[test]
    fn a_service_binary_beside_a_signed_file_is_attributed() {
        // The service's own image carries no signature the harness could read;
        // the DLL next to it does.
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        assert!(
            generated
                .entry
                .services
                .contains(&"EAAntiCheatService".to_owned())
        );
        assert!(
            generated
                .entry
                .paths
                .iter()
                .any(|entry| entry.path == r"%ProgramFiles%\EA\AC")
        );
    }

    #[test]
    fn the_folders_inside_a_product_identify_nothing() {
        // `Settings` and `Universal` are the EA app's own folders, and used to
        // claim `Local Settings` and the speech platform's keys.
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        for entry in &generated.entry.registry {
            assert!(!entry.key.contains("Local Settings"), "{}", entry.key);
            assert!(!entry.key.contains("Speech_OneCore"), "{}", entry.key);
        }
    }

    #[test]
    fn a_driver_only_the_registry_knows_is_found_named_and_counted() {
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        assert!(matches!(generated.entry.kind, Kind::Kernel));
        assert_eq!(generated.entry.drivers, ["eaanticheat.sys"]);
        assert!(generated.entry.services.contains(&"EAAntiCheat".to_owned()));
        assert!(
            generated
                .review
                .iter()
                .any(|note| note.contains("EAAntiCheat") && note.contains("does not list")),
            "{:#?}",
            generated.review
        );
    }

    #[test]
    fn a_registry_driver_nothing_attributes_is_left_out_and_named() {
        // Neverness To Everness's own driver: no description, an image on a
        // drive that no longer exists, and nothing of the chosen publisher's.
        let mut diff = ea_like();
        diff.registry.push(registry_service(
            "PGameProtectDriver",
            &[
                ("Type", "dword", "1"),
                ("Start", "dword", "3"),
                (
                    "ImagePath",
                    "expand_sz",
                    r"\??\H:\Games\NTE\driver\PGameProtectDriver_X64.sys",
                ),
            ],
        ));

        let generated = draft(&diff, None, Some("Electronic Arts, Inc."));

        assert!(
            !generated
                .entry
                .services
                .contains(&"PGameProtectDriver".to_owned())
        );
        assert!(
            generated
                .review
                .iter()
                .any(|note| note.contains("PGameProtectDriver") && note.contains("left out"))
        );
    }

    #[test]
    fn only_narrows_a_draft_to_one_product() {
        let generated = draft_scoped(
            &ea_like(),
            None,
            Some("Electronic Arts, Inc."),
            &["eaanticheat".to_owned(), r"ea\ac".to_owned()],
        );

        assert_eq!(
            generated.entry.services,
            ["EAAntiCheatService", "EAAntiCheat"]
        );
        let paths: Vec<&str> = generated
            .entry
            .paths
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(paths, [r"%ProgramFiles%\EA\AC"]);
    }

    #[test]
    fn several_products_under_one_signer_are_pointed_out() {
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        assert!(
            generated
                .review
                .iter()
                .any(|note| note.contains("separate product folders") && note.contains("--only")),
            "{:#?}",
            generated.review
        );
    }

    #[test]
    fn a_key_covers_the_views_of_everything_folded_into_it() {
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        let entry = generated
            .entry
            .registry
            .iter()
            .find(|entry| entry.key == r"HKLM\SOFTWARE\EA\AC")
            .expect("the vendor key mirrors the product folder");
        assert!(matches!(entry.view, View::Both));
    }

    #[test]
    fn an_event_source_nothing_attributes_is_named_not_dropped() {
        let generated = draft(&ea_like(), None, Some("Electronic Arts, Inc."));

        assert!(generated.entry.event_sources.is_empty());
        assert!(
            generated
                .review
                .iter()
                .any(|note| note.contains("EA Javelin Anticheat"))
        );
    }

    #[test]
    fn publisher_names_lose_their_corporate_suffixes() {
        assert_eq!(
            publisher_name("Electronic Arts, Inc.").as_deref(),
            Some("electronic arts")
        );
        assert_eq!(
            publisher_name("ACEVILLE PTE LTD").as_deref(),
            Some("aceville")
        );
        assert_eq!(
            publisher_name("N2E Entertainment PTE. LTD.").as_deref(),
            Some("n2e entertainment")
        );
        assert_eq!(publisher_name("Taco").as_deref(), Some("taco"));
        assert_eq!(publisher_name("EA Inc").as_deref(), None);
    }

    #[test]
    fn a_product_folder_is_found_below_its_root() {
        assert_eq!(
            below_root(r"c:\program files\ea\ac\x.exe"),
            ["ea", "ac", "x.exe"]
        );
        assert_eq!(
            below_root(r"c:\users\someone\appdata\local\riot games\x"),
            ["riot games", "x"]
        );
        assert_eq!(
            below_root(r"c:\windows\system32\drivers\vgk.sys"),
            ["vgk.sys"]
        );
        assert_eq!(below_root(r"d:\games\nte\x"), ["games", "nte", "x"]);
    }

    #[test]
    fn an_unattributable_service_or_driver_is_left_out_and_named() {
        // The ACE-ADVT shape: a driver attestation-signed by Microsoft, in
        // System32\drivers, with no copy anywhere the publisher's files are —
        // next to the publisher's own service. And an unrelated driver Windows
        // Update happened to drop between the two snapshots.
        let mut diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\AntiCheatExpert\ACE-Service64.exe",
            r"C:\WINDOWS\system32\drivers\ACE-ADVT.sys",
            r"C:\WINDOWS\system32\drivers\netadapter-update.sys",
        ]);
        sign_one(&mut diff, "ACE-Service64.exe", "ACEVILLE PTE LTD");
        diff.services = vec![
            added_service(
                "AntiCheatExpert Protection",
                r#""C:\Program Files\AntiCheatExpert\ACE-Service64.exe""#,
                false,
            ),
            added_service(
                "ACE-ADVT",
                r"\??\C:\WINDOWS\system32\drivers\ACE-ADVT.sys",
                true,
            ),
        ];

        let generated = draft(&diff, None, Some("ACEVILLE PTE LTD"));

        assert_eq!(generated.entry.services, vec!["AntiCheatExpert Protection"]);
        assert!(
            generated.entry.drivers.is_empty(),
            "{:?}",
            generated.entry.drivers
        );
        assert!(matches!(generated.entry.kind, Kind::Usermode));
        let notes = generated.review.join("\n");
        assert!(
            notes.contains("KERNEL DRIVER service `ACE-ADVT`"),
            "{notes}"
        );
        assert!(notes.contains("netadapter-update.sys"), "{notes}");
        // The kind note must not claim no driver was seen.
        assert!(!notes.contains("no driver was observed"), "{notes}");
        assert!(
            notes.contains("a driver *was* added and left out"),
            "{notes}"
        );
    }

    #[test]
    fn a_driver_copied_from_the_publishers_directory_is_attributed() {
        // A driver shipped under the product directory and installed into
        // System32\drivers is the same file under two paths.
        let mut diff = crate::diff::tests::diff_with_added_files(&[
            r"C:\Program Files\Example AC\example.exe",
            r"C:\Program Files\Example AC\Drivers\example-core.sys",
            r"C:\WINDOWS\system32\drivers\example-core.sys",
        ]);
        sign_one(&mut diff, "example.exe", "Example Vendor");
        diff.services = vec![added_service(
            "ExampleCore",
            r"\??\C:\WINDOWS\system32\drivers\example-core.sys",
            true,
        )];

        let generated = draft(&diff, None, Some("Example Vendor"));

        assert_eq!(generated.entry.services, vec!["ExampleCore"]);
        assert_eq!(generated.entry.drivers, vec!["example-core.sys"]);
        assert!(matches!(generated.entry.kind, Kind::Kernel));
    }

    #[test]
    fn a_wow64_alias_folds_into_the_32_bit_view() {
        let mut review: Vec<String> = Vec::new();
        let diff = crate::diff::tests::diff_with_added_registry_keys(&[
            (r"HKLM\SOFTWARE\Example AC", "32"),
            (r"HKLM\SOFTWARE\WOW6432Node\Example AC", "64"),
        ]);
        let attribution = Attribution {
            tokens: std::iter::once("example ac".to_owned()).collect(),
            ..Attribution::default()
        };

        let entries = registry_entries(&diff, &attribution, &Exceptions::none(), &mut review);

        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].key, r"HKLM\SOFTWARE\Example AC");
        assert_eq!(entries[0].view, View::Bits32);
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

    /// The committed Riot Vanguard install diff, exactly as `suggest` read it.
    const VANGUARD_INSTALL_DIFF: &str =
        include_str!("../../../observations/2026-08-19-riot-vanguard/install.json");

    /// The draft committed alongside that diff.
    const VANGUARD_DRAFT: &str =
        include_str!("../../../observations/2026-08-19-riot-vanguard/draft.toml");

    /// The committed EA AntiCheat install diff, the first taken from a clean
    /// baseline.
    const EA_INSTALL_DIFF: &str =
        include_str!("../../../observations/2026-10-09-ea-anticheat/install.json");

    /// The draft committed alongside it.
    const EA_DRAFT: &str = include_str!("../../../observations/2026-10-09-ea-anticheat/draft.toml");

    /// The committed `AntiCheatExpert` install diff, by a second title.
    const ACE_INSTALL_DIFF: &str =
        include_str!("../../../observations/2026-10-10-anticheatexpert/install.json");

    /// The draft committed alongside it.
    const ACE_INSTALL_DRAFT: &str =
        include_str!("../../../observations/2026-10-10-anticheatexpert/draft.toml");

    /// The committed `AntiCheatExpert` diff, which runs from installed to
    /// uninstalled.
    const ACE_REMOVAL_DIFF: &str =
        include_str!("../../../observations/2026-08-19-anticheatexpert/residue.json");

    /// The draft committed alongside it.
    const ACE_DRAFT: &str =
        include_str!("../../../observations/2026-08-19-anticheatexpert/draft.toml");

    /// The timestamp a committed draft records on its first line.
    fn generated_utc(draft: &str) -> &str {
        draft
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("# DRAFT — generated "))
            .expect("the committed draft starts with its generation line")
    }

    #[test]
    fn the_committed_vanguard_draft_is_reproducible_from_its_committed_diff() {
        // A committed draft nobody can rebuild is an assertion, not evidence.
        // A change to the differ or to this generator that alters the draft
        // fails here, where it has to be explained, instead of leaving a
        // committed artefact nobody can reproduce.
        let diff: Diff =
            serde_json::from_str(VANGUARD_INSTALL_DIFF).expect("the committed install diff parses");

        let rendered = to_toml(
            &draft(&diff, None, Some("Riot Games, Inc.")),
            generated_utc(VANGUARD_DRAFT),
        )
        .expect("the draft serialises");

        assert_eq!(rendered, VANGUARD_DRAFT);
    }

    #[test]
    fn the_committed_anticheatexpert_draft_is_reproducible_from_its_committed_diff() {
        // Its first draft came from that diff reversed by a script nobody
        // kept. `suggest --removed` reads it the other way round instead, and
        // this is what it makes of it.
        let diff: Diff =
            serde_json::from_str(ACE_REMOVAL_DIFF).expect("the committed removal diff parses");

        let rendered = to_toml(
            &draft(
                &crate::diff::reversed(&diff),
                None,
                Some("ACEVILLE PTE LTD"),
            ),
            generated_utc(ACE_DRAFT),
        )
        .expect("the draft serialises");

        assert_eq!(rendered, ACE_DRAFT);
    }

    #[test]
    fn the_committed_anticheatexpert_install_draft_is_reproducible_from_its_committed_diff() {
        // Unscoped: nothing else in an eleven-hour window clustered with ACE,
        // and attestation-signed drivers were attributed by their directory.
        let diff: Diff =
            serde_json::from_str(ACE_INSTALL_DIFF).expect("the committed install diff parses");

        let rendered = to_toml(
            &draft(&diff, None, Some("ACEVILLE PTE LTD")),
            generated_utc(ACE_INSTALL_DRAFT),
        )
        .expect("the draft serialises");

        assert_eq!(rendered, ACE_INSTALL_DRAFT);
    }

    #[test]
    fn the_committed_ea_anticheat_draft_is_reproducible_from_its_committed_diff() {
        // Scoped, because the publisher also signs the EA app the same window
        // installed: the scope is part of what this is a draft of, and a
        // change that moves the EA app back in fails here.
        let diff: Diff =
            serde_json::from_str(EA_INSTALL_DIFF).expect("the committed install diff parses");
        let only = ["eaanticheat", "ea\\ac", "javelin"].map(String::from);

        let rendered = to_toml(
            &draft_scoped(&diff, None, Some("Electronic Arts, Inc."), &only),
            generated_utc(EA_DRAFT),
        )
        .expect("the draft serialises");

        assert_eq!(rendered, EA_DRAFT);
    }
}
