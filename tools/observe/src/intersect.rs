//! What several footprints have in common.
//!
//! `docs/16-OBSERVATION-HARNESS.md` §"Multi-title observation": for a shared
//! anti-cheat, observe at least three titles from different launchers. What
//! every footprint contains is the anti-cheat itself; what only some contain is
//! per-title integration. This computes the first set, as a diff, so `suggest`
//! can draft from it like any other.
//!
//! # Matched by identity, never by content
//!
//! A service matches by name, a file by path, a registry key by path and view,
//! all as Windows compares them, without regard to case. Two titles routinely
//! ship different builds of one anti-cheat, so its files differ in hash and its
//! service in image path from one footprint to the next, and matching on
//! content would find nothing shared at all. The record kept is the first
//! footprint's; the others are still in their own diffs.
//!
//! # A footprint that started dirty shrinks the intersection
//!
//! An anti-cheat already installed when a title's earlier snapshot was taken is
//! not in that title's footprint, so it drops out of the intersection. That
//! errs towards too little — a shared footprint missing the anti-cheat's own
//! service is conspicuous — rather than towards claiming one title's files as
//! everyone's.

use std::collections::{BTreeMap, BTreeSet};

use crate::diff::{
    DIFF_FORMAT_VERSION, Diff, FileChange, Footprint, Refiltered, RegistryChange, ServiceChange,
    Suppressed, SuppressedFile, refilter,
};
use crate::model::RegistryKeyRef;
use crate::policy::Policy;

/// Why footprints could not be intersected.
#[derive(Debug, PartialEq, Eq)]
pub enum IntersectError {
    /// Fewer than two footprints. The intersection of one footprint is that
    /// footprint, and calling it shared would claim evidence nobody gathered.
    TooFew(usize),
    /// The footprints come from snapshots of different formats, which name
    /// some registry keys differently and record different things. See
    /// [`crate::model::SNAPSHOT_FORMAT_VERSION`].
    MixedFormats(BTreeSet<u32>),
    /// One footprint was given twice — the same two snapshot times — which
    /// would count one title as two.
    Repeated {
        /// When the repeated footprint's earlier snapshot was taken.
        before_taken_utc: String,
    },
    /// A footprint is itself an intersection. Its titles would be counted
    /// again under its name; intersect the footprints it came from instead.
    Nested,
}

impl std::fmt::Display for IntersectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFew(count) => write!(
                f,
                "an intersection needs at least two footprints, and {count} was given"
            ),
            Self::MixedFormats(formats) => write!(
                f,
                "the footprints come from snapshot formats {formats:?}, which record different \
                 things; intersect footprints whose snapshots were taken with one build"
            ),
            Self::Repeated { before_taken_utc } => write!(
                f,
                "the footprint whose earlier snapshot was taken at {before_taken_utc} was given \
                 more than once, which would count one title as two"
            ),
            Self::Nested => write!(
                f,
                "a footprint is itself an intersection; intersect the footprints it came from \
                 instead, so each title counts once"
            ),
        }
    }
}

impl std::error::Error for IntersectError {}

/// Intersect footprints.
///
/// Each is brought under this build's privacy policy first, so a footprint
/// written by an older build cannot carry what this one refuses into the
/// result. The result's changes are those every footprint holds; its coverage is
/// what every footprint covered, because a domain one footprint never captured
/// cannot be shown to be shared; and [`Diff::intersection_of`] says what it was
/// computed from.
///
/// # Errors
/// If fewer than two footprints are given, one is given twice or is itself an
/// intersection, or their snapshots differ in format.
pub fn intersect(mut footprints: Vec<Diff>) -> Result<Diff, IntersectError> {
    if footprints.len() < 2 {
        return Err(IntersectError::TooFew(footprints.len()));
    }
    if footprints
        .iter()
        .any(|footprint| footprint.intersection_of.is_some())
    {
        return Err(IntersectError::Nested);
    }
    let mut seen = BTreeSet::new();
    for footprint in &footprints {
        if !seen.insert((&footprint.before_taken_utc, &footprint.after_taken_utc)) {
            return Err(IntersectError::Repeated {
                before_taken_utc: footprint.before_taken_utc.clone(),
            });
        }
    }
    let formats: BTreeSet<u32> = footprints
        .iter()
        .map(|footprint| footprint.snapshot_format_version)
        .collect();
    if formats.len() > 1 {
        return Err(IntersectError::MixedFormats(formats));
    }

    let policy = Policy::current();
    let mut refiltered = Refiltered::default();
    for footprint in &mut footprints {
        refilter(footprint, &policy);
        refiltered.absorb(footprint.refiltered);
    }

    let sources: Vec<Footprint> = footprints
        .iter()
        .map(|footprint| Footprint {
            before_taken_utc: footprint.before_taken_utc.clone(),
            after_taken_utc: footprint.after_taken_utc.clone(),
            changes: footprint.services.len()
                + footprint.suppressed.len()
                + footprint.files.len()
                + footprint.suppressed_files.len()
                + footprint.registry.len(),
        })
        .collect();

    let service_sides: Vec<(&[ServiceChange], &[Suppressed])> = footprints
        .iter()
        .map(|footprint| {
            (
                footprint.services.as_slice(),
                footprint.suppressed.as_slice(),
            )
        })
        .collect();
    let (services, suppressed) = shared(&service_sides, service_identity, suppressed_service);

    let file_sides: Vec<(&[FileChange], &[SuppressedFile])> = footprints
        .iter()
        .map(|footprint| {
            (
                footprint.files.as_slice(),
                footprint.suppressed_files.as_slice(),
            )
        })
        .collect();
    let (files, suppressed_files) = shared(&file_sides, file_identity, suppressed_file);

    // The registry has no noise filter, so nothing on that side is suppressed.
    let registry_sides: Vec<(&[RegistryChange], &[RegistryChange])> = footprints
        .iter()
        .map(|footprint| (footprint.registry.as_slice(), &[][..]))
        .collect();
    let (registry, _) = shared(&registry_sides, registry_identity, itself);

    let coverage = footprints[1..]
        .iter()
        .fold(footprints[0].coverage.clone(), |coverage, other| {
            coverage.intersect(&other.coverage)
        });

    let mut signers: BTreeMap<String, usize> = BTreeMap::new();
    for change in &files {
        if let Some(signer) = &change.signer {
            *signers.entry(signer.clone()).or_insert(0) += 1;
        }
    }

    Ok(Diff {
        format_version: DIFF_FORMAT_VERSION,
        snapshot_format_version: footprints[0].snapshot_format_version,
        // The span every footprint falls within. Timestamps are ISO 8601 in UTC,
        // so text order is time order.
        before_taken_utc: footprints
            .iter()
            .map(|footprint| footprint.before_taken_utc.clone())
            .min()
            .unwrap_or_default(),
        after_taken_utc: footprints
            .iter()
            .map(|footprint| footprint.after_taken_utc.clone())
            .max()
            .unwrap_or_default(),
        rebooted_between: rebooted_in_any(&footprints),
        emptied_directories: shared_list(
            footprints
                .iter()
                .map(|footprint| footprint.emptied_directories.as_deref()),
            |directory: &String| folded(directory),
        ),
        emptied_keys: shared_list(
            footprints
                .iter()
                .map(|footprint| footprint.emptied_keys.as_deref()),
            key_identity,
        ),
        coverage,
        services,
        suppressed,
        files,
        suppressed_files,
        registry,
        registry_policy_changed: footprints
            .iter()
            .any(|footprint| footprint.registry_policy_changed),
        filesystem_policy_changed: footprints
            .iter()
            .any(|footprint| footprint.filesystem_policy_changed),
        signers,
        refiltered,
        intersection_of: Some(sources),
    })
}

/// One footprint's changes in one domain, by identity: those the noise filter
/// kept, and those it moved aside.
type Indexed<'a, T, S> = (BTreeMap<String, &'a T>, BTreeMap<String, &'a S>);

/// The changes every footprint holds, by identity.
///
/// A change is suppressed in the result only when every footprint suppressed
/// it. The noise filter is not recorded in a diff, so two footprints may have
/// been made with different ones, and a change present in all of them must not
/// vanish because they disagree about it.
fn shared<T: Clone, S: Clone>(
    sides: &[(&[T], &[S])],
    identity: fn(&T) -> String,
    change_of: fn(&S) -> &T,
) -> (Vec<T>, Vec<S>) {
    let indexed: Vec<Indexed<'_, T, S>> = sides
        .iter()
        .map(|(kept, suppressed)| {
            (
                kept.iter()
                    .map(|change| (identity(change), change))
                    .collect(),
                suppressed
                    .iter()
                    .map(|entry| (identity(change_of(entry)), entry))
                    .collect(),
            )
        })
        .collect();
    let Some((first_kept, first_suppressed)) = indexed.first() else {
        return (Vec::new(), Vec::new());
    };
    let candidates: BTreeSet<&String> = first_kept.keys().chain(first_suppressed.keys()).collect();

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();
    for key in candidates {
        let everywhere = indexed
            .iter()
            .all(|(kept, suppressed)| kept.contains_key(key) || suppressed.contains_key(key));
        if !everywhere {
            continue;
        }
        if let Some(change) = indexed.iter().find_map(|(kept, _)| kept.get(key)) {
            kept.push((*change).clone());
        } else if let Some(entry) = first_suppressed.get(key) {
            suppressed.push((*entry).clone());
        }
    }
    (kept, suppressed)
}

/// Entries of a per-footprint list that every footprint holds, or `None` when
/// any footprint does not know the list at all — the same rule a diff applies
/// to its two snapshots.
fn shared_list<'a, T: Clone + 'a>(
    lists: impl Iterator<Item = Option<&'a [T]>>,
    identity: impl Fn(&T) -> String,
) -> Option<Vec<T>> {
    let lists: Vec<&[T]> = lists.collect::<Option<_>>()?;
    let (first, rest) = lists.split_first()?;
    let others: Vec<BTreeSet<String>> = rest
        .iter()
        .map(|list| list.iter().map(&identity).collect())
        .collect();
    Some(
        first
            .iter()
            .filter(|entry| {
                let key = identity(entry);
                others.iter().all(|other| other.contains(&key))
            })
            .cloned()
            .collect(),
    )
}

/// Whether any footprint spans a restart: `Some(true)` if one does,
/// `Some(false)` only if every one is known not to, `None` otherwise.
fn rebooted_in_any(footprints: &[Diff]) -> Option<bool> {
    let answers: Vec<Option<bool>> = footprints
        .iter()
        .map(|footprint| footprint.rebooted_between)
        .collect();
    if answers.contains(&Some(true)) {
        Some(true)
    } else if answers.iter().all(|answer| *answer == Some(false)) {
        Some(false)
    } else {
        None
    }
}

/// A path, key or service name as Windows compares it.
fn folded(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn service_identity(change: &ServiceChange) -> String {
    folded(&change.name)
}

fn suppressed_service(entry: &Suppressed) -> &ServiceChange {
    &entry.change
}

fn file_identity(change: &FileChange) -> String {
    folded(&change.path)
}

fn suppressed_file(entry: &SuppressedFile) -> &FileChange {
    &entry.change
}

/// Path and view: one key read through the two views is two artifacts, as
/// everywhere else in this harness.
fn registry_identity(change: &RegistryChange) -> String {
    format!("{}\u{0}{}", folded(&change.key), change.view)
}

fn itself(change: &RegistryChange) -> &RegistryChange {
    change
}

fn key_identity(key: &RegistryKeyRef) -> String {
    format!("{}\u{0}{}", folded(&key.key), key.view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::ChangeKind;
    use crate::diff::tests::{diff_with_added_files, diff_with_added_registry_keys};
    use crate::model::Domain;

    const EAC_EXE: &str = r"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe";
    const EAC_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS";

    fn service(name: &str) -> ServiceChange {
        ServiceChange {
            name: name.to_owned(),
            kind: ChangeKind::Added,
            is_driver: false,
            is_boot_start: false,
            before: None,
            after: None,
            fields: Vec::new(),
        }
    }

    /// A footprint covering services, files and the registry.
    ///
    /// Each one is its own observation, with its own snapshot time, as two
    /// titles' footprints would be.
    fn footprint(services: &[&str], files: &[&str], keys: &[(&str, &str)]) -> Diff {
        static TAKEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        let mut diff = diff_with_added_files(files);
        diff.registry = diff_with_added_registry_keys(keys).registry;
        diff.coverage.captured = vec![Domain::Services, Domain::Filesystem, Domain::Registry];
        diff.coverage.not_captured = Domain::all()
            .into_iter()
            .filter(|domain| !diff.coverage.captured.contains(domain))
            .collect();
        diff.services = services.iter().map(|name| service(name)).collect();
        let n = TAKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        diff.after_taken_utc = format!("2026-08-19T01:{:02}:{:02}.000Z", n / 60 % 60, n % 60);
        diff
    }

    #[test]
    fn fewer_than_two_footprints_are_refused() {
        let one = footprint(&["EasyAntiCheat_EOS"], &[], &[]);

        assert!(matches!(
            intersect(vec![one]),
            Err(IntersectError::TooFew(1))
        ));
    }

    #[test]
    fn one_footprint_given_twice_is_refused() {
        let a = footprint(&["EasyAntiCheat_EOS"], &[], &[]);

        // One title is not evidence of sharing, however many times it is named.
        assert!(matches!(
            intersect(vec![a.clone(), a]),
            Err(IntersectError::Repeated { .. })
        ));
    }

    #[test]
    fn an_intersection_is_not_intersected_again() {
        let shared = intersect(vec![footprint(&[], &[], &[]), footprint(&[], &[], &[])]).unwrap();

        assert!(matches!(
            intersect(vec![shared, footprint(&[], &[], &[])]),
            Err(IntersectError::Nested)
        ));
    }

    #[test]
    fn footprints_from_different_snapshot_formats_are_refused() {
        let older = footprint(&[], &[], &[]);
        let mut newer = footprint(&[], &[], &[]);
        newer.snapshot_format_version = older.snapshot_format_version + 1;

        assert!(matches!(
            intersect(vec![older, newer]),
            Err(IntersectError::MixedFormats(_))
        ));
    }

    #[test]
    fn only_what_every_footprint_holds_is_shared() {
        let a = footprint(
            &["EasyAntiCheat_EOS", "GameA"],
            &[EAC_EXE, r"C:\Games\A\EasyAntiCheat\Settings.json"],
            &[(EAC_KEY, "64"), (EAC_KEY, "32")],
        );
        // Another title, another launcher: different case, its own files, and
        // the key seen through one view only.
        let (exe, key) = (EAC_EXE.to_ascii_lowercase(), EAC_KEY.to_ascii_lowercase());
        let b = footprint(
            &["easyanticheat_eos", "GameB"],
            &[&exe, r"D:\Library\B\EasyAntiCheat\Settings.json"],
            &[(&key, "64")],
        );

        let shared = intersect(vec![a, b]).unwrap();

        let names: Vec<&str> = shared.services.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["EasyAntiCheat_EOS"],
            "the first footprint's record is kept"
        );
        let paths: Vec<&str> = shared.files.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, [EAC_EXE]);
        let keys: Vec<(&str, &str)> = shared
            .registry
            .iter()
            .map(|c| (c.key.as_str(), c.view.as_str()))
            .collect();
        assert_eq!(
            keys,
            [(EAC_KEY, "64")],
            "a view is part of a key's identity"
        );
    }

    #[test]
    fn a_change_kept_by_one_footprint_is_never_lost_to_another_ones_filter() {
        let mut a = footprint(&[], &[], &[]);
        let mut b = footprint(&[], &[], &[]);
        a.services.push(service("WinDefend"));
        // Made with the standard filter, which suppresses it.
        b.suppressed.push(Suppressed {
            rule: "volatile-service".to_owned(),
            change: service("WinDefend"),
        });
        let mut c = footprint(&[], &[], &[]);
        c.suppressed.push(Suppressed {
            rule: "volatile-service".to_owned(),
            change: service("WinDefend"),
        });

        let kept_somewhere = intersect(vec![a, b.clone()]).unwrap();
        let suppressed_everywhere = intersect(vec![b, c]).unwrap();

        assert_eq!(kept_somewhere.services.len(), 1);
        assert!(kept_somewhere.suppressed.is_empty());
        assert!(suppressed_everywhere.services.is_empty());
        assert_eq!(suppressed_everywhere.suppressed.len(), 1);
    }

    #[test]
    fn a_domain_one_footprint_never_captured_is_not_covered() {
        let a = footprint(&[], &[EAC_EXE], &[]);
        let mut b = footprint(&[], &[], &[]);
        b.coverage
            .captured
            .retain(|domain| *domain != Domain::Filesystem);
        b.coverage.not_captured.push(Domain::Filesystem);

        let shared = intersect(vec![a, b]).unwrap();

        // Not "no file is shared": one footprint never looked.
        assert!(shared.files.is_empty());
        assert!(!shared.coverage.covers(Domain::Filesystem));
    }

    #[test]
    fn what_this_build_refuses_never_reaches_an_intersection() {
        let account =
            r"HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\someone@example.invalid";
        // Pushed in directly, as a footprint written before the policy existed
        // holds it: `compare` would already have dropped it.
        let older = || {
            let mut diff = footprint(&[], &[], &[(EAC_KEY, "64")]);
            diff.registry.push(RegistryChange {
                key: account.to_owned(),
                view: "64".to_owned(),
                kind: ChangeKind::Added,
                before: None,
                after: Some(crate::model::RegistryRecord {
                    key: account.to_owned(),
                    view: "64".to_owned(),
                    values: Vec::new(),
                }),
                fields: Vec::new(),
            });
            diff
        };

        let shared = intersect(vec![older(), older()]).unwrap();

        let text = serde_json::to_string(&shared).unwrap();
        assert!(!text.contains("someone@example.invalid"), "{text}");
        assert_eq!(shared.registry.len(), 1);
        assert_eq!(
            shared.refiltered.registry_records, 2,
            "counted, never silent"
        );
    }

    #[test]
    fn an_intersection_says_what_it_was_computed_from() {
        let a = footprint(&["EasyAntiCheat_EOS", "GameA"], &[EAC_EXE], &[]);
        let b = footprint(&["EasyAntiCheat_EOS"], &[EAC_EXE], &[]);

        let shared = intersect(vec![a, b]).unwrap();

        let sources = shared.intersection_of.as_ref().unwrap();
        let changes: Vec<usize> = sources.iter().map(|source| source.changes).collect();
        assert_eq!(changes, [3, 2]);
    }

    #[test]
    fn emptied_lists_are_shared_only_when_every_footprint_knows_them() {
        let mut a = footprint(&[], &[], &[]);
        let mut b = footprint(&[], &[], &[]);
        a.emptied_directories = Some(vec![r"C:\Program Files\Vendor".to_owned()]);
        b.emptied_directories = Some(vec![r"c:\program files\vendor".to_owned()]);

        let known = intersect(vec![a.clone(), b.clone()]).unwrap();
        b.emptied_directories = None;
        let unknown = intersect(vec![a, b]).unwrap();

        assert_eq!(
            known.emptied_directories,
            Some(vec![r"C:\Program Files\Vendor".to_owned()])
        );
        assert_eq!(unknown.emptied_directories, None);
    }
}
