//! The filesystem domain: what is on disk under the roots `docs/16` names.
//!
//! **Portable.** The walk, the hashing and the exclusion rules are all
//! `std::fs` and pure logic, so they are tested on Linux. Only the Authenticode
//! signer lookup needs Win32, and it arrives here through a function pointer —
//! which is also what lets the tests exercise the walk without one.
//!
//! Using `std::fs` rather than raw Win32 is not only convenience. Safety Gate
//! G3 forbids reading a hardware identifier *including for reporting*, and the
//! Win32 metadata structures hand you a volume serial number whether you asked
//! for it or not. Going through `std::fs::Metadata` means the value is never in
//! scope to be recorded by accident.
//!
//! # What is deliberately not hashed
//!
//! Everything under the roots is recorded by path, size and timestamp, which is
//! all a diff needs to notice a file appearing. Contents are hashed only for
//! the extensions an anti-cheat actually ships as, and only below a size cap.
//! Hashing every file under `%ProgramFiles%` on a machine with games installed
//! would read hundreds of gigabytes to answer a question nobody asked.
//!
//! Each skipped file says so individually, in [`FileRecord::not_hashed`]. The
//! rule from `crate::diff` applies here too: a snapshot that quietly omitted
//! something is worse than one that says what it left out.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::model::{AccessDenied, Domain, FileRecord, FilesystemPolicy};

/// Files larger than this are recorded but not hashed.
pub const MAX_HASH_BYTES: u64 = 128 * 1024 * 1024;

/// Extensions whose contents are hashed.
///
/// Anti-cheat ships as a driver, a service executable and its libraries. `.cat`
/// is here because a catalog file is how most of Windows is signed, and its
/// arrival is itself evidence of an install.
pub const HASHED_EXTENSIONS: &[&str] = &[
    "sys", "exe", "dll", "ocx", "drv", "cpl", "scr", "efi", "cat", "msi",
];

/// Path fragments that stop the walk, matched case-insensitively.
///
/// `docs/16-OBSERVATION-HARNESS.md` §"Reducing noise" names most of these.
/// Every one is a directory whose contents change on their own, so including
/// them would bury the install under its own churn — and unlike the service
/// filter, an excluded directory is never walked at all, so it cannot be
/// recovered from the snapshot afterwards. The list is therefore short, names
/// caches rather than applications, and is recorded in the snapshot.
pub const EXCLUDED_FRAGMENTS: &[&str] = &[
    // Windows servicing and defence, both of which version their own directories.
    "\\windows defender\\platform\\",
    "\\softwaredistribution\\",
    "\\windows\\servicing\\",
    "\\windows\\winsxs\\",
    "\\windows\\assembly\\",
    // Per-user and per-machine caches. The temp directories are named
    // precisely rather than as a bare backslash-temp-backslash fragment: a
    // game is entitled to keep its own SomeGame\Temp\, and excluding that
    // would hide part of the very footprint this exists to find.
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\inetcache\\",
    "\\webcache\\",
    "\\crashdumps\\",
    "\\usoshared\\logs\\",
    "\\d3dscache\\",
    "\\dxcache\\",
    "\\nv_cache\\",
    "\\gluecache\\",
    "\\shadercache\\",
    // Browsers keep their profiles under the roots we walk.
    "\\google\\chrome\\user data\\",
    "\\microsoft\\edge\\user data\\",
    "\\mozilla\\firefox\\profiles\\",
    "\\bravesoftware\\",
    // Package and build caches.
    "\\npm-cache\\",
    "\\node_modules\\",
    "\\.cargo\\registry\\",
    "\\pip\\cache\\",
    "\\nuget\\packages\\",
    // Store app data, which is large and churns without an installer involved.
    "\\packages\\",
];

/// How the walk finds a file's Authenticode signer.
///
/// A function pointer rather than a direct call, so the walk stays portable and
/// the tests can run it with no signer at all.
pub type SignerLookup = fn(&Path) -> Option<String>;

/// A signer lookup that finds nothing, so the walk can be tested without one.
#[cfg(test)]
#[must_use]
fn no_signer(_path: &Path) -> Option<String> {
    None
}

/// Everything the filesystem collector returns.
pub struct Captured {
    /// The files found.
    pub files: Vec<FileRecord>,
    /// Directories and files that could not be read.
    pub access_denied: Vec<AccessDenied>,
    /// What the walk was told to do.
    pub policy: FilesystemPolicy,
    /// Directories holding no file anywhere beneath them, topmost only.
    ///
    /// See [`crate::model::Snapshot::file_empty_directories`] for why a file
    /// list alone cannot see the residue this catches.
    pub file_empty_directories: Vec<String>,
}

/// Walk a set of roots.
///
/// Never follows a reparse point. A junction under `%ProgramData%` pointing at
/// `%ProgramFiles%` would otherwise be walked twice under two names, and a
/// junction pointing at its own ancestor would not terminate at all. The
/// adversarial path table in `docs/12-TESTING-STRATEGY.md` exists because this
/// class of thing is easy to get wrong.
pub fn walk(roots: &[PathBuf], signer: SignerLookup) -> Captured {
    let policy = FilesystemPolicy {
        roots: roots
            .iter()
            .map(|root| root.to_string_lossy().into_owned())
            .collect(),
        excluded: EXCLUDED_FRAGMENTS
            .iter()
            .map(|fragment| (*fragment).to_owned())
            .collect(),
        hashed_extensions: HASHED_EXTENSIONS
            .iter()
            .map(|extension| (*extension).to_owned())
            .collect(),
        max_hash_bytes: MAX_HASH_BYTES,
    };

    let mut pending: Vec<(PathBuf, std::fs::Metadata)> = Vec::new();
    let mut access_denied = Vec::new();
    let mut queue: VecDeque<PathBuf> = roots.iter().cloned().collect();
    // Every directory the walk actually read, and the subset that turned out to
    // hold a file. A directory that could not be read enters neither: an
    // unreadable directory is not an empty one, and reporting it as emptied
    // residue would be inventing evidence.
    let mut read_directories: Vec<PathBuf> = Vec::new();
    let mut holds_a_file: HashSet<PathBuf> = HashSet::new();

    while let Some(directory) = queue.pop_front() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                // Recorded, never skipped. A directory that could not be read is
                // not a directory that is empty, and the diff must be able to
                // tell the two apart.
                access_denied.push(AccessDenied {
                    domain: Domain::Filesystem,
                    item: directory.to_string_lossy().into_owned(),
                    reason: error.to_string(),
                });
                continue;
            }
        };

        let mut holds_any_file = false;
        for entry in entries.flatten() {
            let path = entry.path();
            if is_excluded(&path) {
                continue;
            }

            // symlink_metadata, not metadata: it describes the link itself
            // rather than following it.
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    access_denied.push(AccessDenied {
                        domain: Domain::Filesystem,
                        item: path.to_string_lossy().into_owned(),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                // Reparse point. Recorded as an item we chose not to follow, so
                // its absence from the walk is visible rather than silent.
                access_denied.push(AccessDenied {
                    domain: Domain::Filesystem,
                    item: path.to_string_lossy().into_owned(),
                    reason: "reparse point, not traversed".to_owned(),
                });
                continue;
            }

            if metadata.is_dir() {
                queue.push_back(path);
                continue;
            }

            holds_any_file = true;
            pending.push((path, metadata));
        }

        // Once per directory rather than once per file: this loop runs 714 000
        // times on the development machine and the set only needs to know that
        // the answer is yes.
        if holds_any_file {
            holds_a_file.insert(directory.clone());
        }
        read_directories.push(directory);
    }

    let file_empty_directories = file_empty_roots(&read_directories, &holds_a_file);

    // Directory enumeration stays serial — it is a work queue, and the cost is
    // in the leaves rather than the walk. Hashing and the signer lookup are
    // where the time goes: each opens and reads a file, and on this machine
    // that is 124k of them. Serially it took eight and a half minutes.
    let mut files: Vec<FileRecord> = pending
        .par_iter()
        .map(|(path, metadata)| record(path, metadata.len(), metadata, signer))
        .collect();

    files.sort_by(|a, b| a.path.cmp(&b.path));
    access_denied.sort_by(|a, b| a.item.cmp(&b.item));

    Captured {
        files,
        access_denied,
        policy,
        file_empty_directories,
    }
}

/// The topmost directories that hold no file anywhere beneath them.
///
/// `holds_a_file` names directories with a file directly in them. Marking every
/// ancestor of each turns that into "has a file somewhere below", and what is
/// left over is empty scaffolding. Only the top of each such chain is returned:
/// an empty `Logs` inside an empty `Riot Vanguard` is one finding, not two.
fn file_empty_roots(read: &[PathBuf], holds_a_file: &HashSet<PathBuf>) -> Vec<String> {
    let mut has_files_below: HashSet<&Path> = HashSet::new();
    for directory in holds_a_file {
        let mut current = Some(directory.as_path());
        while let Some(path) = current {
            if !has_files_below.insert(path) {
                // Already marked, so its ancestors were marked at the same time
                // by whichever descendant got here first. Nothing above is left
                // to do.
                break;
            }
            current = path.parent();
        }
    }

    let read_set: HashSet<&Path> = read.iter().map(PathBuf::as_path).collect();
    let mut roots: Vec<String> = read
        .iter()
        .filter(|directory| !has_files_below.contains(directory.as_path()))
        .filter(|directory| {
            directory
                .parent()
                .is_none_or(|parent| !read_set.contains(parent) || has_files_below.contains(parent))
        })
        .map(|directory| directory.to_string_lossy().into_owned())
        .collect();
    roots.sort();
    roots
}

fn record(
    path: &Path,
    size: u64,
    metadata: &std::fs::Metadata,
    signer: SignerLookup,
) -> FileRecord {
    let modified_utc = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| crate::clock::from_unix_millis(since.as_millis()))
        .unwrap_or_default();

    let mut sha256 = None;
    let mut not_hashed = None;

    if should_hash(path) {
        if size > MAX_HASH_BYTES {
            not_hashed = Some(format!(
                "{size} bytes exceeds the {MAX_HASH_BYTES} byte cap"
            ));
        } else {
            match hash(path) {
                Ok(digest) => sha256 = Some(digest),
                Err(error) => not_hashed = Some(error.to_string()),
            }
        }
    }
    // Deliberately nothing in the `else`. Recording "not an extension we hash"
    // on every one of the 600k files that are not is half a megabyte of
    // identical strings restating what `FilesystemPolicy::hashed_extensions`
    // already says once. `not_hashed` is reserved for the cases the policy does
    // *not* explain: a file too large, or one that would not open.

    FileRecord {
        path: path.to_string_lossy().into_owned(),
        size,
        modified_utc,
        // Only ask about files whose contents were interesting enough to hash;
        // the lookup opens and parses the file, and running it over every asset
        // in a game directory would cost far more than it tells us.
        signer: if sha256.is_some() { signer(path) } else { None },
        sha256,
        not_hashed,
    }
}

/// Whether a path falls inside an excluded fragment.
#[must_use]
pub fn is_excluded(path: &Path) -> bool {
    let lowered = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\");
    // A trailing separator lets a directory match the fragment that names it,
    // so `…\Temp` is excluded and not only `…\Temp\something`.
    let with_separator = format!("{lowered}\\");
    EXCLUDED_FRAGMENTS
        .iter()
        .any(|fragment| with_separator.contains(fragment))
}

/// Whether a file's contents are hashed under the shipped policy.
#[must_use]
pub fn should_hash(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            let lowered = extension.to_ascii_lowercase();
            HASHED_EXTENSIONS.contains(&lowered.as_str())
        })
}

fn hash(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    // Fixed buffer rather than reading the file into memory: a 128 MB cap on
    // hashing is not a licence to allocate 128 MB.
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_policy_extensions_are_hashed() {
        assert!(should_hash(Path::new("C:\\x\\vgk.sys")));
        assert!(should_hash(Path::new("C:\\x\\vgc.EXE")));
        assert!(should_hash(Path::new("C:\\x\\lib.Dll")));
        assert!(!should_hash(Path::new("C:\\x\\texture.pak")));
        assert!(!should_hash(Path::new("C:\\x\\README")));
    }

    #[test]
    fn excluded_fragments_match_case_insensitively_and_on_either_separator() {
        assert!(is_excluded(Path::new(
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\x.dll"
        )));
        assert!(is_excluded(Path::new(
            "C:/Users/x/AppData/Local/Temp/y.exe"
        )));
        assert!(is_excluded(Path::new(
            "C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\z"
        )));
    }

    #[test]
    fn a_directory_named_by_a_fragment_is_itself_excluded() {
        // Without the trailing separator the fragment `\temp\` would miss the
        // directory it names and only exclude what is inside it, so the walk
        // would descend into it anyway.
        assert!(is_excluded(Path::new("C:\\Users\\x\\AppData\\Local\\Temp")));
    }

    #[test]
    fn an_anti_cheat_path_is_never_excluded() {
        // The failure that matters: a noise rule swallowing the thing we came
        // for. `\Packages\` is on the list, and `Riot Vanguard` must not brush
        // against it.
        assert!(!is_excluded(Path::new(
            "C:\\Program Files\\Riot Vanguard\\vgk.sys"
        )));
        assert!(!is_excluded(Path::new(
            "C:\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe"
        )));
        assert!(!is_excluded(Path::new(
            "C:\\WINDOWS\\system32\\drivers\\ACE-BASE.sys"
        )));
    }

    #[test]
    fn walking_a_tree_records_sizes_hashes_and_the_policy() {
        // Not the system temp directory: that is on the exclusion list, so a
        // tree built there would be correctly skipped and the test would be
        // asserting against an empty walk.
        let temporary = tempfile::Builder::new()
            .prefix("ws-observe-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let root = temporary.path().to_path_buf();
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("driver.sys"), b"contents").unwrap();
        std::fs::write(nested.join("asset.pak"), b"not hashed").unwrap();

        let captured = walk(std::slice::from_ref(&root), no_signer);

        let driver = captured
            .files
            .iter()
            .find(|file| file.path.ends_with("driver.sys"))
            .expect("the driver should have been found");
        assert_eq!(driver.size, 8);
        assert_eq!(
            driver.sha256.as_deref(),
            // SHA-256 of "contents".
            Some("d1b2a59fbea7e20077af9f91b27e95e865061b270be03ff539ab3b73587882e8")
        );
        assert!(driver.not_hashed.is_none());

        let asset = captured
            .files
            .iter()
            .find(|file| file.path.ends_with("asset.pak"))
            .expect("the asset should have been found");
        assert!(asset.sha256.is_none());
        // The policy already says which extensions are hashed, so an ordinary
        // skip carries no per-file reason.
        assert!(asset.not_hashed.is_none());

        assert_eq!(captured.policy.max_hash_bytes, MAX_HASH_BYTES);
        assert!(!captured.policy.excluded.is_empty());
    }

    #[test]
    fn an_emptied_directory_is_reported_and_only_its_topmost() {
        // The shape Riot Vanguard's uninstaller leaves: the files are gone, the
        // directory that held them and its `Logs` child are not.
        let temporary = tempfile::Builder::new()
            .prefix("ws-observe-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let root = temporary.path().to_path_buf();
        let leftover = root.join("Riot Vanguard");
        std::fs::create_dir_all(leftover.join("Logs")).unwrap();
        let occupied = root.join("Something Else");
        std::fs::create_dir_all(&occupied).unwrap();
        std::fs::write(occupied.join("still-here.sys"), b"contents").unwrap();

        let captured = walk(std::slice::from_ref(&root), no_signer);

        let empty = &captured.file_empty_directories;
        assert!(
            empty.iter().any(|d| d.ends_with("Riot Vanguard")),
            "the emptied directory should be reported: {empty:?}"
        );
        assert!(
            !empty.iter().any(|d| d.ends_with("Logs")),
            "an empty child of an empty parent is one finding, not two: {empty:?}"
        );
        assert!(
            !empty.iter().any(|d| d.ends_with("Something Else")),
            "a directory with a file in it is not empty: {empty:?}"
        );
        // The root has a file below it, through `Something Else`, so it is not
        // itself scaffolding.
        assert!(
            !empty.iter().any(|d| d.as_str() == root.to_string_lossy()),
            "a root with files somewhere below it is not empty: {empty:?}"
        );
    }

    #[test]
    fn an_applications_own_temp_directory_is_not_excluded() {
        // The first version of this list carried a bare temp fragment. It
        // excluded the system temp directories as intended, and also every
        // application keeping its own — a chunk of footprint silently missing,
        // which the walk cannot recover afterwards because an excluded
        // directory is never read at all.
        assert!(!is_excluded(Path::new(
            "C:\\Program Files\\SomeGame\\Temp\\staging.pak"
        )));
        assert!(!is_excluded(Path::new(
            "C:\\ProgramData\\Vendor\\TempData\\x.dll"
        )));
        // But the real ones still are.
        assert!(is_excluded(Path::new(
            "C:\\Users\\x\\AppData\\Local\\Temp\\y.exe"
        )));
        assert!(is_excluded(Path::new("C:\\Windows\\Temp\\z.dll")));
    }

    #[test]
    fn an_unreadable_root_is_recorded_rather_than_ignored() {
        let temporary = tempfile::Builder::new()
            .prefix("ws-observe-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let missing = temporary.path().join("does-not-exist-9f3a");
        let captured = walk(std::slice::from_ref(&missing), no_signer);

        assert!(captured.files.is_empty());
        assert_eq!(captured.access_denied.len(), 1);
        assert_eq!(captured.access_denied[0].domain, Domain::Filesystem);
    }
}
