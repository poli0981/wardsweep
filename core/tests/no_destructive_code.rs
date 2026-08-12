//! Asserts that this build cannot delete anything.
//!
//! Two rules from `CLAUDE.md` and `docs/19-ROADMAP.md` are enforced here rather
//! than in review:
//!
//! - v0.1 is audit-only: "No removal code exists in the binary."
//! - `std::fs::remove_*` outside the quarantine module is a review blocker.
//!
//! A grep in a reviewer's head is not a mechanism. This is, and it fails loudly
//! the first time someone adds a delete in the wrong place — including in a
//! module that has not been written yet, because the rule is about location
//! rather than about intent.
//!
//! Scope is `src/` only. Test and benchmark code may clean up after itself.

use std::path::{Path, PathBuf};

/// Calls that destroy something, and the reason each is named.
const DESTRUCTIVE: &[(&str, &str)] = &[
    (
        "remove_file",
        "std::fs::remove_file — quarantine module only",
    ),
    (
        "remove_dir",
        "std::fs::remove_dir/remove_dir_all — quarantine module only",
    ),
    (
        "DeleteService",
        "SCM service deletion — exec module only, after a reboot",
    ),
    (
        "ChangeServiceConfig",
        "service reconfiguration — exec module only",
    ),
    ("ControlService", "service stop/control — exec module only"),
    (
        "RegDeleteKey",
        "registry deletion — quarantine module only, after a .reg export",
    ),
    (
        "RegDeleteValue",
        "registry deletion — quarantine module only",
    ),
    ("RegSetValue", "registry write — exec module only"),
    (
        "MoveFileEx",
        "delayed rename; must append to PendingFileRenameOperations",
    ),
    (
        "SetFileAttributes",
        "attribute change — quarantine module only",
    ),
    ("TerminateProcess", "forbidden outright by Safety Gate G2"),
    ("NtUnloadDriver", "forbidden outright by Safety Gate G2"),
];

/// Modules permitted to contain destructive calls once they are written.
///
/// Empty today, and that is the point: the whole tree is covered.
const PERMITTED: &[&str] = &["core/src/quar/", "core/src/exec/"];

/// Hardware identifiers Safety Gate G3 forbids reading or writing.
///
/// G3 is unusual in that it bans *reads* too, so a scanner that merely
/// enumerated them for a report would already be a violation.
const HARDWARE_IDENTITY: &[&str] = &[
    "MachineGuid",
    "SMBIOS",
    "Win32_ComputerSystemProduct",
    "GetVolumeInformation",
    "IOCTL_STORAGE_QUERY_PROPERTY",
    "GetAdaptersAddresses",
    "Tbsi_",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core/ has a parent")
        .to_path_buf()
}

/// Every `.rs` file under a `src/` directory in the workspace.
fn shipped_sources() -> Vec<PathBuf> {
    let root = repo_root();
    let roots = [
        root.join("core/src"),
        root.join("cli/src"),
        root.join("tools/catalog/src"),
        root.join("tools/observe/src"),
    ];

    let mut files = Vec::new();
    for dir in roots {
        collect(&dir, &mut files);
    }
    assert!(!files.is_empty(), "found no source files to check");
    files
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn relative(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn no_destructive_call_exists_outside_the_modules_allowed_to_have_one() {
    let mut offences = Vec::new();

    for file in shipped_sources() {
        let relative = relative(&file);
        if PERMITTED
            .iter()
            .any(|allowed| relative.starts_with(allowed))
        {
            continue;
        }
        // This file names every forbidden call in order to look for them.
        if relative.contains("/tests/") {
            continue;
        }

        let text = std::fs::read_to_string(&file).expect("source file should be readable");
        for (line_number, line) in text.lines().enumerate() {
            // Comments and doc comments discuss these calls constantly; the
            // rule is about code.
            let code = line.split("//").next().unwrap_or(line);
            for (needle, reason) in DESTRUCTIVE {
                if code.contains(needle) {
                    offences.push(format!(
                        "{relative}:{}: `{needle}` — {reason}",
                        line_number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "destructive calls found outside the permitted modules:\n  {}",
        offences.join("\n  ")
    );
}

#[test]
fn nothing_reads_a_hardware_identifier() {
    let mut offences = Vec::new();

    for file in shipped_sources() {
        let relative = relative(&file);
        let text = std::fs::read_to_string(&file).expect("source file should be readable");
        for (line_number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            for needle in HARDWARE_IDENTITY {
                if code.contains(needle) {
                    offences.push(format!("{relative}:{}: `{needle}`", line_number + 1));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "Safety Gate G3 forbids reading or writing hardware identity, including \
         for reporting:\n  {}",
        offences.join("\n  ")
    );
}
