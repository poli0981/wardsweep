//! `wardsweep scan` as it is run: the built binary, the signed catalog this
//! repository ships, and the machine the tests run on.
//!
//! The shipped catalog has no entries, so these check the command's contract —
//! where output goes, what it exits with — rather than what it finds; the
//! engine's own tests and `core/tests/win_machine.rs` cover that.

use std::path::PathBuf;
use std::process::{Command, Output};

fn wardsweep(args: &[&str], catalog: Option<PathBuf>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wardsweep"));
    command.args(args);
    if let Some(catalog) = catalog {
        command.arg("--catalog").arg(catalog);
    }
    command.output().expect("wardsweep runs")
}

#[cfg(windows)]
fn shipped_catalog() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("catalog")
        .join("catalog.toml")
}

/// A scratch file under the target directory, which Cargo gives integration
/// tests for this.
fn scratch(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

#[cfg(windows)]
#[test]
fn an_empty_catalog_finds_nothing_and_says_so() {
    let output = wardsweep(&["scan"], Some(shipped_catalog()));

    // Nothing found, or partial if this machine denied the scan something.
    assert!(matches!(output.status.code(), Some(1 | 3)), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("0 finding(s)"), "{text}");
}

#[cfg(windows)]
#[test]
fn json_goes_to_stdout_or_to_the_file_named_and_the_verdict_to_stderr() {
    let output = wardsweep(&["scan", "--json"], Some(shipped_catalog()));
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
        .collect();
    let summary = lines.last().expect("a summary line");
    assert_eq!(summary["v"], 1);
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["findings"], 0);
    assert!(String::from_utf8_lossy(&output.stderr).contains("0 finding(s)"));

    let file = scratch("scan.ndjson");
    let path = file.to_string_lossy().into_owned();
    let output = wardsweep(&["scan", "--json", "-o", &path], Some(shipped_catalog()));
    assert!(output.stdout.is_empty(), "{output:?}");
    let written = std::fs::read_to_string(&file).expect("the report was written");
    assert!(written.ends_with('\n'));
    assert!(written.contains("\"type\":\"summary\""), "{written}");
}

#[test]
fn orphan_and_full_are_refused_until_reference_counting_exists() {
    for mode in ["orphan", "full"] {
        let output = wardsweep(&["scan", "--mode", mode], None);

        assert_eq!(output.status.code(), Some(64), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("reference counting"));
    }
}

#[test]
fn a_scan_with_no_catalog_is_an_error_not_nothing_found() {
    let output = wardsweep(&["scan"], Some(scratch("no-such-catalog.toml")));

    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
