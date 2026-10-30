//! The machine view over Win32, against the machine the tests run on.
//!
//! The always-on tests read what every Windows has — the event log service,
//! the TCP/IP driver's key, `CurrentVersion` — so they hold on a developer's
//! machine and on a CI runner alike. The ignored one audits this machine with
//! the drafts the observation cycles committed and prints what it found; what
//! that is depends on what is installed, so it checks only what holds anywhere:
//!
//! ```text
//! cargo test -p wardsweep-core --test win_machine -- --ignored --nocapture
//! ```
#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use wardsweep_core::catalog::{self, Catalog};
use wardsweep_core::scan::engine::audit;
use wardsweep_core::scan::model::{Classification, RegView};
use wardsweep_core::scan::view::{Lookup, MachineView, PathKind};
use wardsweep_core::scan::win::{Machine, environment};

#[test]
fn a_service_every_windows_has_is_found_and_one_nobody_has_is_absent() {
    match Machine.service("EventLog") {
        Lookup::Found(status) => {
            assert!(!status.stale);
            assert!(!status.image.is_empty(), "{status:?}");
        }
        other => panic!("EventLog: {other:?}"),
    }
    assert_eq!(
        Machine.service("WardSweepTestNoSuchService"),
        Lookup::Absent
    );
    assert_eq!(
        Machine.service_key("WardSweepTestNoSuchService"),
        Lookup::Absent
    );
}

#[test]
fn driver_keys_come_from_the_services_key() {
    let Lookup::Found(found) = Machine.driver_keys() else {
        panic!("the Services key could not be listed");
    };
    let tcpip = found
        .drivers
        .iter()
        .find(|key| key.name.eq_ignore_ascii_case("Tcpip"))
        .expect("every Windows registers the TCP/IP driver");
    assert!(tcpip.is_driver());
    assert!(
        tcpip.image.to_ascii_lowercase().ends_with("tcpip.sys"),
        "{tcpip:?}"
    );
    // Services are not drivers.
    assert!(
        !found
            .drivers
            .iter()
            .any(|key| key.name.eq_ignore_ascii_case("EventLog"))
    );
}

#[test]
fn a_key_is_looked_for_in_the_view_it_names() {
    let key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
    assert_eq!(
        Machine.registry_key(key, RegView::Bits64),
        Lookup::Found(())
    );
    assert_eq!(
        Machine.registry_key(key, RegView::Bits32),
        Lookup::Found(())
    );
    assert_eq!(
        Machine.registry_key(
            "HKLM\\SOFTWARE\\WardSweep Test No Such Key",
            RegView::Bits64
        ),
        Lookup::Absent
    );
}

#[test]
fn a_link_is_described_and_never_followed() {
    let folder = tempfile::tempdir().expect("a temporary folder");
    let target = folder.path().join("target");
    std::fs::create_dir(&target).expect("the link's target");
    std::fs::write(target.join("inside.txt"), b"x").expect("a file behind the link");
    let link = folder.path().join("link");
    // A junction needs no privilege, unlike a symbolic link.
    let made = Command::new("cmd")
        .arg("/c")
        .arg("mklink")
        .arg("/J")
        .arg(&link)
        .arg(&target)
        .output()
        .expect("cmd runs");
    assert!(made.status.success(), "{made:?}");

    let text = |path: &Path| path.to_string_lossy().into_owned();
    assert_eq!(
        Machine.path(&text(&link)),
        Lookup::Found(PathKind::ReparsePoint)
    );
    assert_eq!(
        Machine.path(&text(&target)),
        Lookup::Found(PathKind::Directory)
    );
    assert_eq!(
        Machine.path(&text(&target.join("inside.txt"))),
        Lookup::Found(PathKind::File)
    );
    assert_eq!(
        Machine.path(&text(&folder.path().join("absent"))),
        Lookup::Absent
    );
}

#[test]
fn the_environment_answers_every_placeholder_the_catalog_knows() {
    let environment = environment();
    for name in wardsweep_core::catalog::expand::KNOWN_VARIABLES {
        assert!(environment.lookup(name).is_some(), "{name} has no entry");
    }
    let root = environment
        .lookup("SystemRoot")
        .and_then(|values| values.into_iter().next())
        .expect("SystemRoot is set");
    assert_eq!(Machine.path(&root), Lookup::Found(PathKind::Directory));
}

/// The drafts the observation cycles committed, each with the header a catalog
/// needs, as one catalog.
fn drafts() -> Catalog {
    let header = "schema_version = 1\n\
                  catalog_version = \"0.0.1-test\"\n\
                  minimum_app_version = \"0.1.0\"\n\n";
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut text = header.to_owned();
    for draft in [
        "observations/2026-10-09-ea-anticheat/draft.toml",
        "observations/2026-10-10-anticheatexpert/draft.toml",
    ] {
        let body = std::fs::read_to_string(root.join(draft)).expect("the draft is committed");
        text.push_str(&body);
        text.push('\n');
    }
    catalog::parse(&text).expect("the drafts parse as a catalog")
}

#[test]
#[ignore = "what it finds depends on what this machine has installed"]
fn audit_this_machine_with_the_committed_drafts() {
    let report = audit(&drafts(), &Machine, &environment());

    print!("{}", report.to_ndjson().expect("the report is JSON"));
    assert_eq!(report.protected, [], "the drafts pass the deny-list");
    for finding in &report.findings {
        if finding.classification == Classification::Suspicious {
            assert!(
                !finding
                    .evidence
                    .iter()
                    .any(|line| line.contains("could not be checked")),
                "an error is never suspicious: {finding:?}"
            );
        }
    }
}
