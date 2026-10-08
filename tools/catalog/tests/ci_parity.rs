//! Parity between this tool and `.github/workflows/catalog-verify.yml`.
//!
//! The workflow hard-codes six invocations. If a subcommand is renamed, a flag
//! is dropped, or `catalog/pubkey.hex` goes missing, CI turns red on `main`
//! with no local warning. These tests run the same argv vectors against the
//! real files in `catalog/`, so the breakage surfaces in `cargo test` instead.
//!
//! They run on both CI runners and on both local platforms, which matters
//! because the workflow itself only ever runs on ubuntu.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The repository root, two levels above this crate.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <root>/tools/catalog")
        .to_path_buf()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wardsweep-catalog"))
        .current_dir(repo_root())
        .args(args)
        .output()
        .expect("the catalog tool should be runnable")
}

fn assert_ok(args: &[&str]) {
    let output = run(args);
    assert!(
        output.status.success(),
        "`wardsweep-catalog {}` failed with {:?}\nstdout: {}\nstderr: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn the_six_catalog_verify_invocations_all_pass() {
    // Verbatim from .github/workflows/catalog-verify.yml.
    assert_ok(&["validate", "catalog/catalog.toml"]);
    assert_ok(&[
        "verify",
        "--toml",
        "catalog/catalog.toml",
        "--sig",
        "catalog/catalog.toml.sig",
        "--pubkey",
        "catalog/pubkey.hex",
    ]);
    assert_ok(&["check-denylist", "catalog/catalog.toml"]);
    assert_ok(&["check-refs", "catalog/catalog.toml"]);
    assert_ok(&["audit-shared", "catalog/catalog.toml", "--require-evidence"]);
}

#[test]
fn the_example_catalog_still_passes_the_checks_ci_runs_on_it() {
    // catalog.example.toml is the template contributors copy from. If it rots,
    // every contribution starts from something broken.
    assert_ok(&["validate", "catalog/catalog.example.toml"]);
    assert_ok(&["check-refs", "catalog/catalog.example.toml"]);
    assert_ok(&["check-denylist", "catalog/catalog.example.toml"]);
    assert_ok(&[
        "audit-shared",
        "catalog/catalog.example.toml",
        "--require-evidence",
    ]);
}

/// A gate nobody has watched fail is not a gate.
#[test]
fn a_catalog_naming_a_protected_path_is_rejected() {
    let hostile = std::env::temp_dir().join("wardsweep-denied-catalog-test.toml");
    std::fs::write(
        &hostile,
        "schema_version = 1\n\
         catalog_version = \"0.0.0-test\"\n\
         minimum_app_version = \"0.1.0\"\n\
         [[anticheat]]\n\
         id = \"hostile\"\n\
         display = \"Hostile\"\n\
         kind = \"usermode\"\n\
         shared = true\n\
         risk = \"low\"\n\
         paths = [{ path = \"%SystemRoot%\\\\System32\", class = \"install\" }]\n",
    )
    .expect("temp file should be writable");

    let path = hostile.to_string_lossy().into_owned();
    let output = run(&["check-denylist", &path]);
    let _ = std::fs::remove_file(&hostile);

    assert!(
        !output.status.success(),
        "a catalog naming %SystemRoot%\\System32 must be refused"
    );
    assert_eq!(output.status.code(), Some(9), "docs/11 exit code table");
}

/// Signing is where the maintainer vouches for a catalog, so it must refuse
/// one that CI would refuse — and a key, once made, must not be replaced by
/// running keygen again.
#[test]
fn a_catalog_that_fails_the_gate_is_not_signed_and_a_key_is_not_overwritten() {
    let dir = std::env::temp_dir().join(format!("wardsweep-sign-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir should be creatable");
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

    assert_ok(&[
        "keygen",
        "--out-secret",
        &path("secret.hex"),
        "--out-public",
        &path("public.hex"),
    ]);
    let original = std::fs::read(dir.join("secret.hex")).expect("the key was written");
    let again = run(&[
        "keygen",
        "--out-secret",
        &path("secret.hex"),
        "--out-public",
        &path("public.hex"),
    ]);
    assert!(
        !again.status.success(),
        "keygen must refuse an existing key"
    );
    assert_eq!(
        std::fs::read(dir.join("secret.hex")).expect("the key is still there"),
        original
    );

    // Schema-valid, and names a protected path: validate alone would sign it.
    std::fs::write(
        dir.join("hostile.toml"),
        "schema_version = 1\n\
         catalog_version = \"0.0.0-test\"\n\
         minimum_app_version = \"0.1.0\"\n\
         [[anticheat]]\n\
         id = \"hostile\"\n\
         display = \"Hostile\"\n\
         kind = \"usermode\"\n\
         shared = true\n\
         risk = \"low\"\n\
         paths = [{ path = \"%SystemRoot%\\\\System32\", class = \"install\" }]\n",
    )
    .expect("temp file should be writable");
    let signed = run(&[
        "sign",
        "--toml",
        &path("hostile.toml"),
        "--secret",
        &path("secret.hex"),
        "--out",
        &path("hostile.toml.sig"),
    ]);
    let wrote_signature = dir.join("hostile.toml.sig").exists();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !signed.status.success(),
        "a catalog CI would refuse must not be signed"
    );
    assert!(!wrote_signature);
}

/// An unsigned or wrongly-signed catalog is refused, never used with a warning.
#[test]
fn a_tampered_catalog_fails_verification() {
    let tampered = std::env::temp_dir().join("wardsweep-tampered-catalog-test.toml");
    let mut body = std::fs::read(repo_root().join("catalog/catalog.toml"))
        .expect("the shipping catalog should be readable");
    body.extend_from_slice(b"\n# one byte more than was signed\n");
    std::fs::write(&tampered, &body).expect("temp file should be writable");

    let path = tampered.to_string_lossy().into_owned();
    let output = run(&[
        "verify",
        "--toml",
        &path,
        "--sig",
        "catalog/catalog.toml.sig",
        "--pubkey",
        "catalog/pubkey.hex",
    ]);
    let _ = std::fs::remove_file(&tampered);

    assert!(
        !output.status.success(),
        "a modified catalog must not verify"
    );
    assert_eq!(output.status.code(), Some(9));
}
