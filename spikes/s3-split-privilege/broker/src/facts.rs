//! Machine-readable output for `scripts/run-s3.ps1`.
//!
//! One fact per line, `S3|key=value|…`, always to stdout and additionally to
//! `--fact-file` when one was given — which is how an elevated broker, whose
//! stdout the launching UI cannot inherit, still reports what it observed.
//!
//! Its own module because the job thread emits facts too: the harness needs to
//! know the exact moment a commit transaction is open in order to kill the
//! process inside one, and that moment is only visible from there.

use std::sync::{Mutex, OnceLock};

/// Where facts are mirrored, if anywhere. Set once, before any fact is emitted.
static FACT_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

/// Begin mirroring facts to a file.
///
/// # Errors
/// If the file cannot be opened for appending.
pub fn mirror_to(path: &std::path::Path) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let _ = FACT_FILE.set(Mutex::new(file));
    Ok(())
}

/// Emit one fact.
pub fn emit(line: &str) {
    use std::io::Write as _;

    println!("S3|{line}");
    let _ = std::io::stdout().flush();

    if let Some(file) = FACT_FILE.get()
        && let Ok(mut file) = file.lock()
    {
        let _ = writeln!(file, "S3|{line}");
        let _ = file.flush();
    }
}

/// Collapse a message to one line so it cannot break the `S3|` record format.
#[must_use]
pub fn one_line(value: &str) -> String {
    value.replace(['\r', '\n', '|'], " ")
}
