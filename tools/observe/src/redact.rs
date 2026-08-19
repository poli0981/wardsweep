//! Removing personal identity from a snapshot or a diff.
//!
//! `docs/16-OBSERVATION-HARNESS.md`: raw snapshots "contain full path listings
//! of a real machine"; if one must be shared, "run it through
//! `wardsweep observe redact` first, which replaces usernames and per-user
//! paths with placeholders."
//!
//! Diffs are committed to the repository, so this matters for them too — a
//! footprint diff of anything installed per-user carries the contributor's
//! account name into a public repository, once per path.
//!
//! # What it does not do
//!
//! This removes *identity*, not *secrets*. It is not a sanitiser: a value in a
//! snapshot could contain anything an application chose to write there, and no
//! pattern list can promise otherwise. `docs/16`'s checklist still expects a
//! person to read the diff before it is attached to a pull request.
//!
//! The one thing it does promise is that the substitutions are **exhaustive
//! over the string values it can see** — every string in the document is
//! rewritten, not only the ones in fields this module knows the names of. A
//! redactor that understood the schema would silently miss whatever the schema
//! gained next.
//!
//! # Two passes, because the profile directory is not the only place a name goes
//!
//! Rewriting `\Users\someone\` is the obvious half and it is not enough.
//! Measured on a real snapshot, 284 294 paths were rewritten that way and 213
//! occurrences of the account name survived — in filenames and registry keys
//! outside the profile entirely, written there by applications:
//! `…\User Account Pictures\someone.dat`, `…\ConnectedDevicesPlatform\L.someone.cdp`,
//! `…\DwnlData\someone\…`.
//!
//! So the first pass *learns* the account names from the profile paths, and the
//! second replaces those names wherever else they appear. Matching is on token
//! boundaries: an account name that is also an English word — `Anon` inside
//! `Anonymous`, say — must not be rewritten mid-word.
//!
//! That boundary rule leaves a residue by construction, so
//! [`Report::residual`] counts what is still there and the caller says so. A
//! redactor that quietly leaves identity behind is worse than one that refuses,
//! because it is trusted.

use std::collections::BTreeMap;

/// A substitution that was applied, and how often.
pub type Applied = BTreeMap<String, usize>;

/// What a redaction pass did, and what it could not do.
#[derive(Debug, Default)]
pub struct Report {
    /// Substitutions applied, by placeholder.
    pub applied: Applied,
    /// Account names discovered in profile paths.
    pub names: Vec<String>,
    /// Occurrences of a discovered name still present afterwards, by name.
    ///
    /// Non-empty means the file still identifies someone. The boundary rule
    /// that keeps `Anonymous` intact is what leaves these behind.
    pub residual: BTreeMap<String, usize>,
}

/// Placeholder for the account name a path belongs to.
pub const USER_PLACEHOLDER: &str = "%USER%";
/// Placeholder for a machine-local account identifier.
pub const SID_PLACEHOLDER: &str = "S-1-5-21-%REDACTED%";
/// Placeholder for a computer name in a UNC path.
pub const HOST_PLACEHOLDER: &str = "%COMPUTER%";

/// Redact a whole document: learn the account names, rewrite, then audit.
///
/// Returns what it did *and* what it could not do. The second half is the
/// point — see the module comment.
pub fn redact_document(value: &mut serde_json::Value) -> Report {
    let mut report = Report {
        names: discover_names(value),
        ..Report::default()
    };

    rewrite(value, &report.names, &mut report.applied);

    for name in &report.names {
        let count = count_occurrences(value, name);
        if count > 0 {
            report.residual.insert(name.clone(), count);
        }
    }

    report
}

/// Account names appearing as a `\Users\<name>\` segment anywhere.
#[must_use]
pub fn discover_names(value: &serde_json::Value) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    collect_names(value, &mut names);
    names.into_iter().collect()
}

fn collect_names(value: &serde_json::Value, names: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(name) = profile_name(text) {
                names.insert(name);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_names(item, names);
            }
        }
        serde_json::Value::Object(fields) => {
            for (_, field) in fields {
                collect_names(field, names);
            }
        }
        _ => {}
    }
}

fn count_occurrences(value: &serde_json::Value, name: &str) -> usize {
    match value {
        serde_json::Value::String(text) => text.matches(name).count(),
        serde_json::Value::Array(items) => {
            items.iter().map(|item| count_occurrences(item, name)).sum()
        }
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(_, field)| count_occurrences(field, name))
            .sum(),
        _ => 0,
    }
}

/// The account name in a path that is *rooted* at a profile directory.
///
/// Only `C:\Users\name\…`, never a `\Users\` segment further along. That
/// distinction is not pedantry. A real snapshot contains
/// `…\Containers\Layers\<guid>\Files\Users\ContainerUser`, an Android source
/// tree under `…\settings\users\EditUserInfoController.java`, and an ASP.NET
/// sample under `…\Users\addUser.aspx`. Learning from those taught the
/// redactor that `desktop.ini`, `guest` and `*` were people — and it then
/// replaced those tokens across the whole document, corrupting unrelated data
/// in the name of protecting it.
fn profile_name(text: &str) -> Option<String> {
    // `\\?\C:\Users\…` is the same path in extended-length form.
    let path = text.strip_prefix(r"\\?\").unwrap_or(text);

    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }

    let rest = &path[3..];
    let after = rest.to_ascii_lowercase();
    let after = after.strip_prefix("users\\")?;
    let start = rest.len() - after.len();
    let end = rest[start..]
        .find('\\')
        .map_or(rest.len(), |offset| start + offset);

    let name = &rest[start..end];
    if name.is_empty()
        || is_shared_profile(name)
        || name == USER_PLACEHOLDER
        // Characters Windows forbids in an account name. Cheap, and it is what
        // stops a glob or a file name being mistaken for a person.
        || name.contains(['*', '?', '"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '<', '>'])
    {
        return None;
    }

    Some(name.to_owned())
}

/// Whether a profile directory belongs to a person.
fn is_shared_profile(name: &str) -> bool {
    name.eq_ignore_ascii_case("public")
        || name.eq_ignore_ascii_case("default")
        || name.eq_ignore_ascii_case("all users")
        || name.eq_ignore_ascii_case("default user")
}

/// Rewrite every string in a JSON document.
///
/// Returns the counts by placeholder, so the caller can say what it did rather
/// than claim to have done something.
pub fn rewrite(value: &mut serde_json::Value, names: &[String], applied: &mut Applied) {
    match value {
        serde_json::Value::String(text) => {
            let (replaced, hits) = redact_text_with(text, names);
            if hits.is_empty() {
                return;
            }
            *text = replaced;
            for placeholder in hits {
                *applied.entry(placeholder).or_insert(0) += 1;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite(item, names, applied);
            }
        }
        serde_json::Value::Object(fields) => {
            // Values only. A key is a schema field name, and rewriting one
            // would produce a document that no longer parses.
            for (_, field) in fields.iter_mut() {
                rewrite(field, names, applied);
            }
        }
        _ => {}
    }
}

/// Rewrite one string with no learned names. Used by the tests, which exercise
/// each substitution in isolation before the document-level behaviour.
#[cfg(test)]
#[must_use]
pub fn redact_text(text: &str) -> (String, Vec<String>) {
    redact_text_with(text, &[])
}

/// Rewrite one string, reporting which placeholders were used.
#[must_use]
pub fn redact_text_with(text: &str, names: &[String]) -> (String, Vec<String>) {
    let mut applied = Vec::new();
    let mut result = text.to_owned();

    if let Some(replaced) = replace_user_profiles(&result) {
        result = replaced;
        applied.push(USER_PLACEHOLDER.to_owned());
    }
    if let Some(replaced) = replace_sids(&result) {
        result = replaced;
        applied.push(SID_PLACEHOLDER.to_owned());
    }
    if let Some(replaced) = replace_unc_hosts(&result) {
        result = replaced;
        applied.push(HOST_PLACEHOLDER.to_owned());
    }
    // Last, and only for names the first pass actually found on this machine.
    // A fixed list of common account names would rewrite text that has nothing
    // to do with anybody.
    for name in names {
        if let Some(replaced) = replace_bare_name(&result, name) {
            result = replaced;
            applied.push(USER_PLACEHOLDER.to_owned());
        }
    }

    (result, applied)
}

/// Replace a learned account name where it stands as its own token.
///
/// Boundaries are alphanumeric characters on either side. `Anon` inside
/// `Anonymous` is not the account, and rewriting it would corrupt unrelated
/// text; `L.Anon.cdp` and `\DwnlData\Anon\` are, and are rewritten. The cost
/// of the rule is that `Anonb7a4e505` survives, which is why the caller reports
/// a residual count rather than claiming the file is clean.
fn replace_bare_name(text: &str, name: &str) -> Option<String> {
    if name.is_empty() || !text.contains(name) {
        return None;
    }

    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut hit = false;

    while let Some(found) = text[cursor..].find(name) {
        let start = cursor + found;
        let end = start + name.len();

        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();

        result.push_str(&text[cursor..start]);
        if before_ok && after_ok {
            result.push_str(USER_PLACEHOLDER);
            hit = true;
        } else {
            result.push_str(name);
        }
        cursor = end;
    }

    result.push_str(&text[cursor..]);
    hit.then_some(result)
}

/// `C:\Users\someone\…` becomes `C:\Users\%USER%\…`.
///
/// Matched on the `\Users\` segment rather than against a known account name,
/// so a snapshot taken on one machine and redacted on another still works, and
/// so a second profile on the same machine is covered too.
fn replace_user_profiles(text: &str) -> Option<String> {
    let lowered = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut hit = false;

    while let Some(found) = lowered[cursor..].find("\\users\\") {
        let start = cursor + found + "\\users\\".len();
        result.push_str(&text[cursor..start]);

        // The account name runs to the next separator, or to the end.
        let end = text[start..]
            .find('\\')
            .map_or(text.len(), |offset| start + offset);
        let name = &text[start..end];

        // `Public` and `Default` are not people, and a catalog entry may
        // legitimately name them.
        if is_shared_profile(name) || name == USER_PLACEHOLDER || name.is_empty() {
            result.push_str(name);
        } else {
            result.push_str(USER_PLACEHOLDER);
            hit = true;
        }

        cursor = end;
    }

    result.push_str(&text[cursor..]);
    hit.then_some(result)
}

/// `S-1-5-21-a-b-c-1001` becomes `S-1-5-21-%REDACTED%`.
///
/// Only the `S-1-5-21-` domain: the well-known SIDs (`S-1-5-18` for SYSTEM,
/// `S-1-5-32-544` for Administrators) identify nobody and appear in every
/// snapshot's pipe and service records, where replacing them would destroy
/// information for no gain.
fn replace_sids(text: &str) -> Option<String> {
    const PREFIX: &str = "S-1-5-21-";
    if !text.contains(PREFIX) {
        return None;
    }

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut hit = false;

    while let Some(found) = text[cursor..].find(PREFIX) {
        let start = cursor + found;
        result.push_str(&text[cursor..start]);

        let rest = &text[start + PREFIX.len()..];

        // Already redacted. Without this the placeholder's own prefix matches
        // on a second pass and the suffix is appended twice — and a redacted
        // file is exactly what gets redacted again by someone unsure whether
        // it was.
        let suffix = &SID_PLACEHOLDER[PREFIX.len()..];
        if rest.starts_with(suffix) {
            result.push_str(SID_PLACEHOLDER);
            cursor = start + SID_PLACEHOLDER.len();
            continue;
        }

        // Consume the digit-and-hyphen run that follows the prefix.
        let taken = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());

        result.push_str(SID_PLACEHOLDER);
        hit = true;
        cursor = start + PREFIX.len() + taken;
    }

    result.push_str(&text[cursor..]);
    hit.then_some(result)
}

/// `\\MACHINE\share` becomes `\\%COMPUTER%\share`.
fn replace_unc_hosts(text: &str) -> Option<String> {
    if !text.starts_with("\\\\") {
        return None;
    }
    let rest = &text[2..];
    // `\\.\pipe\…` and `\\?\C:\…` are device paths, not host names.
    if rest.starts_with('.') || rest.starts_with('?') {
        return None;
    }
    let end = rest.find('\\').unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() || host == HOST_PLACEHOLDER {
        return None;
    }
    Some(format!("\\\\{HOST_PLACEHOLDER}{}", &rest[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_profile_path_is_replaced() {
        let (out, hits) = redact_text("C:\\Users\\Anon\\AppData\\Local\\Riot Games\\x.log");
        assert_eq!(out, "C:\\Users\\%USER%\\AppData\\Local\\Riot Games\\x.log");
        assert_eq!(hits, vec![USER_PLACEHOLDER]);
    }

    #[test]
    fn shared_profiles_are_not_people_and_survive() {
        // A catalog entry may legitimately name these, and %PUBLIC% is one of
        // the variables docs/04 allows in a path template.
        for path in [
            "C:\\Users\\Public\\Documents\\x",
            "C:\\Users\\Default\\NTUSER.DAT",
        ] {
            let (out, hits) = redact_text(path);
            assert_eq!(out, path, "{path} should be unchanged");
            assert!(hits.is_empty());
        }
    }

    #[test]
    fn a_machine_local_sid_is_replaced_but_a_well_known_one_is_not() {
        let (out, _) = redact_text("D:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-21-111-222-333-1001)");
        assert_eq!(out, "D:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-21-%REDACTED%)");

        // SYSTEM and Administrators identify nobody and appear everywhere.
        let (unchanged, hits) = redact_text("S-1-5-18 and S-1-5-32-544");
        assert_eq!(unchanged, "S-1-5-18 and S-1-5-32-544");
        assert!(hits.is_empty());
    }

    #[test]
    fn a_unc_host_is_replaced_but_a_device_path_is_not() {
        let (out, _) = redact_text("\\\\FILESERVER\\share\\x");
        assert_eq!(out, "\\\\%COMPUTER%\\share\\x");

        for device in ["\\\\.\\pipe\\wardsweep-abc", "\\\\?\\C:\\Windows"] {
            let (unchanged, hits) = redact_text(device);
            assert_eq!(unchanged, device);
            assert!(hits.is_empty());
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        // Running it twice must not mangle its own placeholders — a redacted
        // file is exactly the kind of thing that gets redacted again by someone
        // who is not sure whether it was.
        let once = redact_text("C:\\Users\\Anon\\x — S-1-5-21-1-2-3-1001").0;
        let twice = redact_text(&once).0;
        assert_eq!(once, twice);
    }

    #[test]
    fn an_account_name_outside_the_profile_directory_is_also_removed() {
        // Measured on a real snapshot: 213 occurrences survived the obvious
        // pass, in filenames and registry keys applications had written the
        // account name into.
        let mut document = serde_json::json!({
            "files": [
                { "path": "C:\\Users\\Anon\\AppData\\Local\\x" },
                { "path": "C:\\ProgramData\\Microsoft\\User Account Pictures\\Anon.dat" },
                { "path": "C:\\ProgramData\\ConnectedDevicesPlatform\\L.Anon.cdp" }
            ]
        });
        let report = redact_document(&mut document);

        assert_eq!(report.names, vec!["Anon".to_owned()]);
        let text = document.to_string();
        assert!(!text.contains("Anon."), "{text}");
        assert!(!text.contains("Pictures\\\\Anon"), "{text}");
    }

    #[test]
    fn a_users_segment_that_is_not_a_profile_root_teaches_nothing() {
        // Every one of these appeared in a real snapshot, and learning from
        // them made the redactor replace `desktop.ini`, `guest` and `*` across
        // the whole document.
        for path in [
            r"C:\ProgramData\Microsoft\Windows\Containers\Layers\g\Files\Users\ContainerUser",
            r"C:\src\android\settings\users\EditUserInfoController.java",
            r"C:\samples\App_Code\Users\addUser.aspx",
        ] {
            let document = serde_json::json!({ "path": path });
            assert!(
                discover_names(&document).is_empty(),
                "{path} should teach no account name"
            );
        }
    }

    #[test]
    fn a_profile_root_teaches_its_name_in_either_path_form() {
        let plain = serde_json::json!({ "p": r"C:\Users\Anon\AppData" });
        assert_eq!(discover_names(&plain), vec!["Anon".to_owned()]);

        // Extended-length form names the same profile.
        let extended = serde_json::json!({ "p": r"\\?\C:\Users\Anon\AppData" });
        assert_eq!(discover_names(&extended), vec!["Anon".to_owned()]);
    }

    #[test]
    fn an_account_name_inside_an_unrelated_word_is_left_alone() {
        // "Anon" is a substring of "Anonymous", and a snapshot is full of
        // strings like "Create Anonymous Remote Service".
        let mut document = serde_json::json!({
            "files": [
                { "path": "C:\\Users\\Anon\\x" },
                { "path": "C:\\Sql\\Create Anonymous Remote Service.sql" }
            ]
        });
        redact_document(&mut document);
        assert!(document.to_string().contains("Anonymous"));
    }

    #[test]
    fn what_could_not_be_removed_is_counted_rather_than_ignored() {
        // The boundary rule leaves this behind by construction. Reporting it is
        // the difference between a tool that is honest and one that is trusted
        // wrongly.
        let mut document = serde_json::json!({
            "files": [
                { "path": "C:\\Users\\Anon\\x" },
                { "path": "C:\\JetBrains\\fileHistory\\Anonb7a4e505-ngram" }
            ]
        });
        let report = redact_document(&mut document);
        assert_eq!(report.residual.get("Anon"), Some(&1));
    }

    #[test]
    fn a_clean_document_reports_no_residual() {
        let mut document = serde_json::json!({
            "files": [{ "path": "C:\\Users\\Anon\\AppData\\Local\\x" }]
        });
        let report = redact_document(&mut document);
        assert!(report.residual.is_empty());
    }

    #[test]
    fn every_string_in_the_document_is_rewritten_not_only_known_fields() {
        // The point of walking the tree blindly: a field added to the schema
        // tomorrow is covered without this module being told about it.
        let mut document = serde_json::json!({
            "known": "C:\\Users\\Anon\\a",
            "nested": { "deep": ["C:\\Users\\Anon\\b", {"newer": "C:\\Users\\Anon\\c"}] },
            "number": 42
        });
        let report = redact_document(&mut document);

        let text = document.to_string();
        assert!(!text.contains("Anon"), "{text}");
        assert_eq!(report.applied[USER_PLACEHOLDER], 3);
    }

    #[test]
    fn object_keys_are_left_alone() {
        // Rewriting a key would produce a document that no longer deserialises
        // into the model it came from.
        let mut document = serde_json::json!({ "C:\\Users\\Anon": "C:\\Users\\Anon" });
        redact_document(&mut document);

        let object = document.as_object().unwrap();
        assert!(object.contains_key("C:\\Users\\Anon"));
        assert_eq!(object["C:\\Users\\Anon"], "C:\\Users\\%USER%");
    }
}
