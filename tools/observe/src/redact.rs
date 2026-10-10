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
//! second replaces those names wherever else they appear, in any letter case.
//! Matching is on token boundaries: an account name that is also an English
//! word — `Anon` inside `Anonymous`, say — must not be rewritten mid-word.
//!
//! # Names the document cannot teach
//!
//! The machine's own name appears in a document without a path to learn it
//! from, and so can an account name in a file that has already been redacted
//! once. Both arrive as [`Extra`] names from the caller — the command line adds
//! the local machine's computer and account names — and are replaced the same
//! way.
//!
//! # E-mail addresses
//!
//! Two committed diffs carried the contributor's Microsoft-account address as
//! the name of a registry key, with the account name glued to digits in front
//! of the `@`: a token boundary rule cannot reach it, and nothing here
//! recognised an address at all. Addresses are now replaced wherever they
//! appear, before any name is.
//!
//! That boundary rule still leaves a residue by construction, so
//! [`Report::residual`] counts what is left, in any case, and shows where it
//! is. A redactor that quietly leaves identity behind is worse than one that
//! refuses, because it is trusted.
//!
//! # The document comes back the way it went in
//!
//! A diff is indented because a person reviews it, and a snapshot is compact
//! because it is large; [`render_like`] writes the redacted copy in whichever
//! layout the original had, with its keys in their original order. Redaction
//! used to write everything on one line with every object's keys sorted, which
//! is how the committed diffs came to be one-line files that no later rewrite
//! could change without touching every line.

use std::collections::BTreeMap;

/// A substitution that was applied, and how often.
pub type Applied = BTreeMap<String, usize>;

/// Names known from outside the document.
#[derive(Debug, Clone, Default)]
pub struct Extra {
    /// Account names, replaced by [`USER_PLACEHOLDER`].
    pub accounts: Vec<String>,
    /// Computer names, replaced by [`HOST_PLACEHOLDER`].
    pub computers: Vec<String>,
    /// Opaque identifiers a review found and no rule knows — an account number
    /// in a game's file name, a folder named after a hash of one — replaced by
    /// [`ID_PLACEHOLDER`].
    pub identifiers: Vec<String>,
}

/// The shortest name replaced on its own.
///
/// A one- or two-letter name is a token in half the strings in a snapshot, and
/// replacing it everywhere would destroy the document to protect it. Such a
/// name is reported as not applied instead.
pub const MIN_NAME_LEN: usize = 3;

/// What a redaction pass did, and what it could not do.
#[derive(Debug, Default)]
pub struct Report {
    /// Substitutions applied, by placeholder.
    pub applied: Applied,
    /// Account names discovered in profile paths, plus any supplied.
    pub names: Vec<String>,
    /// Computer names supplied by the caller.
    pub computers: Vec<String>,
    /// How many identifiers the caller supplied. Counted rather than listed:
    /// the caller has them already, and a report is something people paste.
    pub identifiers: usize,
    /// Supplied names too short to replace safely, and so left alone.
    pub skipped: Vec<String>,
    /// What is still present afterwards, by name.
    ///
    /// Non-empty means the file may still identify someone. The boundary rule
    /// that keeps `Anonymous` intact is what leaves these behind — and so does
    /// an account name glued to other characters, which is how an e-mail
    /// address survived before addresses had a rule of their own.
    pub residual: BTreeMap<String, Residual>,
}

/// Where a name still appears after redaction.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Residual {
    /// Occurrences, in any letter case, in values and in object keys.
    pub count: usize,
    /// A few occurrences in context, with the name itself masked, so a person
    /// can judge them without the report repeating what it is warning about.
    pub contexts: Vec<String>,
}

/// How many contexts a residual keeps.
const MAX_CONTEXTS: usize = 5;
/// Characters kept either side of an occurrence in a context.
const CONTEXT_CHARS: usize = 24;

/// Placeholder for the account name a path belongs to.
pub const USER_PLACEHOLDER: &str = "%USER%";
/// Placeholder for a machine-local account identifier.
pub const SID_PLACEHOLDER: &str = "S-1-5-21-%REDACTED%";
/// Placeholder for a computer name.
pub const HOST_PLACEHOLDER: &str = "%COMPUTER%";
/// Placeholder for an e-mail address.
pub const EMAIL_PLACEHOLDER: &str = "%EMAIL%";
/// Placeholder for an opaque identifier a registry value carries.
pub const ID_PLACEHOLDER: &str = "%ID%";

/// Value-name endings that mark an opaque per-session, per-device or
/// per-account identifier, compared without regard to case.
///
/// EA's anti-cheat keeps `LastSessionId` and `LastServiceSessionId` under its
/// own key. The key and the value names are footprint and stay; the identifiers
/// mean something only to the vendor's servers, and are masked.
const IDENTIFIER_NAMES: &[&str] = &[
    "sessionid",
    "deviceid",
    "machineid",
    "clientid",
    "installid",
    "userid",
    "accountid",
];

/// Redact a whole document: learn the account names, rewrite, then audit.
///
/// Returns what it did *and* what it could not do. The second half is the
/// point — see the module comment.
pub fn redact_document(value: &mut serde_json::Value, extra: &Extra) -> Report {
    let mut report = Report::default();

    let mut accounts = discover_names(value);
    let mut computers = Vec::new();
    let mut identifiers = Vec::new();
    for (supplied, into) in [
        (&extra.accounts, &mut accounts),
        (&extra.computers, &mut computers),
        (&extra.identifiers, &mut identifiers),
    ] {
        for name in supplied {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if name.len() < MIN_NAME_LEN {
                report.skipped.push(name.to_owned());
            } else if !into.iter().any(|known| known.eq_ignore_ascii_case(name)) {
                into.push(name.to_owned());
            }
        }
    }

    let names: Vec<(String, &'static str)> = accounts
        .iter()
        .map(|name| (name.clone(), USER_PLACEHOLDER))
        .chain(
            computers
                .iter()
                .map(|name| (name.clone(), HOST_PLACEHOLDER)),
        )
        .chain(identifiers.iter().map(|id| (id.clone(), ID_PLACEHOLDER)))
        .collect();

    rewrite(value, &names, &mut report.applied);

    for (name, _) in &names {
        let mut residual = Residual::default();
        audit(value, name, &mut residual);
        if residual.count > 0 {
            report.residual.insert(name.clone(), residual);
        }
    }

    report.names = accounts;
    report.computers = computers;
    report.identifiers = identifiers.len();
    report
}

/// Serialise a redacted document in the layout its source had.
///
/// Indented when the source spans more than one line, compact when it does
/// not. A compact document never does: JSON escapes a newline inside a string.
///
/// # Errors
/// If the document cannot be serialised, which a parsed document always can.
pub fn render_like(source: &str, document: &serde_json::Value) -> serde_json::Result<String> {
    if source.trim().contains('\n') {
        serde_json::to_string_pretty(document)
    } else {
        serde_json::to_string(document)
    }
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

/// Count what is left of a name, in values and in object keys, and keep a
/// few occurrences in context.
///
/// Object keys are never rewritten — see [`rewrite`] — and some of them are
/// data: a diff's signer map is keyed by certificate subject. A name surviving
/// there is still a name surviving.
fn audit(value: &serde_json::Value, name: &str, residual: &mut Residual) {
    match value {
        serde_json::Value::String(text) => record_occurrences(text, name, residual),
        serde_json::Value::Array(items) => {
            for item in items {
                audit(item, name, residual);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                record_occurrences(key, name, residual);
                audit(field, name, residual);
            }
        }
        _ => {}
    }
}

fn record_occurrences(text: &str, name: &str, residual: &mut Residual) {
    for start in find_ignoring_case(text, name) {
        residual.count += 1;
        if residual.contexts.len() < MAX_CONTEXTS {
            residual.contexts.push(context(text, start, name.len()));
        }
    }
    // Inside a value written as hex, on any boundary: what the rewrite left
    // because it was glued to something is exactly what this must report.
    if let Some(bytes) = decode_hex(text) {
        for wide in [false, true] {
            for _ in find_encoded(&bytes, name, wide, false) {
                residual.count += 1;
                if residual.contexts.len() < MAX_CONTEXTS {
                    let encoding = if wide { "UTF-16" } else { "ASCII" };
                    residual.contexts.push(format!(
                        "[NAME] as {encoding} inside a {}-byte binary value",
                        bytes.len()
                    ));
                }
            }
        }
    }
}

/// An occurrence with a little of its surroundings, the name itself masked.
fn context(text: &str, start: usize, len: usize) -> String {
    let before: String = text[..start]
        .chars()
        .rev()
        .take(CONTEXT_CHARS)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let after: String = text[start + len..].chars().take(CONTEXT_CHARS).collect();
    let lead = if before.len() < start { "…" } else { "" };
    let tail = if start + len + after.len() < text.len() {
        "…"
    } else {
        ""
    };
    format!("{lead}{before}[NAME]{after}{tail}")
}

/// Byte offsets of every occurrence of `needle` in `text`, ignoring ASCII
/// case. Lower-casing ASCII never moves a byte, so the offsets index `text`.
fn find_ignoring_case(text: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() || needle.len() > text.len() {
        return Vec::new();
    }
    let haystack = text.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    haystack.match_indices(&needle).map(|(at, _)| at).collect()
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
/// `names` pairs each name with its placeholder. Returns the counts by
/// placeholder through `applied`, so the caller can say what it did rather
/// than claim to have done something.
pub fn rewrite(
    value: &mut serde_json::Value,
    names: &[(String, &'static str)],
    applied: &mut Applied,
) {
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
            mask_identifier(fields, applied);
            // Values only. A key is a schema field name, and rewriting one
            // would produce a document that no longer parses.
            for (_, field) in fields.iter_mut() {
                rewrite(field, names, applied);
            }
        }
        _ => {}
    }
}

/// Whether a registry value's name says it holds an opaque identifier.
fn names_an_identifier(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    IDENTIFIER_NAMES
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}

/// Mask the data of a registry value, or of a change to one, whose name says
/// it is an identifier. The name stays, so the value is still evidence that it
/// exists.
///
/// The two shapes a document carries: a value, `{name, kind, data}`, and a
/// field change, `{field, before, after}` with each side as `kind:data`.
fn mask_identifier(fields: &mut serde_json::Map<String, serde_json::Value>, applied: &mut Applied) {
    let named = |key: &str| {
        fields
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(names_an_identifier)
    };
    let (targets, typed): (&[&str], bool) = if named("name") && fields.contains_key("data") {
        (&["data"], false)
    } else if named("field") && fields.contains_key("before") {
        (&["before", "after"], true)
    } else {
        return;
    };
    for target in targets {
        let Some(serde_json::Value::String(text)) = fields.get_mut(*target) else {
            continue;
        };
        let (kind, data) = match text.split_once(':') {
            Some((kind, data)) if typed => (Some(kind.to_owned()), data),
            _ => (None, text.as_str()),
        };
        if data.is_empty() || data == ID_PLACEHOLDER {
            continue;
        }
        *text = kind.map_or_else(
            || ID_PLACEHOLDER.to_owned(),
            |kind| format!("{kind}:{ID_PLACEHOLDER}"),
        );
        *applied.entry(ID_PLACEHOLDER.to_owned()).or_insert(0) += 1;
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
pub fn redact_text_with(text: &str, names: &[(String, &'static str)]) -> (String, Vec<String>) {
    let mut applied = Vec::new();
    let mut result = text.to_owned();

    // First: an address contains the account name more often than not, and
    // once the name has been replaced inside it the address no longer looks
    // like one.
    if let Some(replaced) = replace_emails(&result) {
        result = replaced;
        applied.push(EMAIL_PLACEHOLDER.to_owned());
    }
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
    // Last, and only for names this machine or this document supplied. A
    // fixed list of common account names would rewrite text that has nothing
    // to do with anybody.
    for (name, placeholder) in names {
        if let Some(replaced) = replace_bare_name(&result, name, placeholder) {
            result = replaced;
            applied.push((*placeholder).to_owned());
        }
    }
    if let Some((replaced, placeholders)) = replace_in_hex(&result, names) {
        result = replaced;
        applied.extend(placeholders);
    }

    (result, applied)
}

/// Replace names inside a value written as hex.
///
/// A registry binary reaches a document as hex digits, and a path inside one —
/// a shell link, a recent-items entry — carries the account name as ASCII or
/// UTF-16 bytes that no text rule can see. A Store application's storage table
/// carried 72 of them in one diff. Each is replaced by its placeholder in the
/// same encoding, on the same token boundaries as text, so the value keeps its
/// shape and says where a name was.
fn replace_in_hex(text: &str, names: &[(String, &'static str)]) -> Option<(String, Vec<String>)> {
    if names.is_empty() {
        return None;
    }
    let mut bytes = decode_hex(text)?;
    let mut applied = Vec::new();
    for (name, placeholder) in names {
        for wide in [false, true] {
            let starts = find_encoded(&bytes, name, wide, true);
            if starts.is_empty() {
                continue;
            }
            let width = encode(name, wide).len();
            let replacement = encode(placeholder, wide);
            let mut rebuilt = Vec::with_capacity(bytes.len());
            let mut copied = 0;
            for start in starts {
                rebuilt.extend_from_slice(&bytes[copied..start]);
                rebuilt.extend_from_slice(&replacement);
                copied = start + width;
            }
            rebuilt.extend_from_slice(&bytes[copied..]);
            bytes = rebuilt;
            applied.push((*placeholder).to_owned());
        }
    }
    if applied.is_empty() {
        return None;
    }
    let upper = text.bytes().any(|byte| byte.is_ascii_uppercase());
    Some((encode_hex(&bytes, upper), applied))
}

/// The bytes a string of hex digits spells, when it is one: an even number of
/// digits and nothing else. An ordinary word made of the letters a to f decodes
/// too, harmlessly — a name has to be found inside it before anything changes.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() < 2
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8], upper: bool) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let digits = if upper { UPPER } else { LOWER };
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(digits[usize::from(byte >> 4)]));
        text.push(char::from(digits[usize::from(byte & 0x0f)]));
    }
    text
}

/// A string's bytes as UTF-8, or as UTF-16LE.
fn encode(text: &str, wide: bool) -> Vec<u8> {
    if wide {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        text.as_bytes().to_vec()
    }
}

/// Offsets of `name` in `bytes`, ASCII case ignored, encoded as UTF-8 or as
/// UTF-16LE. With `bounded`, only where it stands on its own as
/// [`replace_bare_name`] requires of text: no letter or digit, in the same
/// encoding, on either side.
fn find_encoded(bytes: &[u8], name: &str, wide: bool, bounded: bool) -> Vec<usize> {
    let pattern = encode(name, wide);
    if pattern.is_empty() || pattern.len() > bytes.len() {
        return Vec::new();
    }
    let unit = if wide { 2 } else { 1 };
    let is_word = |at: usize| {
        bytes.get(at).is_some_and(u8::is_ascii_alphanumeric)
            && (!wide || bytes.get(at + 1) == Some(&0))
    };

    let mut found = Vec::new();
    let mut at = 0;
    while at + pattern.len() <= bytes.len() {
        let matches = bytes[at..at + pattern.len()]
            .iter()
            .zip(&pattern)
            .all(|(byte, expected)| byte.eq_ignore_ascii_case(expected));
        let alone =
            !bounded || ((at < unit || !is_word(at - unit)) && !is_word(at + pattern.len()));
        if matches && alone {
            found.push(at);
            at += pattern.len();
        } else {
            at += 1;
        }
    }
    found
}

/// `someone@example.com` becomes `%EMAIL%`.
///
/// Deliberately plain: a local part of letters, digits and `._%+-`, a domain of
/// at least two dot-separated labels ending in an alphabetic top-level label.
/// That excludes the things in a snapshot that merely contain an `@` — a
/// formatted resource reference like `@fmt|…`, a scoped package name, a bare
/// `user@host` — and includes every address a person types.
fn replace_emails(text: &str) -> Option<String> {
    if !text.contains('@') {
        return None;
    }

    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut copied = 0usize;
    let mut search = 0usize;
    let mut hit = false;

    while let Some(offset) = text[search..].find('@') {
        let at = search + offset;
        let local_start = bytes[copied..at]
            .iter()
            .rposition(|byte| !is_local_byte(*byte))
            .map_or(copied, |index| copied + index + 1);
        let domain_end = bytes[at + 1..]
            .iter()
            .position(|byte| !is_domain_byte(*byte))
            .map_or(bytes.len(), |index| at + 1 + index);
        // A sentence ending in an address leaves its full stop attached.
        let domain = text[at + 1..domain_end].trim_end_matches(['.', '-']);

        if local_start < at && is_email_domain(domain) {
            result.push_str(&text[copied..local_start]);
            result.push_str(EMAIL_PLACEHOLDER);
            copied = at + 1 + domain.len();
            search = copied;
            hit = true;
        } else {
            search = at + 1;
        }
    }

    result.push_str(&text[copied..]);
    hit.then_some(result)
}

fn is_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn is_email_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    !is_scale_suffix(domain)
        && labels.len() >= 2
        && labels
            .iter()
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        && labels
            .last()
            .is_some_and(|top| top.len() >= 2 && top.bytes().all(|byte| byte.is_ascii_alphabetic()))
}

/// Whether a "domain" is an image's display-scale suffix: the `2x.png` of
/// `arrow@2x.png`, the `1.5x.png` of `icon@1.5x.png`. Application bundles name
/// files that way by the hundred, and the EA app's did reach a diff as a row of
/// e-mail addresses.
fn is_scale_suffix(domain: &str) -> bool {
    const IMAGES: &[&str] = &["png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico"];
    let Some((scale, extension)) = domain.rsplit_once('.') else {
        return false;
    };
    let Some(number) = scale.strip_suffix(['x', 'X']) else {
        return false;
    };
    number.starts_with(|c: char| c.is_ascii_digit())
        && number.chars().all(|c| c.is_ascii_digit() || c == '.')
        && IMAGES
            .iter()
            .any(|image| image.eq_ignore_ascii_case(extension))
}

/// Replace a name where it stands as its own token, in any letter case.
///
/// Boundaries are alphanumeric characters on either side. `Anon` inside
/// `Anonymous` is not the account, and rewriting it would corrupt unrelated
/// text; `L.Anon.cdp`, `\DwnlData\ANON\` and `anon` are, and are rewritten.
/// The cost of the rule is that `Anonb7a4e505` survives, which is why the
/// caller reports a residual rather than claiming the file is clean.
fn replace_bare_name(text: &str, name: &str, placeholder: &str) -> Option<String> {
    let starts = find_ignoring_case(text, name);
    if starts.is_empty() {
        return None;
    }

    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut hit = false;

    for start in starts {
        if start < cursor {
            continue; // overlaps the previous replacement
        }
        let end = start + name.len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            result.push_str(&text[cursor..start]);
            result.push_str(placeholder);
            cursor = end;
            hit = true;
        }
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

    fn redact(document: &mut serde_json::Value) -> Report {
        redact_document(document, &Extra::default())
    }

    #[test]
    fn an_identifier_a_review_supplies_is_masked_on_token_boundaries() {
        let mut document = serde_json::json!({
            "files": [
                {"path": "C:\\Users\\%USER%\\AppData\\Local\\Game\\cache\\playtime_3299311611.json"},
                {"path": "C:\\Game\\data\\13299311611.bin"}
            ]
        });
        let extra = Extra {
            identifiers: vec!["3299311611".to_owned()],
            ..Extra::default()
        };

        let report = redact_document(&mut document, &extra);

        let text = serde_json::to_string(&document).unwrap();
        assert!(text.contains("playtime_%ID%.json"), "{text}");
        assert_eq!(report.applied.get(ID_PLACEHOLDER), Some(&1));
        assert_eq!(report.identifiers, 1);
        // Inside a longer number it is left alone, and reported for a person
        // to judge rather than passed over in silence.
        assert!(text.contains("13299311611.bin"), "{text}");
        assert_eq!(report.residual.get("3299311611").map(|r| r.count), Some(1));
    }

    #[test]
    fn an_identifier_value_keeps_its_name_and_loses_its_data() {
        let mut document = serde_json::json!({
            "registry": [{
                "key": "HKCU\\SOFTWARE\\EA\\AC",
                "after": {"values": [
                    {"name": "LastSessionId", "kind": "sz", "data": "8f1e2d3c-1111-2222-3333-444455556666"},
                    {"name": "version", "kind": "sz", "data": "1.2.3"}
                ]},
                "fields": [
                    {"field": "LastServiceSessionId", "before": "sz:aaa", "after": "sz:bbb"}
                ]
            }]
        });

        let report = redact(&mut document);

        let text = serde_json::to_string(&document).unwrap();
        for identifier in ["8f1e2d3c", "sz:aaa", "sz:bbb"] {
            assert!(!text.contains(identifier), "{identifier} survived: {text}");
        }
        assert!(
            text.contains("\"LastSessionId\""),
            "the name is evidence and stays"
        );
        assert!(text.contains("sz:%ID%"), "the type survives a field change");
        assert!(text.contains("1.2.3"), "an ordinary value is untouched");
        assert_eq!(report.applied.get(ID_PLACEHOLDER), Some(&3));
    }

    #[test]
    fn a_redacted_document_keeps_its_layout_and_key_order() {
        // Keys deliberately out of alphabetical order, as a diff writes them.
        let indented = "{\n  \"format_version\": 2,\n  \"before_taken_utc\": \"x\",\n  \"after\": {\n    \"path\": \"C:\\\\Users\\\\Anon\\\\a\",\n    \"kind\": \"added\"\n  }\n}";
        let compact: String =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(indented).unwrap())
                .unwrap();

        for source in [indented.to_owned(), compact.clone()] {
            let mut document: serde_json::Value = serde_json::from_str(&source).unwrap();
            redact(&mut document);
            let out = render_like(&source, &document).unwrap();

            assert_eq!(
                out.contains('\n'),
                source.contains('\n'),
                "layout changed: {out}"
            );
            let order: Vec<usize> = [
                "format_version",
                "before_taken_utc",
                "after",
                "path",
                "kind",
            ]
            .iter()
            .map(|key| out.find(&format!("\"{key}\"")).unwrap())
            .collect();
            assert!(order.is_sorted(), "keys reordered: {out}");
            assert!(out.contains("%USER%"));
        }
        // The compact form really is compact, and the indented one indented.
        assert!(!compact.contains('\n'));
    }

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
        let once = redact_text("C:\\Users\\Anon\\x — S-1-5-21-1-2-3-1001 — anon42@example.com").0;
        let twice = redact_text(&once).0;
        assert_eq!(once, twice);
    }

    #[test]
    fn a_name_inside_a_binary_value_is_replaced_in_its_own_encoding() {
        // A shell link's path, as a Store application's storage table held it:
        // the account name in UTF-16, and once more in ASCII.
        let path = "C:\\Users\\Anon\\AppData\\Local\\x";
        let mut bytes = vec![0x4c, 0, 0, 0];
        bytes.extend(path.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend_from_slice(b"\0anon\\cache\0Anonymous\0");
        let names = vec![("Anon".to_owned(), USER_PLACEHOLDER)];

        let (out, hits) = redact_text_with(&encode_hex(&bytes, false), &names);

        let decoded = decode_hex(&out).expect("still hex");
        let text = String::from_utf16_lossy(
            &decoded[4..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        );
        assert!(text.starts_with("C:\\Users\\%USER%\\AppData"), "{text}");
        let narrow = String::from_utf8_lossy(&decoded);
        assert!(narrow.contains("\0%USER%\\cache"), "{narrow}");
        // The boundary rule holds in bytes as in text.
        assert!(narrow.contains("Anonymous"), "{narrow}");
        assert_eq!(hits, vec![USER_PLACEHOLDER, USER_PLACEHOLDER]);

        // And what a rewrite cannot reach is still reported.
        let mut residual = Residual::default();
        record_occurrences(&out, "anon", &mut residual);
        assert_eq!(residual.count, 1, "{:?}", residual.contexts);
        assert!(residual.contexts[0].contains("binary value"));
    }

    #[test]
    fn hex_that_spells_no_name_is_left_as_it_was() {
        let names = vec![("Anon".to_owned(), USER_PLACEHOLDER)];
        for text in ["0114020000000000C0", "deadbeef", "cafe", "abc"] {
            let (out, hits) = redact_text_with(text, &names);
            assert_eq!(out, text);
            assert!(hits.is_empty(), "{text}");
        }
    }

    #[test]
    fn an_e_mail_address_is_replaced_wherever_it_appears() {
        // The shape that reached a committed diff: the address as the last
        // component of a registry key, the account name glued to digits.
        let key =
            r"HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\anon10092@outlook.com";
        let (out, hits) = redact_text(key);
        assert_eq!(
            out,
            r"HKCU\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\%EMAIL%"
        );
        assert_eq!(hits, vec![EMAIL_PLACEHOLDER]);

        let (out, _) = redact_text("mailto:first.last+tag@sub.example.co.uk; and x@y.org.");
        assert_eq!(out, "mailto:%EMAIL%; and %EMAIL%.");

        // An image's scale suffix beside it does not hide an address.
        let (out, _) = redact_text("icon@2x.png, sent by someone@mail.example.org");
        assert_eq!(out, "icon@2x.png, sent by %EMAIL%");
    }

    #[test]
    fn things_that_merely_contain_an_at_sign_are_left_alone() {
        for text in [
            "@fmt|AnonymousData",
            "@types/node",
            "user@localhost",
            "@%SystemRoot%\\system32\\shell32.dll,-21787",
            "version 1.2@3",
            "a@b.c1",
            // Display-scale suffixes, as the EA app's Qt styles name them.
            "C:\\Program Files\\App\\QtQuick\\Controls\\Styles\\Base\\images\\arrow-down@2x.png",
            "icon@1.5x.PNG",
        ] {
            let (out, hits) = redact_text(text);
            assert_eq!(out, text, "{text} should be unchanged");
            assert!(hits.is_empty(), "{text}");
        }
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
        let report = redact(&mut document);

        assert_eq!(report.names, vec!["Anon".to_owned()]);
        let text = document.to_string();
        assert!(!text.contains("Anon."), "{text}");
        assert!(!text.contains("Pictures\\\\Anon"), "{text}");
    }

    #[test]
    fn a_learned_name_is_replaced_in_any_letter_case() {
        // Windows account names are case-insensitive, and applications write
        // them however they like.
        let mut document = serde_json::json!({
            "files": [
                { "path": "C:\\Users\\Anon\\AppData\\Local\\x" },
                { "path": "C:\\ProgramData\\Vendor\\ANON\\settings.json" },
                { "data": "last user: anon" }
            ]
        });
        let report = redact(&mut document);

        let text = document.to_string();
        assert!(!text.to_ascii_lowercase().contains("anon"), "{text}");
        assert!(report.residual.is_empty());
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
        redact(&mut document);
        assert!(document.to_string().contains("Anonymous"));
    }

    #[test]
    fn what_could_not_be_removed_is_counted_and_shown_in_context() {
        // The boundary rule leaves this behind by construction. Reporting it,
        // and showing where, is the difference between a tool that is honest
        // and one that is trusted wrongly — the previous report said only that
        // a residue was "`Anonymous` and the like", and it was an address.
        let mut document = serde_json::json!({
            "files": [
                { "path": "C:\\Users\\Anon\\x" },
                { "path": "C:\\JetBrains\\fileHistory\\Anonb7a4e505-ngram" }
            ]
        });
        let report = redact(&mut document);

        let residual = &report.residual["Anon"];
        assert_eq!(residual.count, 1);
        assert_eq!(
            residual.contexts,
            vec!["…:\\JetBrains\\fileHistory\\[NAME]b7a4e505-ngram"]
        );
    }

    #[test]
    fn a_residual_in_another_case_or_in_an_object_key_is_still_counted() {
        let mut document = serde_json::json!({
            "files": [{ "path": "C:\\Users\\Anon\\x" }, { "path": "D:\\ANONb7\\y" }],
            "signers": { "Anon Signing CA": 1 }
        });
        let report = redact(&mut document);
        assert_eq!(report.residual["Anon"].count, 2);
    }

    #[test]
    fn a_clean_document_reports_no_residual() {
        let mut document = serde_json::json!({
            "files": [{ "path": "C:\\Users\\Anon\\AppData\\Local\\x" }]
        });
        let report = redact(&mut document);
        assert!(report.residual.is_empty());
    }

    #[test]
    fn supplied_names_are_replaced_too_and_short_ones_are_refused() {
        // A redacted file teaches no name, and a computer name never had a
        // path to be learned from. Both come from the caller.
        let mut document = serde_json::json!({
            "values": [
                { "name": "HostNameCollection", "data": "DESKTOP-ANON7;ANON-PC" },
                { "name": "UserNameCollection", "data": "someone" }
            ]
        });
        let extra = Extra {
            accounts: vec!["someone".to_owned(), "jo".to_owned()],
            computers: vec!["ANON-PC".to_owned()],
            ..Extra::default()
        };
        let report = redact_document(&mut document, &extra);

        let text = document.to_string();
        assert!(
            !text.contains("ANON-PC") && !text.contains("someone"),
            "{text}"
        );
        assert!(
            text.contains("%COMPUTER%") && text.contains("%USER%"),
            "{text}"
        );
        assert_eq!(report.skipped, vec!["jo".to_owned()]);
        assert_eq!(report.computers, vec!["ANON-PC".to_owned()]);
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
        let report = redact(&mut document);

        let text = document.to_string();
        assert!(!text.contains("Anon"), "{text}");
        assert_eq!(report.applied[USER_PLACEHOLDER], 3);
    }

    #[test]
    fn object_keys_are_left_alone() {
        // Rewriting a key would produce a document that no longer deserialises
        // into the model it came from.
        let mut document = serde_json::json!({ "C:\\Users\\Anon": "C:\\Users\\Anon" });
        redact(&mut document);

        let object = document.as_object().unwrap();
        assert!(object.contains_key("C:\\Users\\Anon"));
        assert_eq!(object["C:\\Users\\Anon"], "C:\\Users\\%USER%");
    }
}
