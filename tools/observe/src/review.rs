//! What a person has to look at before a diff is committed.
//!
//! `redact` removes the identity it can name: account names it learned or was
//! given, e-mail addresses, machine SIDs, host names. What it cannot name it
//! cannot remove, and that is how the committed diffs came to carry an
//! account's e-mail address, hex-encoded shell links with the account name in
//! them, and identifiers in file names (`docs/PROGRESS.md`, "The 2026-10-08
//! audit"; `observations/2026-10-09-ea-anticheat/notes.md`). The review that
//! caught the rest was a set of scratch scripts run by hand.
//!
//! This is that review, in the harness. It reads a diff and lists what looks
//! like an identifier, grouped by kind, each distinct value once with a count
//! and one place it occurs. It changes nothing and decides nothing: a person
//! reads the list, masks what is personal with `redact --also-id`, and runs it
//! again until every remaining entry is understood. While anything is listed
//! the command exits non-zero, so a script cannot commit the diff by accident.
//!
//! # What it looks for
//!
//! - **Identity `redact` would still remove**: its own rules for e-mail
//!   addresses, profile paths, SIDs and host names, run again over every
//!   string, so a diff redacted by an older build or not at all is caught.
//! - **Hex-encoded text**: a registry binary reaches a diff as hex digits, and
//!   a shell link inside one carries paths as UTF-16 bytes no text rule sees.
//!   Every hex value is decoded both ways and searched like text.
//! - **Machine-key file names**: 32 hex digits, `_`, and a GUID — the shape of
//!   a `CryptoAPI` key file, whose suffix is the machine's GUID, which Safety Gate
//!   G3 forbids reading at all.
//! - **Identifier-shaped names** in paths and registry keys: a run of nine or
//!   more digits (an account number, a timestamp), a run of sixteen or more hex
//!   digits mixing letters and digits (a hash of something), and a GUID in a
//!   per-user path or key.
//! - **The `before` side of a modified value that held a path**: a rotating
//!   slot — a most-recently-used list, a jump list — that names whatever else
//!   the machine ran, on the side `redact` has no reason to look at.
//!
//! The patterns are deliberately wide. A version folder of nine digits or a
//! package hash is listed too, and a person reads past it; the cost of the
//! opposite mistake is in the repository's history for good. Classes that are
//! known to be harmless — a Windows component store's hash names, COM
//! registrations — are data in `review-benign.txt`, not code, so the list can
//! be argued with without touching a matcher.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::redact;

/// Contexts in which an identifier-shaped name is known to be harmless, one
/// lower-cased fragment per line.
const BENIGN: &str = include_str!("review-benign.txt");

/// Characters kept either side of a finding in its context.
const CONTEXT_CHARS: usize = 40;

/// The shortest digit run reported.
const MIN_DIGITS: usize = 9;

/// The shortest hex run reported.
const MIN_HEX: usize = 16;

/// What a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A rule `redact` has would still change this string.
    Unredacted,
    /// Identity found inside a hex-encoded value.
    HexText,
    /// A `CryptoAPI` machine-key file name.
    MachineKey,
    /// A long run of digits in a path or key.
    Digits,
    /// A long run of hex digits in a path or key.
    Hash,
    /// A GUID in a per-user path or key.
    Guid,
    /// A path on the before side of a modified value.
    Before,
}

impl Kind {
    /// What a reader is told about this kind, once.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Unredacted => {
                "identity `redact` would remove — run `redact` on this file before anything else"
            }
            Self::HexText => {
                "identity inside a hex-encoded value: decode it and mask the name or identifier"
            }
            Self::MachineKey => {
                "a CryptoAPI machine-key file name, whose suffix is the machine's GUID (G3): \
                 mask it, and find out why the walk reached it"
            }
            Self::Digits => {
                "a long run of digits: an account or device number is personal, a build number is not"
            }
            Self::Hash => "a long hash: a hash of an account or a machine is personal",
            Self::Guid => "a GUID in a per-user path or key: an install or account id is personal",
            Self::Before => {
                "the earlier value of a modified slot held a path: a recent-items list names \
                 what else ran on the machine"
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Unredacted => "unredacted",
            Self::HexText => "hex-text",
            Self::MachineKey => "machine-key",
            Self::Digits => "digits",
            Self::Hash => "hash",
            Self::Guid => "guid",
            Self::Before => "before",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One place something of one kind was found: a value, or — for the
/// identifier shapes, which come in their hundreds from a cache — the folder
/// or key holding them, with the values found there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// How many times it occurs.
    pub count: usize,
    /// The distinct values found here.
    pub values: BTreeSet<String>,
    /// Where it first occurs, as a path into the document.
    pub at: String,
    /// The text around its first occurrence.
    pub context: String,
}

/// Everything a review found, by kind and then by where.
pub type Findings = BTreeMap<Kind, BTreeMap<String, Finding>>;

/// Review a diff, read as plain JSON so that nothing the schema gained after
/// this was written can be skipped.
#[must_use]
pub fn review(document: &serde_json::Value) -> Findings {
    let benign: Vec<&str> = BENIGN
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let mut walk = Walk {
        at: String::new(),
        owner: None,
        benign: &benign,
        findings: Findings::new(),
    };
    walk.visit(document);
    walk.findings
}

/// The state of one review: where in the document it is, and what owns the
/// strings there.
struct Walk<'a> {
    at: String,
    /// The registry key or file path of the innermost record being read, so a
    /// value change is grouped under the key it belongs to.
    owner: Option<String>,
    benign: &'a [&'a str],
    findings: Findings,
}

/// One occurrence, before it is grouped.
struct Hit<'t> {
    kind: Kind,
    group: String,
    value: &'t str,
    text: &'t str,
    offset: usize,
}

impl Walk<'_> {
    fn visit(&mut self, value: &serde_json::Value) {
        match value {
            serde_json::Value::String(text) => self.check(text),
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let length = self.at.len();
                    let _ = write!(self.at, "[{index}]");
                    self.visit(item);
                    self.at.truncate(length);
                }
            }
            serde_json::Value::Object(fields) => {
                let owner = ["key", "path"]
                    .iter()
                    .find_map(|name| fields.get(*name).and_then(serde_json::Value::as_str));
                let outer = owner.map(|owner| self.owner.replace(owner.to_owned()));
                for (name, item) in fields {
                    let length = self.at.len();
                    if !self.at.is_empty() {
                        self.at.push('.');
                    }
                    self.at.push_str(name);
                    // An object's own keys are text too: the e-mail address that
                    // reached the repository was the name of a registry key.
                    self.check(name);
                    self.visit(item);
                    self.at.truncate(length);
                }
                if let Some(outer) = outer {
                    self.owner = outer;
                }
            }
            _ => {}
        }
    }

    fn record(&mut self, hit: &Hit<'_>) {
        let finding = self
            .findings
            .entry(hit.kind)
            .or_default()
            .entry(hit.group.clone())
            .or_insert_with(|| Finding {
                count: 0,
                values: BTreeSet::new(),
                at: self.at.clone(),
                context: context(hit.text, hit.offset, hit.value.len()),
            });
        finding.count += 1;
        finding.values.insert(hit.value.to_owned());
    }

    fn check(&mut self, text: &str) {
        let mut hits = Vec::new();
        let (redacted, applied) = redact::redact_text_with(text, &[]);
        let applied = applied.join(",");
        if !applied.is_empty() && redacted != text {
            hits.push(Hit {
                kind: Kind::Unredacted,
                group: applied.clone(),
                value: &applied,
                text,
                offset: 0,
            });
        }

        // A value change writes a binary as `binary:<hex>`; a record's own
        // values write the hex alone.
        let hex = text.strip_prefix("binary:").unwrap_or(text);
        if let Some(bytes) = redact::decode_hex(hex).filter(|_| hex.len() >= MIN_HEX) {
            for decoded in decodings(&bytes) {
                self.check_decoded(&decoded);
            }
            // A hex value is data, not a name: the shape checks below would
            // list every binary in the diff.
            for hit in &hits {
                self.record(hit);
            }
            return;
        }

        for (offset, found) in machine_keys(text) {
            hits.push(Hit {
                kind: Kind::MachineKey,
                group: found.to_owned(),
                value: found,
                text,
                offset,
            });
        }

        let lowered = text.to_ascii_lowercase();
        if self.at.ends_with(".before")
            && self.at.contains(".fields[")
            && holds_path(text)
            && self.owner.as_deref().is_some_and(is_history_slot)
        {
            hits.push(Hit {
                kind: Kind::Before,
                group: self.owner.clone().unwrap_or_else(|| text.to_owned()),
                value: text,
                text,
                offset: 0,
            });
        }
        if is_path_like(&lowered)
            && !self
                .benign
                .iter()
                .any(|fragment| lowered.contains(fragment))
        {
            hits.extend(shapes(text, &lowered));
        }
        for hit in &hits {
            self.record(hit);
        }
    }

    fn check_decoded(&mut self, decoded: &str) {
        let (redacted, applied) = redact::redact_text_with(decoded, &[]);
        let applied = applied.join(",");
        if !applied.is_empty() && redacted != decoded {
            self.record(&Hit {
                kind: Kind::HexText,
                group: applied.clone(),
                value: &applied,
                text: decoded,
                offset: 0,
            });
        }
        for (offset, found) in machine_keys(decoded) {
            self.record(&Hit {
                kind: Kind::HexText,
                group: found.to_owned(),
                value: found,
                text: decoded,
                offset,
            });
        }
    }
}

/// The identifier shapes in a path or key, each grouped under the folder or key
/// holding the first of its kind: a cache names a thousand files after hashes,
/// and they are one thing to read.
fn shapes<'t>(text: &'t str, lowered: &str) -> Vec<Hit<'t>> {
    let mut found: Vec<(Kind, usize, &'t str)> = Vec::new();
    found.extend(
        runs(text, MIN_DIGITS, |byte| byte.is_ascii_digit())
            .into_iter()
            .map(|(offset, value)| (Kind::Digits, offset, value)),
    );
    found.extend(
        runs(text, MIN_HEX, |byte| byte.is_ascii_hexdigit())
            .into_iter()
            .filter(|(_, value)| {
                value.bytes().any(|byte| byte.is_ascii_digit())
                    && value.bytes().any(|byte| byte.is_ascii_alphabetic())
            })
            .map(|(offset, value)| (Kind::Hash, offset, value)),
    );
    if is_per_user(lowered) {
        found.extend(
            guids(text)
                .into_iter()
                .map(|(offset, value)| (Kind::Guid, offset, value)),
        );
    }
    let mut first: BTreeMap<Kind, usize> = BTreeMap::new();
    for (kind, offset, _) in &found {
        first
            .entry(*kind)
            .and_modify(|earliest| *earliest = (*earliest).min(*offset))
            .or_insert(*offset);
    }
    found
        .into_iter()
        .map(|(kind, offset, value)| Hit {
            kind,
            group: location(text, first[&kind]),
            value,
            text,
            offset,
        })
        .collect()
}

/// The folder or key a value at `offset` sits in: the text up to and with the
/// last separator before it.
fn location(text: &str, offset: usize) -> String {
    text[..offset]
        .rfind('\\')
        .map_or_else(|| text[..offset].to_owned(), |at| text[..=at].to_owned())
}

/// A file path, a registry key, or a path already redacted to a placeholder.
fn is_path_like(lowered: &str) -> bool {
    holds_path(lowered)
        || [
            "hklm\\",
            "hkcu\\",
            "hku\\",
            "%user",
            "%localappdata%",
            "%appdata%",
        ]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

/// Whether a string holds a drive-rooted path anywhere.
fn holds_path(text: &str) -> bool {
    text.as_bytes()
        .windows(3)
        .any(|window| window[0].is_ascii_alphabetic() && window[1] == b':' && window[2] == b'\\')
}

/// Paths and keys that belong to one account rather than to the machine.
fn is_per_user(lowered: &str) -> bool {
    (lowered.contains("\\users\\") || lowered.starts_with("hkcu\\") || lowered.starts_with("hku\\"))
        && !lowered.contains("\\classes\\")
}

/// A key whose values are slots that rotate through what the machine did: one
/// account's keys, or a history the system keeps. A machine-wide setting that
/// held an older program's path is an update, and is not listed.
fn is_history_slot(owner: &str) -> bool {
    let lowered = owner.to_ascii_lowercase();
    lowered.starts_with("hkcu\\")
        || lowered.starts_with("hku\\")
        || ["\\ufh\\", "mru", "recent", "history", "jumplist"]
            .iter()
            .any(|marker| lowered.contains(marker))
}

/// Maximal runs of bytes `accept` takes, at least `minimum` long, that stand
/// on their own: no letter or digit directly either side.
fn runs(text: &str, minimum: usize, accept: impl Fn(u8) -> bool) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !accept(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && accept(bytes[end]) {
            end += 1;
        }
        let alone = (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
            && (end == bytes.len() || !bytes[end].is_ascii_alphanumeric());
        if end - start >= minimum && alone {
            found.push((start, &text[start..end]));
        }
        start = end;
    }
    found
}

/// Whether `text[at..]` begins with a GUID's 8-4-4-4-12 hex digits.
fn guid_at(bytes: &[u8], at: usize) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut position = at;
    for (index, length) in GROUPS.iter().enumerate() {
        if index > 0 {
            if bytes.get(position) != Some(&b'-') {
                return false;
            }
            position += 1;
        }
        let Some(group) = bytes.get(position..position + length) else {
            return false;
        };
        if !group.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        position += length;
    }
    true
}

/// GUIDs in a string, braces or none.
fn guids(text: &str) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while at + 36 <= bytes.len() {
        let alone = at == 0 || !bytes[at - 1].is_ascii_hexdigit();
        if alone
            && guid_at(bytes, at)
            && bytes
                .get(at + 36)
                .is_none_or(|byte| !byte.is_ascii_hexdigit())
        {
            found.push((at, &text[at..at + 36]));
            at += 36;
        } else {
            at += 1;
        }
    }
    found
}

/// `<32 hex digits>_<GUID>`: a `CryptoAPI` key file's name.
fn machine_keys(text: &str) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (start, run) in runs(text, 32, |byte| byte.is_ascii_hexdigit() || byte == b'_') {
        let Some(separator) = run.find('_') else {
            continue;
        };
        let at = start + separator;
        if separator >= 32 && bytes.get(at) == Some(&b'_') && guid_at(bytes, at + 1) {
            let begin = at - 32;
            found.push((begin, &text[begin..at + 37]));
        }
    }
    found
}

/// The text a byte string could be: UTF-16LE when every other byte is zero
/// often enough to read, and the printable ASCII it holds either way.
fn decodings(bytes: &[u8]) -> Vec<String> {
    let mut texts = Vec::new();
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let wide = String::from_utf16_lossy(&units);
    if wide.chars().filter(char::is_ascii_graphic).count() >= 8 {
        texts.push(printable(&wide));
    }
    let narrow: String = bytes.iter().map(|&byte| char::from(byte)).collect();
    texts.push(printable(&narrow));
    texts
}

/// Non-printing characters as spaces, so a decoded binary reads as text with
/// gaps where its structure was.
fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                ' '
            }
        })
        .collect()
}

fn context(text: &str, offset: usize, length: usize) -> String {
    let start = text.floor_char_boundary(offset.saturating_sub(CONTEXT_CHARS));
    let end = text.ceil_char_boundary((offset + length + CONTEXT_CHARS).min(text.len()));
    let mut context = String::new();
    if start > 0 {
        context.push('…');
    }
    context.push_str(text[start..end].trim());
    if end < text.len() {
        context.push('…');
    }
    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every value found, with its kind, whatever group it is in.
    fn kinds(document: &serde_json::Value) -> Vec<(Kind, String)> {
        review(document)
            .into_iter()
            .flat_map(|(kind, groups)| {
                groups.into_values().flat_map(move |finding| {
                    finding.values.into_iter().map(move |value| (kind, value))
                })
            })
            .collect()
    }

    #[test]
    fn a_clean_diff_has_nothing_to_say() {
        let document = json!({
            "files": [{ "path": "C:\\Program Files\\EA\\AC\\EAAntiCheat.GameService.exe" }],
            "registry": [{ "key": "HKLM\\SOFTWARE\\EA\\AC", "view": "64" }],
        });
        assert_eq!(kinds(&document), []);
    }

    #[test]
    fn identity_redact_would_remove_is_listed() {
        let document = json!({
            "registry": [{ "key": "HKCU\\SOFTWARE\\Microsoft\\IdentityCRL\\someone1990@example.com" }],
        });
        let found = kinds(&document);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, Kind::Unredacted);
    }

    #[test]
    fn a_profile_path_already_redacted_is_not() {
        let document =
            json!({ "path": "C:\\Users\\%USER%\\AppData\\Local\\EA SPORTS FC 26\\settings.ini" });
        assert_eq!(kinds(&document), []);
    }

    #[test]
    fn identity_inside_a_hex_value_is_listed() {
        // A shell link's path, UTF-16LE, as a registry binary reaches a diff.
        let path = "C:\\Users\\someone\\Documents\\x.lnk";
        let hex: String =
            path.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02X}");
                    hex
                });
        let document = json!({ "fields": [{ "field": "Data", "before": "", "after": hex }] });
        let found = kinds(&document);
        assert!(
            found.iter().any(|(kind, _)| *kind == Kind::HexText),
            "{found:?}"
        );
    }

    #[test]
    fn a_machine_key_name_is_always_listed() {
        let name = format!(
            "{}_{}",
            "a".repeat(32),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        let document = json!({ "path": format!("C:\\ProgramData\\Example\\{name}") });
        assert_eq!(kinds(&document), [(Kind::MachineKey, name)]);
    }

    #[test]
    fn identifier_shaped_names_in_paths_are_listed() {
        let document = json!({
            "files": [
                { "path": "D:\\SteamLibrary\\steamapps\\common\\Game\\Saved\\76561198000000000\\save.sav" },
                { "path": "C:\\Users\\%USER%\\AppData\\Local\\Vendor\\3f2a9c1b7d4e8f60a1b2\\cache" },
            ],
        });
        let found = kinds(&document);
        assert!(
            found.contains(&(Kind::Digits, "76561198000000000".to_owned())),
            "{found:?}"
        );
        assert!(
            found.contains(&(Kind::Hash, "3f2a9c1b7d4e8f60a1b2".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn a_guid_is_listed_only_where_it_belongs_to_one_account() {
        let guid = "{0D4E3A27-1B9F-4C6A-8E5D-2F7B9C1A3E64}";
        let document = json!({
            "registry": [
                { "key": format!("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{guid}") },
                { "key": format!("HKCU\\SOFTWARE\\Vendor\\Sessions\\{guid}") },
                { "key": format!("HKCU\\SOFTWARE\\Classes\\CLSID\\{guid}") },
            ],
        });
        let found = kinds(&document);
        assert_eq!(found, [(Kind::Guid, guid[1..37].to_owned())], "{found:?}");
        assert_eq!(
            review(&document)[&Kind::Guid]["HKCU\\SOFTWARE\\Vendor\\Sessions\\"].count,
            1
        );
    }

    #[test]
    fn a_rotating_slot_that_held_a_path_is_listed() {
        let document = json!({
            "registry": [{
                "key": "HKCU\\SOFTWARE\\Vendor\\Recent",
                "fields": [{ "field": "MRU0", "before": "E:\\Tools\\other-program.exe", "after": "" }],
            }],
        });
        let found = kinds(&document);
        assert_eq!(
            found,
            [(Kind::Before, "E:\\Tools\\other-program.exe".to_owned())]
        );
        // Grouped under the key it belongs to, which is what a reader judges.
        assert!(review(&document)[&Kind::Before].contains_key("HKCU\\SOFTWARE\\Vendor\\Recent"));
    }

    #[test]
    fn a_binary_value_change_is_decoded_like_any_other_hex() {
        // The DHCP option cache reached a committed diff this way.
        let text = "C:\\Users\\someone\\x";
        let hex: String = text.bytes().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        let document = json!({ "fields": [{ "field": "Options", "before": format!("binary:{hex}"), "after": "" }] });
        let found = kinds(&document);
        assert!(
            found.iter().any(|(kind, _)| *kind == Kind::HexText),
            "{found:?}"
        );
    }

    #[test]
    fn a_cache_full_of_hashes_is_one_thing_to_read() {
        let files: Vec<serde_json::Value> = (0..50)
            .map(|index| {
                json!({ "path": format!(
                    "C:\\Users\\%USER%\\AppData\\Local\\NVIDIA\\GLCache\\{index:02}a1b2c3d4e5f6a7b8c9\\x.bin"
                ) })
            })
            .collect();
        let findings = review(&json!({ "files": files }));
        let hashes = &findings[&Kind::Hash];
        assert_eq!(hashes.len(), 1, "{:?}", hashes.keys());
        let cache = &hashes["C:\\Users\\%USER%\\AppData\\Local\\NVIDIA\\GLCache\\"];
        assert_eq!(cache.count, 50);
        assert_eq!(cache.values.len(), 50);
    }

    #[test]
    fn short_and_embedded_runs_are_not_identifiers() {
        let document = json!({
            "files": [
                { "path": "C:\\Program Files\\Vendor\\12345678\\x.dll" },
                { "path": "C:\\Program Files\\Vendor\\build1234567890x\\x.dll" },
            ],
        });
        assert_eq!(kinds(&document), []);
    }

    #[test]
    fn each_value_is_listed_once_with_its_count() {
        let document = json!([
            { "path": "C:\\Users\\%USER%\\AppData\\Local\\V\\123456789012\\a" },
            { "path": "C:\\Users\\%USER%\\AppData\\Local\\V\\123456789012\\b" },
        ]);
        let findings = review(&document);
        let digits = &findings[&Kind::Digits]["C:\\Users\\%USER%\\AppData\\Local\\V\\"];
        assert_eq!(digits.count, 2);
        assert_eq!(digits.values.len(), 1);
        assert_eq!(digits.at, "[0].path");
    }

    #[test]
    fn the_benign_list_is_read_from_its_file() {
        assert!(
            BENIGN
                .lines()
                .any(|line| line.trim() == "\\windows\\winsxs\\")
        );
    }
}
