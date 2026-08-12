//! Expansion of the `%VAR%` placeholders a catalog path may contain.
//!
//! `docs/04-CATALOG-SCHEMA.md` lists exactly ten variables and states they are
//! "expanded by the broker, never by the shell". This module handles the
//! *validation-time* half of that: turning a template into the set of concrete
//! paths it could denote, so the deny-list can be run against all of them
//! before a catalog is ever trusted.
//!
//! The roots used here are representative, not discovered. At runtime the
//! broker substitutes real values — including one expansion per local user
//! profile and one per discovered game library. For validation the point is
//! only to reach the locations that would trip the deny-list, so a fixed set
//! that covers the interesting shapes is both sufficient and deterministic.

/// The complete set of variables a catalog may use.
pub const KNOWN_VARIABLES: &[&str] = &[
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "SystemRoot",
    "PUBLIC",
    "STEAM_LIBRARY",
    "EPIC_LIBRARY",
];

/// Why a template could not be expanded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    /// A `%NAME%` the schema does not define.
    #[error("unknown path variable `%{0}%`")]
    UnknownVariable(String),
    /// A lone `%` with no closing delimiter.
    #[error("unterminated `%` in path template")]
    UnterminatedVariable,
}

/// Representative expansions used during validation.
///
/// Multi-valued variables deliberately include a second volume, because
/// `docs/13-P0-SPIKES.md` S2 calls out a game installed on a second volume as a
/// case that must work.
fn candidates_for(name: &str) -> Option<&'static [&'static str]> {
    Some(match name.to_ascii_uppercase().as_str() {
        "PROGRAMFILES" => &[r"C:\Program Files"],
        "PROGRAMFILES(X86)" => &[r"C:\Program Files (x86)"],
        "PROGRAMDATA" => &[r"C:\ProgramData"],
        "LOCALAPPDATA" => &[r"C:\Users\ExampleUser\AppData\Local"],
        "APPDATA" => &[r"C:\Users\ExampleUser\AppData\Roaming"],
        "USERPROFILE" => &[r"C:\Users\ExampleUser"],
        "SYSTEMROOT" => &[r"C:\Windows"],
        "PUBLIC" => &[r"C:\Users\Public"],
        "STEAM_LIBRARY" => &[r"C:\Program Files (x86)\Steam", r"D:\SteamLibrary"],
        "EPIC_LIBRARY" => &[r"C:\Program Files\Epic Games", r"D:\Epic Games"],
        _ => return None,
    })
}

/// Expand a template into every concrete path it could denote.
///
/// A template with no variables expands to itself. A template using a
/// multi-valued variable expands to one path per value.
///
/// # Errors
///
/// Returns [`ExpandError`] if the template names a variable the schema does not
/// define, or has an unterminated `%`.
pub fn expand_for_validation(template: &str) -> Result<Vec<String>, ExpandError> {
    let mut results = vec![String::new()];
    let mut rest = template;

    while let Some(start) = rest.find('%') {
        let (literal, after) = rest.split_at(start);
        let after = &after[1..];
        let Some(end) = after.find('%') else {
            return Err(ExpandError::UnterminatedVariable);
        };
        let name = &after[..end];
        let Some(values) = candidates_for(name) else {
            return Err(ExpandError::UnknownVariable(name.to_owned()));
        };

        results = results
            .into_iter()
            .flat_map(|prefix| {
                values.iter().map(move |value| {
                    let mut next = prefix.clone();
                    next.push_str(literal);
                    next.push_str(value);
                    next
                })
            })
            .collect();

        rest = &after[end + 1..];
    }

    for result in &mut results {
        result.push_str(rest);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_without_variables_expands_to_itself() {
        assert_eq!(
            expand_for_validation(r"C:\Games\Example").unwrap(),
            vec![r"C:\Games\Example".to_owned()]
        );
    }

    #[test]
    fn single_valued_variables_produce_one_path() {
        assert_eq!(
            expand_for_validation(r"%ProgramData%\ExampleAC\logs").unwrap(),
            vec![r"C:\ProgramData\ExampleAC\logs".to_owned()]
        );
        // Parentheses inside the variable name must survive.
        assert_eq!(
            expand_for_validation(r"%ProgramFiles(x86)%\ExampleAC").unwrap(),
            vec![r"C:\Program Files (x86)\ExampleAC".to_owned()]
        );
    }

    #[test]
    fn multi_valued_variables_produce_one_path_per_library() {
        let expanded =
            expand_for_validation(r"%STEAM_LIBRARY%\steamapps\common\Example Shooter").unwrap();
        assert_eq!(expanded.len(), 2);
        assert!(expanded.iter().any(|p| p.starts_with(r"D:\SteamLibrary")));
    }

    #[test]
    fn systemroot_expands_somewhere_the_denylist_will_catch() {
        // A catalog writing %SystemRoot%\System32 must not slip past the
        // deny-list just because it used a variable.
        assert_eq!(
            expand_for_validation(r"%SystemRoot%\System32\evil").unwrap(),
            vec![r"C:\Windows\System32\evil".to_owned()]
        );
    }

    #[test]
    fn unknown_and_unterminated_variables_are_errors() {
        assert_eq!(
            expand_for_validation(r"%WINDIR%\System32"),
            Err(ExpandError::UnknownVariable("WINDIR".to_owned()))
        );
        assert_eq!(
            expand_for_validation(r"%ProgramData\Foo"),
            Err(ExpandError::UnterminatedVariable)
        );
    }
}
