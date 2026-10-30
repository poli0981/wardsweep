//! Game libraries, found from the launchers' own manifests.
//!
//! `docs/05-DETECTION-ENGINE.md` seeds the filesystem walk from "discovered
//! Steam/Epic/EA/Ubisoft/Battle.net/Riot library roots", and the observation
//! harness walks the same roots (`docs/16-OBSERVATION-HARNESS.md`): both titles
//! of the October 2026 cycle were installed in a Steam library on a second
//! volume that nothing walked, and their folders had to be listed by hand.
//!
//! # Manifests only
//!
//! A library on another volume is found because a launcher names it, never by
//! enumerating volumes. Safety Gate G3 rules the volume APIs out, and
//! `core/tests/no_destructive_code.rs` names them; a volume no launcher names
//! is not a library. The same applies to S2's finding that "absence of a game
//! from the library paths you thought to check is not evidence of absence": the
//! answer is the launcher's own record, not a guess at where games might be.
//!
//! Everything here is parsing and `std::fs` reads, so it is portable and tested
//! on Linux. Where a launcher keeps its manifests — Steam's install directory
//! is in the registry — is the caller's question.
//!
//! Steam and Epic are read today. EA app, Ubisoft Connect, Battle.net and Riot
//! keep theirs elsewhere and are not, so a game installed only through one of
//! them is outside these libraries.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The launcher whose manifest names a library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Launcher {
    /// Steam, from `steamapps\libraryfolders.vdf`.
    Steam,
    /// The Epic Games Launcher, from its per-game `.item` manifests.
    Epic,
}

/// A folder a launcher installs games into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// The launcher whose manifest names it.
    pub launcher: Launcher,
    /// The library as `docs/04-CATALOG-SCHEMA.md`'s `%STEAM_LIBRARY%` and
    /// `%EPIC_LIBRARY%` mean it: the folder holding `steamapps` for Steam, the
    /// folder holding the games for Epic. Backslash-separated, with no trailing
    /// separator.
    pub path: String,
}

impl Library {
    /// The folder the games themselves are in: `<library>\steamapps\common`
    /// for Steam, the library itself for Epic.
    #[must_use]
    pub fn games(&self) -> String {
        match self.launcher {
            Launcher::Steam => format!("{}\\steamapps\\common", self.path),
            Launcher::Epic => self.path.clone(),
        }
    }

    /// The catalog variable that names this library.
    #[must_use]
    pub fn variable(&self) -> &'static str {
        match self.launcher {
            Launcher::Steam => "STEAM_LIBRARY",
            Launcher::Epic => "EPIC_LIBRARY",
        }
    }
}

/// A manifest that names libraries but could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// The manifest's path.
    pub path: String,
    /// Why, in whatever terms the platform or the parser gave.
    pub reason: String,
}

/// What [`discover`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// Every library the manifests name, once each, Steam first, then by path.
    pub libraries: Vec<Library>,
    /// Manifests that exist and could not be read. A launcher whose library
    /// list is unreadable is not a launcher with no libraries, and a caller
    /// reporting coverage has to be able to say so.
    pub unreadable: Vec<Unreadable>,
}

/// Find the libraries Steam and the Epic Games Launcher name.
///
/// `steam_install` is Steam's own directory, which holds
/// `steamapps\libraryfolders.vdf`; `epic_manifests` is the Epic Games
/// Launcher's `Data\Manifests` directory. Either may be `None` when that
/// launcher is not installed, and a missing manifest file means the same.
#[must_use]
pub fn discover(steam_install: Option<&Path>, epic_manifests: Option<&Path>) -> Found {
    let mut found = Found::default();

    if let Some(steam) = steam_install {
        let manifest = steam.join("steamapps").join("libraryfolders.vdf");
        match std::fs::read_to_string(&manifest) {
            Ok(text) => match steam_library_paths(&text) {
                Ok(paths) => found
                    .libraries
                    .extend(paths.into_iter().map(|path| Library {
                        launcher: Launcher::Steam,
                        path,
                    })),
                Err(reason) => found.unreadable.push(Unreadable {
                    path: manifest.to_string_lossy().into_owned(),
                    reason,
                }),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => found.unreadable.push(Unreadable {
                path: manifest.to_string_lossy().into_owned(),
                reason: error.to_string(),
            }),
        }
    }

    if let Some(directory) = epic_manifests {
        read_epic_manifests(directory, &mut found);
    }

    found.libraries = deduplicated(found.libraries);
    found
}

fn read_epic_manifests(directory: &Path, found: &mut Found) {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            found.unreadable.push(Unreadable {
                path: directory.to_string_lossy().into_owned(),
                reason: error.to_string(),
            });
            return;
        }
    };
    let mut manifests: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("item"))
        })
        .collect();
    manifests.sort();
    for manifest in manifests {
        let parsed = std::fs::read_to_string(&manifest)
            .map_err(|error| error.to_string())
            .and_then(|text| epic_install_location(&text));
        match parsed {
            Ok(Some(location)) => found.libraries.push(Library {
                launcher: Launcher::Epic,
                path: epic_library_of(&location),
            }),
            Ok(None) => {}
            Err(reason) => found.unreadable.push(Unreadable {
                path: manifest.to_string_lossy().into_owned(),
                reason,
            }),
        }
    }
}

/// The libraries every list names, in the first list's order: what a set of
/// observations all covered. Paths are compared without regard to case.
///
/// No list at all gives nothing, and so does any empty list: a snapshot that
/// walked no library did not cover one.
#[must_use]
pub fn common<'a>(mut lists: impl Iterator<Item = &'a [Library]>) -> Vec<Library> {
    let Some(first) = lists.next() else {
        return Vec::new();
    };
    let mut kept: Vec<Library> = first.to_vec();
    for list in lists {
        kept.retain(|library| {
            list.iter().any(|other| {
                other.launcher == library.launcher && other.path.eq_ignore_ascii_case(&library.path)
            })
        });
    }
    kept
}

/// One library per launcher and path, compared without regard to case, Steam
/// first and then by path.
fn deduplicated(mut libraries: Vec<Library>) -> Vec<Library> {
    libraries.sort_by(|left, right| {
        (left.launcher, left.path.to_ascii_lowercase())
            .cmp(&(right.launcher, right.path.to_ascii_lowercase()))
    });
    libraries.dedup_by(|later, earlier| {
        later.launcher == earlier.launcher && later.path.eq_ignore_ascii_case(&earlier.path)
    });
    libraries
}

/// A path as a manifest wrote it, in the form [`Library::path`] promises:
/// backslashes, no trailing separator. `None` for an empty path.
fn normalised(path: &str) -> Option<String> {
    let path = path.trim().replace('/', "\\");
    let path = path.trim_end_matches('\\');
    // `D:\` trims to `D:`, which names the drive's current directory rather than
    // its root; keep the separator for a bare drive.
    let path = if is_drive(path) {
        format!("{path}\\")
    } else {
        path.to_owned()
    };
    (!path.is_empty()).then_some(path)
}

/// `D:` and the like: a drive with no directory below it.
fn is_drive(path: &str) -> bool {
    path.len() == 2 && path.ends_with(':')
}

/// The folder that holds an Epic game, as `%EPIC_LIBRARY%`.
///
/// Epic installs each game into a folder of its own below the location the
/// user chose, so the library is the game folder's parent — unless that parent
/// is a drive's root, where walking it would mean walking the whole volume,
/// and the game folder stands in for its own library.
fn epic_library_of(install_location: &str) -> String {
    match install_location.rsplit_once('\\') {
        Some((parent, _)) if !parent.is_empty() && !is_drive(parent) => parent.to_owned(),
        _ => install_location.to_owned(),
    }
}

/// The install location an Epic `.item` manifest names, normalised.
///
/// `Ok(None)` for a manifest with no `InstallLocation`, or an empty one.
///
/// # Errors
/// If the manifest is not JSON.
pub fn epic_install_location(item_json: &str) -> Result<Option<String>, String> {
    let manifest: serde_json::Value = serde_json::from_str(item_json)
        .map_err(|error| format!("not an Epic manifest: {error}"))?;
    Ok(manifest
        .get("InstallLocation")
        .and_then(serde_json::Value::as_str)
        .and_then(normalised))
}

/// The library paths Steam's `libraryfolders.vdf` names, in file order and
/// normalised.
///
/// Both layouts Steam has written are read: the current one, where each
/// numbered entry is a block holding `"path"`, and the older one, where each
/// numbered entry is the path itself.
///
/// # Errors
/// If the text is not Valve's key-values format or has no `libraryfolders`
/// block.
pub fn steam_library_paths(vdf: &str) -> Result<Vec<String>, String> {
    let document = key_values(vdf)?;
    let folders = document
        .iter()
        .find_map(|(key, value)| match value {
            Value::Block(entries) if key.eq_ignore_ascii_case("libraryfolders") => Some(entries),
            _ => None,
        })
        .ok_or_else(|| "no `libraryfolders` block".to_owned())?;

    let mut paths: Vec<String> = Vec::new();
    for (key, value) in folders {
        let path = match value {
            Value::Block(entry) => entry.iter().find_map(|(name, value)| match value {
                Value::Text(text) if name.eq_ignore_ascii_case("path") => Some(text.as_str()),
                _ => None,
            }),
            // The older layout: `"1" "D:\\SteamLibrary"`, beside non-numeric
            // keys such as `ContentStatsID` that are not paths.
            Value::Text(text) if key.bytes().all(|byte| byte.is_ascii_digit()) => {
                Some(text.as_str())
            }
            Value::Text(_) => None,
        };
        if let Some(path) = path.and_then(normalised)
            && !paths.iter().any(|seen| seen.eq_ignore_ascii_case(&path))
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// A value in Valve's key-values text format.
#[derive(Debug, PartialEq, Eq)]
enum Value {
    Text(String),
    Block(Vec<(String, Value)>),
}

/// Parse key-values text into its top-level entries.
///
/// Just enough of the format for a library list: quoted and bare strings,
/// braces, `//` comments, and the escapes Steam writes inside quotes.
fn key_values(text: &str) -> Result<Vec<(String, Value)>, String> {
    let tokens = tokenise(text)?;
    let mut position = 0;
    let entries = entries(&tokens, &mut position)?;
    if position == tokens.len() {
        Ok(entries)
    } else {
        Err("unbalanced `}`".to_owned())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Text(String),
    Open,
    Close,
}

fn tokenise(text: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '{' => tokens.push(Token::Open),
            '}' => tokens.push(Token::Close),
            '"' => {
                let mut value = String::new();
                loop {
                    match characters.next() {
                        Some('"') => break,
                        Some('\\') => match characters.next() {
                            Some('n') => value.push('\n'),
                            Some('t') => value.push('\t'),
                            Some(escaped) => value.push(escaped),
                            None => return Err("unterminated string".to_owned()),
                        },
                        Some(other) => value.push(other),
                        None => return Err("unterminated string".to_owned()),
                    }
                }
                tokens.push(Token::Text(value));
            }
            '/' if characters.peek() == Some(&'/') => {
                for skipped in characters.by_ref() {
                    if skipped == '\n' {
                        break;
                    }
                }
            }
            whitespace if whitespace.is_whitespace() => {}
            first => {
                let mut value = String::from(first);
                while let Some(&next) = characters.peek() {
                    if next.is_whitespace() || matches!(next, '{' | '}' | '"') {
                        break;
                    }
                    value.push(next);
                    characters.next();
                }
                tokens.push(Token::Text(value));
            }
        }
    }
    Ok(tokens)
}

fn entries(tokens: &[Token], position: &mut usize) -> Result<Vec<(String, Value)>, String> {
    let mut parsed = Vec::new();
    while let Some(token) = tokens.get(*position) {
        let key = match token {
            Token::Close => break,
            Token::Open => return Err("a block with no key".to_owned()),
            Token::Text(key) => key.clone(),
        };
        *position += 1;
        let value = match tokens.get(*position) {
            Some(Token::Text(text)) => {
                *position += 1;
                Value::Text(text.clone())
            }
            Some(Token::Open) => {
                *position += 1;
                let inner = entries(tokens, position)?;
                if tokens.get(*position) != Some(&Token::Close) {
                    return Err(format!("`{key}` is never closed"));
                }
                *position += 1;
                Value::Block(inner)
            }
            Some(Token::Close) | None => return Err(format!("`{key}` has no value")),
        };
        parsed.push((key, value));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout Steam has written since 2021, abridged from a real file.
    const CURRENT: &str = r#""libraryfolders"
{
	"0"
	{
		"path"		"C:\\Program Files (x86)\\Steam"
		"label"		""
		"contentid"		"1234"
		"totalsize"		"0"
		"apps"
		{
			"228980"		"1048576"
		}
	}
	"1"
	{
		"path"		"D:\\SteamLibrary"
		"label"		""
		"apps"
		{
			"3405690"		"1"
		}
	}
}
"#;

    #[test]
    fn the_current_layout_names_every_library() {
        assert_eq!(
            steam_library_paths(CURRENT).unwrap(),
            [r"C:\Program Files (x86)\Steam", r"D:\SteamLibrary"]
        );
    }

    #[test]
    fn the_older_layout_names_libraries_by_number_only() {
        let older = r#""LibraryFolders"
{
	"TimeNextStatsReport"		"1600000000"
	"ContentStatsID"		"-123"
	"1"		"E:\\Games\\Steam"
}"#;
        assert_eq!(steam_library_paths(older).unwrap(), [r"E:\Games\Steam"]);
    }

    #[test]
    fn paths_are_normalised_and_listed_once() {
        let text = r#""libraryfolders" { "0" { "path" "d:/SteamLibrary/" } "1" { "path" "D:\\steamlibrary" } }"#;
        assert_eq!(steam_library_paths(text).unwrap(), [r"d:\SteamLibrary"]);
    }

    #[test]
    fn comments_and_bare_strings_are_read() {
        let text = "// written by hand\nlibraryfolders\n{\n  0 { path \"F:\\\\Steam\" }\n}\n";
        assert_eq!(steam_library_paths(text).unwrap(), [r"F:\Steam"]);
    }

    #[test]
    fn malformed_manifests_are_refused_rather_than_read_as_empty() {
        assert!(steam_library_paths("\"libraryfolders\" { \"0\" { \"path\" ").is_err());
        assert!(steam_library_paths("\"libraryfolders\" { } }").is_err());
        assert!(steam_library_paths("\"somethingelse\" { }").is_err());
    }

    #[test]
    fn an_epic_manifest_names_the_folder_above_its_game() {
        let item = r#"{ "FormatVersion": 0, "InstallLocation": "D:\\Epic Games\\ExampleShooter", "AppName": "x" }"#;
        let location = epic_install_location(item).unwrap().unwrap();
        assert_eq!(location, r"D:\Epic Games\ExampleShooter");
        assert_eq!(epic_library_of(&location), r"D:\Epic Games");
    }

    #[test]
    fn a_game_at_a_drive_root_is_its_own_library() {
        // Walking `D:\` to cover one game would walk the whole volume.
        assert_eq!(epic_library_of(r"D:\ExampleShooter"), r"D:\ExampleShooter");
    }

    #[test]
    fn an_epic_manifest_without_a_location_names_nothing() {
        assert_eq!(
            epic_install_location(r#"{ "InstallLocation": "" }"#),
            Ok(None)
        );
        assert_eq!(epic_install_location("{}"), Ok(None));
        assert!(epic_install_location("not json").is_err());
    }

    #[test]
    fn games_and_variables_follow_the_schema() {
        let steam = Library {
            launcher: Launcher::Steam,
            path: r"D:\SteamLibrary".to_owned(),
        };
        let epic = Library {
            launcher: Launcher::Epic,
            path: r"D:\Epic Games".to_owned(),
        };
        assert_eq!(steam.games(), r"D:\SteamLibrary\steamapps\common");
        assert_eq!(epic.games(), r"D:\Epic Games");
        assert_eq!(steam.variable(), "STEAM_LIBRARY");
        assert_eq!(epic.variable(), "EPIC_LIBRARY");
    }

    #[test]
    fn discovery_reads_both_launchers_and_reports_what_it_could_not() {
        let root = tempfile::tempdir().unwrap();
        let steam = root.path().join("Steam");
        std::fs::create_dir_all(steam.join("steamapps")).unwrap();
        std::fs::write(steam.join("steamapps").join("libraryfolders.vdf"), CURRENT).unwrap();

        let manifests = root.path().join("Manifests");
        std::fs::create_dir_all(&manifests).unwrap();
        std::fs::write(
            manifests.join("A.item"),
            r#"{ "InstallLocation": "E:\\Epic Games\\Alpha" }"#,
        )
        .unwrap();
        std::fs::write(
            manifests.join("B.item"),
            r#"{ "InstallLocation": "E:\\Epic Games\\Beta" }"#,
        )
        .unwrap();
        std::fs::write(manifests.join("broken.item"), "{").unwrap();
        std::fs::write(manifests.join("notes.txt"), "not a manifest").unwrap();

        let found = discover(Some(&steam), Some(&manifests));

        assert_eq!(
            found.libraries,
            [
                Library {
                    launcher: Launcher::Steam,
                    path: r"C:\Program Files (x86)\Steam".to_owned()
                },
                Library {
                    launcher: Launcher::Steam,
                    path: r"D:\SteamLibrary".to_owned()
                },
                Library {
                    launcher: Launcher::Epic,
                    path: r"E:\Epic Games".to_owned()
                },
            ]
        );
        assert_eq!(found.unreadable.len(), 1, "{:?}", found.unreadable);
        assert!(found.unreadable[0].path.ends_with("broken.item"));
    }

    #[test]
    fn only_libraries_every_list_names_are_common() {
        let steam = |path: &str| Library {
            launcher: Launcher::Steam,
            path: path.to_owned(),
        };
        let before = [steam(r"D:\SteamLibrary"), steam(r"E:\Games")];
        let after = [steam(r"d:\steamlibrary")];
        assert_eq!(
            common([&before[..], &after[..]].into_iter()),
            [steam(r"D:\SteamLibrary")]
        );
        assert_eq!(common([&before[..], &[][..]].into_iter()), []);
        assert_eq!(common(std::iter::empty()), []);
    }

    #[test]
    fn a_launcher_that_is_not_installed_contributes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let found = discover(
            Some(&root.path().join("no-steam-here")),
            Some(&root.path().join("no-epic-here")),
        );
        assert_eq!(found, Found::default());
    }
}
