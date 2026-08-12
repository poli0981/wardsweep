//! Catalog parsing, verification and integrity checking.
//!
//! The catalog is the single source of truth for what an anti-cheat looks like
//! on disk (`docs/04-CATALOG-SCHEMA.md`). It ships as signed TOML, versioned
//! independently of the binary, under CC BY-SA 4.0 so the data can be reused
//! outside this project.
//!
//! This module is deliberately free of any Windows API: `catalog-verify.yml`
//! builds and runs it on ubuntu, and `docs/12-TESTING-STRATEGY.md` wants
//! pure-logic crates tested on Linux CI.

pub mod expand;
pub mod schema;
pub mod validate;
pub mod verify;

pub use schema::Catalog;

/// Why a catalog could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The TOML was malformed, or contained a field the schema does not define.
    ///
    /// Unknown fields are an error on purpose: silently ignoring a misspelled
    /// `divers = [...]` means a driver is never found and the user is told
    /// their machine is clean.
    #[error("catalog is not valid: {0}")]
    Toml(String),
    /// The catalog bytes were not UTF-8.
    #[error("catalog is not valid UTF-8")]
    NotUtf8,
}

/// Parse catalog text.
///
/// # Errors
///
/// Returns [`ParseError::Toml`] for malformed or unrecognised input.
pub fn parse(text: &str) -> Result<Catalog, ParseError> {
    toml::from_str(text).map_err(|error| ParseError::Toml(error.to_string()))
}

/// Parse catalog bytes, as read from disk.
///
/// Takes bytes rather than a `String` because the signature covers the raw
/// bytes and the caller should be holding those anyway.
///
/// # Errors
///
/// Returns [`ParseError`] if the bytes are not UTF-8 or not a valid catalog.
pub fn parse_bytes(bytes: &[u8]) -> Result<Catalog, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::NotUtf8)?;
    parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_field_is_an_error_not_a_shrug() {
        let body = "schema_version = 1\n\
                    catalog_version = \"1\"\n\
                    minimum_app_version = \"0.1.0\"\n\
                    [[anticheat]]\n\
                    id = \"typo\"\ndisplay = \"Typo\"\nkind = \"kernel\"\n\
                    shared = true\nrisk = \"high\"\n\
                    divers = [\"typo.sys\"]\n";
        assert!(matches!(parse(body), Err(ParseError::Toml(_))));
    }

    #[test]
    fn the_example_catalog_in_the_repository_parses() {
        // catalog.example.toml is the template contributors copy. If it stops
        // parsing, every contribution starts from something broken.
        let body = include_str!("../../../catalog/catalog.example.toml");
        let catalog = parse(body).expect("catalog.example.toml must parse");
        assert_eq!(catalog.schema_version, schema::SUPPORTED_SCHEMA_VERSION);
        assert!(!catalog.anticheat.is_empty());
    }
}
