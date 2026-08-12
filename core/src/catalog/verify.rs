//! Ed25519 verification of a detached catalog signature.
//!
//! `docs/04-CATALOG-SCHEMA.md`: the signature covers the **raw bytes** of
//! `catalog.toml`, verification is unconditional, and a catalog that fails is
//! refused outright rather than used with a warning.
//!
//! One subtlety worth stating because it is invisible until CI breaks: signing
//! raw bytes means the file must round-trip through git byte for byte. The
//! repository's `.gitattributes` marks the catalog and its signature `-text`
//! for exactly this reason — otherwise a signature produced on Windows fails on
//! the ubuntu runner and looks like a cryptography bug.

use ed25519_dalek::{Signature, VerifyingKey};

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The public key this build trusts, as committed at `catalog/pubkey.hex`.
///
/// `docs/04` says the key is compiled into the broker; `catalog-verify.yml`
/// passes `--pubkey catalog/pubkey.hex` to the CI tool. Reading the same
/// committed file at compile time makes those the same key by construction
/// rather than by discipline.
pub const COMPILED_IN_PUBLIC_KEY_HEX: &str = include_str!("../../../catalog/pubkey.hex");

/// Why a catalog signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The public key was not 32 bytes of hex.
    #[error("public key is not {PUBLIC_KEY_LEN} bytes of hex")]
    MalformedPublicKey,
    /// The public key bytes are not a valid Ed25519 point.
    #[error("public key is not a valid Ed25519 key")]
    InvalidPublicKey,
    /// The signature was neither 64 raw bytes nor 64 bytes of hex.
    #[error("signature is not {SIGNATURE_LEN} bytes")]
    MalformedSignature,
    /// The signature did not match the catalog bytes under this key.
    #[error("catalog signature does not match")]
    SignatureMismatch,
}

/// Parse a hex-encoded Ed25519 public key.
///
/// Surrounding whitespace, including the trailing newline every text editor
/// adds, is ignored.
///
/// # Errors
///
/// Returns [`VerifyError::MalformedPublicKey`] or [`VerifyError::InvalidPublicKey`].
pub fn parse_public_key(hex_text: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes = hex::decode(hex_text.trim()).map_err(|_| VerifyError::MalformedPublicKey)?;
    let array: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| VerifyError::MalformedPublicKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| VerifyError::InvalidPublicKey)
}

/// Parse a detached signature.
///
/// Accepts the raw 64-byte form, which is what "detached signature" normally
/// means, and also a hex rendering of it. Being liberal here costs nothing:
/// a wrong signature fails verification either way.
///
/// # Errors
///
/// Returns [`VerifyError::MalformedSignature`].
pub fn parse_signature(raw: &[u8]) -> Result<Signature, VerifyError> {
    if let Ok(array) = <[u8; SIGNATURE_LEN]>::try_from(raw) {
        return Ok(Signature::from_bytes(&array));
    }
    let text = std::str::from_utf8(raw).map_err(|_| VerifyError::MalformedSignature)?;
    let bytes = hex::decode(text.trim()).map_err(|_| VerifyError::MalformedSignature)?;
    let array: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| VerifyError::MalformedSignature)?;
    Ok(Signature::from_bytes(&array))
}

/// Verify a detached signature over the raw catalog bytes.
///
/// # Errors
///
/// Returns [`VerifyError`] describing which part failed. A caller must treat
/// any error as "refuse this catalog"; there is no degraded mode.
pub fn verify_detached(
    catalog_bytes: &[u8],
    signature: &[u8],
    public_key_hex: &str,
) -> Result<(), VerifyError> {
    let key = parse_public_key(public_key_hex)?;
    let signature = parse_signature(signature)?;
    key.verify_strict(catalog_bytes, &signature)
        .map_err(|_| VerifyError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed key pair, so the test is deterministic and needs no RNG.
    ///
    /// Secret scalar is 32 bytes of 0x01. This is a test vector, not a key that
    /// signs anything real — the shipping key lives at `catalog/pubkey.hex`.
    fn fixture() -> (ed25519_dalek::SigningKey, String) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let public_hex = hex::encode(signing.verifying_key().to_bytes());
        (signing, public_hex)
    }

    #[test]
    fn a_good_signature_verifies_in_both_encodings() {
        use ed25519_dalek::Signer;
        let (signing, public_hex) = fixture();
        let body = b"schema_version = 1\n";
        let signature = signing.sign(body);

        assert_eq!(
            verify_detached(body, &signature.to_bytes(), &public_hex),
            Ok(())
        );
        let as_hex = hex::encode(signature.to_bytes());
        assert_eq!(
            verify_detached(body, as_hex.as_bytes(), &public_hex),
            Ok(())
        );
        // Trailing newline in the key file must not matter.
        assert_eq!(
            verify_detached(body, &signature.to_bytes(), &format!("{public_hex}\n")),
            Ok(())
        );
    }

    #[test]
    fn a_single_changed_byte_fails() {
        use ed25519_dalek::Signer;
        let (signing, public_hex) = fixture();
        let signature = signing.sign(b"schema_version = 1\n");
        assert_eq!(
            verify_detached(b"schema_version = 2\n", &signature.to_bytes(), &public_hex),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn a_line_ending_change_fails_which_is_why_gitattributes_exists() {
        use ed25519_dalek::Signer;
        let (signing, public_hex) = fixture();
        let unix = b"schema_version = 1\n";
        let signature = signing.sign(unix);
        let windows = b"schema_version = 1\r\n";
        assert_eq!(
            verify_detached(windows, &signature.to_bytes(), &public_hex),
            Err(VerifyError::SignatureMismatch),
            "if this ever passes, the signature is not covering raw bytes"
        );
    }

    #[test]
    fn malformed_inputs_are_reported_distinctly() {
        assert_eq!(
            parse_public_key("nothex").unwrap_err(),
            VerifyError::MalformedPublicKey
        );
        assert_eq!(
            parse_public_key("00ff").unwrap_err(),
            VerifyError::MalformedPublicKey
        );
        assert_eq!(
            parse_signature(b"short").unwrap_err(),
            VerifyError::MalformedSignature
        );
    }

    #[test]
    fn the_compiled_in_key_is_well_formed() {
        // Catches a truncated or placeholder catalog/pubkey.hex at test time
        // rather than at first run on a user's machine.
        parse_public_key(COMPILED_IN_PUBLIC_KEY_HEX)
            .expect("catalog/pubkey.hex must hold a valid Ed25519 public key");
    }
}
