//! Authenticode signer lookup.
//!
//! `docs/16-OBSERVATION-HARNESS.md`: "**Signer clustering is the single most
//! useful signal.** Everything the anti-cheat installer dropped shares a
//! publisher, and it separates instantly from Windows Update noise."
//!
//! This reads the **embedded** signature only, and returns the signing
//! certificate's subject common name. It does not verify the signature chain:
//! the harness describes what is on disk, it does not decide whether to trust
//! it. That distinction matters — `docs/04-CATALOG-SCHEMA.md` treats
//! `authenticode_cn` as an identity signal and says a file at a matching path
//! with the *wrong* publisher is reported as suspicious rather than removed, so
//! the name here is evidence for a person to review, never a verdict.
//!
//! # What "no signer" means
//!
//! Absent is not "unsigned". Most Windows binaries carry no embedded signature
//! at all and are signed through a catalog (`.cat`) file instead, which this
//! does not follow. Anti-cheat binaries are embedded-signed in practice, which
//! is what makes the signal worth collecting despite the gap.

#[cfg(not(windows))]
/// Never finds a signer off Windows.
#[must_use]
pub fn signer_of(_path: &std::path::Path) -> Option<String> {
    None
}

#[cfg(windows)]
pub use self::win32::signer_of;

#[cfg(windows)]
mod win32 {
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
        CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
        CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
        CryptQueryObject, HCERTSTORE,
    };

    /// The subject common name of the certificate that signed this file.
    ///
    /// Returns `None` for anything without an embedded signature, and for any
    /// step of the extraction that does not work. The harness records what it
    /// found; a missing signer is a fact about the file, not an error.
    #[must_use]
    pub fn signer_of(path: &Path) -> Option<String> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut store = HCERTSTORE::default();
        let mut message: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut encoding = CERT_QUERY_ENCODING_TYPE::default();

        // SAFETY: `wide` is a NUL-terminated path that outlives the call. The
        // store and message handles become ours, and both are released on every
        // path out of this function.
        let queried = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide.as_ptr().cast(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&raw mut encoding),
                None,
                None,
                Some(&raw mut store),
                Some(&raw mut message),
                None,
            )
        };
        if queried.is_err() {
            // No embedded signature. By far the most common outcome on a
            // Windows machine, and not worth reporting as a failure.
            return None;
        }

        let name = extract(store, message, encoding);

        // SAFETY: releasing exactly what CryptQueryObject produced, once each.
        unsafe {
            if !message.is_null() {
                let _ = CryptMsgClose(Some(message));
            }
            if !store.is_invalid() {
                let _ = CertCloseStore(Some(store), 0);
            }
        }

        name
    }

    fn extract(
        store: HCERTSTORE,
        message: *mut core::ffi::c_void,
        encoding: CERT_QUERY_ENCODING_TYPE,
    ) -> Option<String> {
        // Two-call idiom: ask for the size of the signer info, then read it.
        let mut needed = 0u32;
        // SAFETY: a null buffer asks for the required size.
        let sized =
            unsafe { CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &raw mut needed) };
        if sized.is_err() || needed == 0 {
            return None;
        }

        // u64-backed so the allocation is aligned for CMSG_SIGNER_INFO, which
        // holds pointers. `vec![0u8; n]` has an alignment of 1.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(size_of::<u64>()).max(1)];
        // SAFETY: the buffer is at least `needed` bytes.
        let read = unsafe {
            CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(buffer.as_mut_ptr().cast()),
                &raw mut needed,
            )
        };
        if read.is_err() {
            return None;
        }

        // SAFETY: the call above wrote a CMSG_SIGNER_INFO at the head of the
        // buffer, with its issuer and serial number pointing into the same
        // allocation — which is why `buffer` must outlive the search below.
        let signer = unsafe { &*buffer.as_ptr().cast::<CMSG_SIGNER_INFO>() };

        // A signer is identified by issuer plus serial number, which is what
        // CERT_INFO carries and what the store is searched by.
        let criteria = CERT_INFO {
            Issuer: signer.Issuer,
            SerialNumber: signer.SerialNumber,
            ..Default::default()
        };

        // SAFETY: `criteria` and `buffer` both outlive the call.
        let context: *mut CERT_CONTEXT = unsafe {
            CertFindCertificateInStore(
                store,
                encoding,
                0,
                CERT_FIND_SUBJECT_CERT,
                Some((&raw const criteria).cast()),
                None,
            )
        };
        if context.is_null() {
            return None;
        }

        let name = subject_name(context);

        // SAFETY: freeing exactly the context just obtained, once.
        unsafe {
            let _ = CertFreeCertificateContext(Some(context.cast_const()));
        }

        name.filter(|value| !value.is_empty())
    }

    /// The certificate's simple display name, which for a code-signing
    /// certificate is the publisher.
    fn subject_name(context: *mut CERT_CONTEXT) -> Option<String> {
        // SAFETY: a null buffer asks for the required length in characters,
        // including the terminator.
        let length = unsafe {
            CertGetNameStringW(
                context.cast_const(),
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                None,
            )
        };
        if length <= 1 {
            return None;
        }

        let mut text = vec![0u16; length as usize];
        // SAFETY: `text` is exactly the length the sizing call reported.
        unsafe {
            CertGetNameStringW(
                context.cast_const(),
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(text.as_mut_slice()),
            );
        }

        let end = text
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(text.len());
        Some(String::from_utf16_lossy(&text[..end]))
    }
}
