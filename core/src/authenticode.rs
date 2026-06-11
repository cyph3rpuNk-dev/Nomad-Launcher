//! Authenticode signature verification for downloaded executables.
//!
//! Pins a downloaded artifact to a known publisher before it is staged or
//! launched. Two independent checks:
//!
//! 1. `WinVerifyTrust` confirms the file carries a valid, OS-trusted
//!    Authenticode signature chain (not expired, chains to a trusted root,
//!    not revoked — with whole-chain revocation checking when the CRL/OCSP
//!    endpoints are reachable; when revocation status cannot be determined,
//!    e.g. offline, the rest of the chain is still enforced).
//! 2. The signer certificate's simple display subject (the publisher CN,
//!    e.g. `"Bitwarden Inc."`) must equal the expected publisher, so a
//!    binary that is validly signed by some *other* publisher — including
//!    one whose name merely embeds the expected string — is rejected.
//!
//! This is defense-in-depth on top of the SHA-256 digest pin done in
//! [`crate::updater::verify_package`]: the hash ties the bytes to what GitHub
//! published; Authenticode ties them to the publisher's signing key.
//!
//! On non-Windows builds [`verify_signed_by`] is a no-op returning `Ok(())` —
//! the launchers are Windows-only in practice, and `windows-sys` is a
//! Windows-target dependency.

use std::path::Path;

/// Errors produced by Authenticode verification.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticodeError {
    /// `WinVerifyTrust` rejected the file (no signature, untrusted chain,
    /// expired, revoked, …). The wrapped value is the raw status code.
    #[error("signature is missing or not trusted (status 0x{0:08X})")]
    NotTrusted(u32),
    /// The signature is trusted but the signer certificate could not be read.
    #[error("could not read signer certificate: {0}")]
    Signer(String),
    /// The signer is trusted but is not the expected publisher.
    #[error("signer subject {found:?} does not match expected {expected:?}")]
    SubjectMismatch {
        /// The subject string read from the signing certificate.
        found: String,
        /// The publisher name that was required.
        expected: String,
    },
}

/// Case-insensitive, whitespace-trimmed equality between the signer's simple
/// display subject (the certificate CN) and the expected publisher name.
///
/// Equality rather than substring: a substring pin would also accept any
/// validly-signed binary whose subject merely *embeds* the expected string
/// (e.g. `"Not Bitwarden Inc."`). Factored out so the publisher-matching
/// rule is testable without a real signed file.
#[must_use]
fn subject_matches(found: &str, expected: &str) -> bool {
    found.trim().eq_ignore_ascii_case(expected.trim())
}

/// Verifies `file` is Authenticode-signed, OS-trusted, and signed by a
/// certificate whose subject equals `expected_subject` (case-insensitive).
///
/// # Errors
/// Returns [`AuthenticodeError`] when the signature is missing/untrusted, the
/// signer certificate cannot be read, or the signer is not the expected
/// publisher.
pub fn verify_signed_by(file: &Path, expected_subject: &str) -> Result<(), AuthenticodeError> {
    #[cfg(windows)]
    {
        imp::win_verify_trust(file)?;
        let subject = imp::signer_subject(file)?;
        if subject_matches(&subject, expected_subject) {
            tracing::debug!(%subject, "Authenticode signer verified");
            Ok(())
        } else {
            Err(AuthenticodeError::SubjectMismatch {
                found: subject,
                expected: expected_subject.to_owned(),
            })
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (file, expected_subject);
        tracing::warn!("Authenticode verification skipped on non-Windows build");
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
        CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
        CMSG_SIGNER_INFO_PARAM, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    use super::AuthenticodeError;

    /// Combined cert encoding type passed to the crypto APIs.
    const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /// `CERT_E_REVOCATION_FAILURE` — revocation could not be checked
    /// (winerror.h; stable ABI value, kept local to avoid widening the
    /// windows-sys feature surface).
    const CERT_E_REVOCATION_FAILURE: u32 = 0x800B_010E;
    /// `CRYPT_E_REVOCATION_OFFLINE` — the revocation server was unreachable.
    const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;

    /// Encodes a path as a NUL-terminated UTF-16 string for the wide Win32 APIs.
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Runs `WinVerifyTrust` with the generic-verify policy and no UI.
    ///
    /// First pass enforces whole-chain revocation (CRL/OCSP); the callers run
    /// right after a download, so the network is normally reachable. When the
    /// revocation *status* cannot be determined (offline, CRL endpoint down),
    /// the check is repeated without revocation so an offline launch is not
    /// bricked — a *definitive* revocation (`CERT_E_REVOKED`) is a plain
    /// untrusted result from the first pass and is never retried.
    ///
    /// Returns `Ok(())` only when the file carries a valid, trusted
    /// Authenticode signature (status `0`); otherwise
    /// [`AuthenticodeError::NotTrusted`] with the raw status code (e.g.
    /// `TRUST_E_NOSIGNATURE`, `CERT_E_UNTRUSTEDROOT`, `CERT_E_REVOKED`).
    pub(super) fn win_verify_trust(file: &Path) -> Result<(), AuthenticodeError> {
        #[allow(clippy::cast_sign_loss)] // raw HRESULT/status bit pattern
        let code = win_verify_trust_with(file, WTD_REVOKE_WHOLECHAIN) as u32;
        match code {
            0 => return Ok(()),
            CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE => {
                tracing::warn!(
                    status = format_args!("0x{code:08X}"),
                    "Authenticode revocation status could not be determined \
                     (offline?); re-verifying without revocation checking"
                );
            }
            _ => return Err(AuthenticodeError::NotTrusted(code)),
        }

        let status = win_verify_trust_with(file, WTD_REVOKE_NONE);
        if status == 0 {
            Ok(())
        } else {
            #[allow(clippy::cast_sign_loss)] // raw HRESULT/status bit pattern
            Err(AuthenticodeError::NotTrusted(status as u32))
        }
    }

    /// One `WinVerifyTrust` invocation with the given `fdwRevocationChecks`
    /// mode, returning the raw status code.
    // `data.dwStateAction = WTD_STATEACTION_CLOSE` is read by WinVerifyTrust
    // through `data_ptr`, which the borrow checker cannot see — hence the
    // otherwise-dead-store allow.
    #[allow(unused_assignments)]
    fn win_verify_trust_with(file: &Path, revocation_checks: u32) -> i32 {
        let path = wide(file);

        // SAFETY: `file_info` and `data` are zero-initialised then populated per
        // the WinVerifyTrust contract; `path` outlives both calls. The VERIFY
        // call is always paired with a CLOSE call to release the state handle.
        unsafe {
            let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
            file_info.cbStruct =
                u32::try_from(std::mem::size_of::<WINTRUST_FILE_INFO>()).unwrap_or(u32::MAX);
            file_info.pcwszFilePath = path.as_ptr();

            let mut data: WINTRUST_DATA = std::mem::zeroed();
            data.cbStruct = u32::try_from(std::mem::size_of::<WINTRUST_DATA>()).unwrap_or(u32::MAX);
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = revocation_checks;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.Anonymous.pFile = &mut file_info;
            data.dwStateAction = WTD_STATEACTION_VERIFY;

            let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let data_ptr: *mut core::ffi::c_void = ptr::addr_of_mut!(data).cast();

            let status = WinVerifyTrust(ptr::null_mut(), &mut action, data_ptr);

            // Release the state data regardless of the verify result.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(ptr::null_mut(), &mut action, data_ptr);

            status
        }
    }

    /// Extracts the signing certificate's simple display subject (typically the
    /// publisher CN, e.g. `"Bitwarden Inc."`) from an embedded Authenticode
    /// signature.
    ///
    /// # Errors
    /// [`AuthenticodeError::Signer`] when the file has no embedded signature
    /// message or the certificate cannot be located/read.
    #[allow(clippy::too_many_lines)]
    pub(super) fn signer_subject(file: &Path) -> Result<String, AuthenticodeError> {
        let path = wide(file);

        let mut h_store: *mut core::ffi::c_void = ptr::null_mut();
        let mut h_msg: *mut core::ffi::c_void = ptr::null_mut();

        // SAFETY: CryptQueryObject populates h_store/h_msg from the file path;
        // all handles obtained here are freed before returning on every path.
        let queried = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.as_ptr().cast(),
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut h_store,
                &mut h_msg,
                ptr::null_mut(),
            )
        };
        if queried == 0 || h_msg.is_null() || h_store.is_null() {
            close_handles(h_store, h_msg);
            return Err(AuthenticodeError::Signer(
                "file has no embedded Authenticode signature".to_owned(),
            ));
        }

        let result = (|| {
            // ── Fetch the signer info (issuer + serial) ──────────────────────
            let mut cb: u32 = 0;
            // SAFETY: first call with a null buffer queries the required size.
            let sized = unsafe {
                CryptMsgGetParam(h_msg, CMSG_SIGNER_INFO_PARAM, 0, ptr::null_mut(), &mut cb)
            };
            if sized == 0 || cb == 0 {
                return Err(AuthenticodeError::Signer(
                    "could not size signer info".to_owned(),
                ));
            }
            let mut buf = vec![0u8; cb as usize];
            // SAFETY: buf is exactly `cb` bytes as required by the sizing call.
            let got = unsafe {
                CryptMsgGetParam(
                    h_msg,
                    CMSG_SIGNER_INFO_PARAM,
                    0,
                    buf.as_mut_ptr().cast(),
                    &mut cb,
                )
            };
            if got == 0 {
                return Err(AuthenticodeError::Signer(
                    "could not read signer info".to_owned(),
                ));
            }

            // SAFETY: buf holds at least a CMSG_SIGNER_INFO header; read_unaligned
            // makes no alignment assumption about the Vec<u8> backing store. The
            // blob pointers in the returned struct reference into buf, which
            // outlives every use of `cert_info` below.
            #[allow(clippy::cast_ptr_alignment)] // soundness provided by read_unaligned
            let signer = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<CMSG_SIGNER_INFO>()) };

            // ── Find the signing certificate by issuer + serial ──────────────
            let mut cert_info: CERT_INFO = unsafe { std::mem::zeroed() };
            cert_info.Issuer = signer.Issuer;
            cert_info.SerialNumber = signer.SerialNumber;

            // SAFETY: cert_info references blob data owned by buf (still alive).
            let cert_ctx: *const CERT_CONTEXT = unsafe {
                CertFindCertificateInStore(
                    h_store,
                    ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    ptr::addr_of!(cert_info).cast(),
                    ptr::null(),
                )
            };
            if cert_ctx.is_null() {
                return Err(AuthenticodeError::Signer(
                    "signing certificate not found in store".to_owned(),
                ));
            }

            // ── Read the subject display name ────────────────────────────────
            // SAFETY: cert_ctx is a valid context from the call above; the first
            // CertGetNameStringW returns the buffer length (incl. NUL).
            let len = unsafe {
                CertGetNameStringW(
                    cert_ctx,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                )
            };
            let subject = if len <= 1 {
                String::new()
            } else {
                let mut name = vec![0u16; len as usize];
                // SAFETY: name is `len` wide chars as the sizing call reported.
                unsafe {
                    CertGetNameStringW(
                        cert_ctx,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        ptr::null(),
                        name.as_mut_ptr(),
                        len,
                    );
                }
                // Drop the trailing NUL before decoding.
                String::from_utf16_lossy(&name[..(len as usize - 1)])
            };

            // SAFETY: cert_ctx came from CertFindCertificateInStore; freeing it
            // is the documented counterpart.
            unsafe {
                CertFreeCertificateContext(cert_ctx);
            }

            if subject.is_empty() {
                Err(AuthenticodeError::Signer(
                    "signing certificate has no subject name".to_owned(),
                ))
            } else {
                Ok(subject)
            }
        })();

        close_handles(h_store, h_msg);
        result
    }

    /// Closes the message and certificate-store handles if non-null.
    fn close_handles(h_store: *mut core::ffi::c_void, h_msg: *mut core::ffi::c_void) {
        // SAFETY: each handle is either null (ignored) or a valid handle from
        // CryptQueryObject; closing is the documented counterpart.
        unsafe {
            if !h_msg.is_null() {
                CryptMsgClose(h_msg);
            }
            if !h_store.is_null() {
                CertCloseStore(h_store, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_match_is_case_insensitive_equality() {
        assert!(subject_matches("Bitwarden Inc.", "Bitwarden Inc."));
        assert!(subject_matches("bitwarden inc.", "BITWARDEN INC."));
        assert!(subject_matches(" Bitwarden Inc. ", "Bitwarden Inc."));
        // Regression: the pin used to be a substring match, which would have
        // accepted any validly-signed publisher whose CN embeds the string.
        assert!(!subject_matches("Not Bitwarden Inc.", "Bitwarden Inc."));
        assert!(!subject_matches(
            "Bitwarden Inc. Holdings",
            "Bitwarden Inc."
        ));
        assert!(!subject_matches(
            "CN=Bitwarden Inc., O=Bitwarden Inc.",
            "Bitwarden Inc."
        ));
        assert!(!subject_matches("Mozilla Corporation", "Bitwarden Inc."));
        assert!(!subject_matches("", "Bitwarden Inc."));
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_file_is_rejected() {
        // A plain unsigned file must fail WinVerifyTrust (no signature).
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("unsigned.exe");
        std::fs::write(&f, b"MZ not a real signed binary").unwrap();
        let err =
            verify_signed_by(&f, "Bitwarden Inc.").expect_err("an unsigned file must be rejected");
        assert!(
            matches!(err, AuthenticodeError::NotTrusted(_)),
            "expected NotTrusted, got {err:?}"
        );
    }
}
