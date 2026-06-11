//! Detached `OpenPGP` signature verification and SHA-256 hashing.
//!
//! Every download is checked against a SHA-256 hash ([`sha256`]); where the
//! upstream publishes a detached GPG signature it is additionally verified
//! against an embedded ASCII-armored public key ([`verify`]).

use std::io::Cursor;
use std::path::{Path, PathBuf};

use pgp::{Deserializable, SignedPublicKey, StandaloneSignature};

/// Errors from signature or hash verification.
#[derive(Debug, thiserror::Error)]
pub enum GpgError {
    /// The embedded public key could not be parsed.
    #[error("invalid public key: {0}")]
    PublicKey(String),
    /// The detached signature could not be parsed.
    #[error("invalid signature data: {0}")]
    SignatureData(String),
    /// The signature did not validate against the public key.
    #[error("signature verification failed: {0}")]
    Invalid(String),
    /// A file needed for verification could not be read.
    #[error("failed to read {path}")]
    Io {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The SHA-256 hash did not match the expected value.
    #[error("sha-256 mismatch: expected {expected}, computed {actual}")]
    HashMismatch {
        /// The expected hash, lowercase hex.
        expected: String,
        /// The hash actually computed, lowercase hex.
        actual: String,
    },
}

/// Verifies the detached signature `signature` over the file `package`,
/// using the ASCII-armored `armored_public_key`.
///
/// # Errors
/// Returns [`GpgError::Io`] if a file cannot be read, [`GpgError::PublicKey`]
/// or [`GpgError::SignatureData`] if an input cannot be parsed, and
/// [`GpgError::Invalid`] if the signature does not validate.
pub fn verify(package: &Path, signature: &Path, armored_public_key: &[u8]) -> Result<(), GpgError> {
    let package_bytes = read(package)?;
    let signature_bytes = read(signature)?;
    verify_bytes(&package_bytes, &signature_bytes, armored_public_key)
}

/// Verifies a detached `OpenPGP` signature held entirely in memory.
///
/// Accepts both ASCII-armored signatures (`.asc`) and binary PGP detached
/// signatures (`.sig`); armored format is tried first.
///
/// # Errors
/// Returns [`GpgError::PublicKey`] / [`GpgError::SignatureData`] when an
/// input cannot be parsed, and [`GpgError::Invalid`] when the signature does
/// not validate against the public key.
pub fn verify_bytes(
    package: &[u8],
    signature: &[u8],
    armored_public_key: &[u8],
) -> Result<(), GpgError> {
    let (public_key, _) = SignedPublicKey::from_armor_single(Cursor::new(armored_public_key))
        .map_err(|e| GpgError::PublicKey(e.to_string()))?;
    // Try ASCII-armored first; fall back to binary PGP (e.g. Pale Moon `.sig` files).
    let sig = StandaloneSignature::from_armor_single(Cursor::new(signature))
        .map(|(s, _)| s)
        .or_else(|_| StandaloneSignature::from_bytes(signature))
        .map_err(|e| GpgError::SignatureData(e.to_string()))?;
    // pgp v0.14 only checks the supplied key, not its subkeys automatically.
    // Try the primary key first, then every signing subkey.
    let primary_err = sig.verify(&public_key, package);
    if primary_err.is_ok() {
        return Ok(());
    }
    for subkey in &public_key.public_subkeys {
        if sig.verify(subkey, package).is_ok() {
            return Ok(());
        }
    }
    primary_err.map_err(|e| GpgError::Invalid(e.to_string()))
}

/// Reads a file, mapping I/O failures to [`GpgError::Io`].
fn read(path: &Path) -> Result<Vec<u8>, GpgError> {
    std::fs::read(path).map_err(|source| GpgError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// SHA-256 hashing and hash verification.
pub mod sha256 {
    use sha2::{Digest, Sha256};

    use super::GpgError;

    /// Returns the lowercase-hex SHA-256 digest of `data`.
    #[must_use]
    pub fn hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Verifies that the SHA-256 digest of `data` equals `expected`
    /// (compared case-insensitively, surrounding whitespace ignored).
    ///
    /// # Errors
    /// Returns [`GpgError::HashMismatch`] when the digests differ.
    pub fn verify(data: &[u8], expected: &str) -> Result<(), GpgError> {
        let actual = hex(data);
        // A plain (non-constant-time) compare is fine here: `expected` is a
        // public upstream digest, not a secret, so there is no timing oracle.
        if actual.eq_ignore_ascii_case(expected.trim()) {
            Ok(())
        } else {
            Err(GpgError::HashMismatch {
                expected: expected.trim().to_owned(),
                actual,
            })
        }
    }
}

/// SHA-512 hashing and hash verification.
pub mod sha512 {
    use sha2::{Digest, Sha512};

    use super::GpgError;

    /// Returns the lowercase-hex SHA-512 digest of `data`.
    #[must_use]
    pub fn hex(data: &[u8]) -> String {
        hex::encode(Sha512::digest(data))
    }

    /// Verifies that the SHA-512 digest of `data` equals `expected`
    /// (compared case-insensitively, surrounding whitespace ignored).
    ///
    /// The `expected` string may be a bare hex digest or the first
    /// whitespace-delimited token of a checksum-file line
    /// (e.g. `"<hash>  filename"`).
    ///
    /// # Errors
    /// Returns [`GpgError::HashMismatch`] when the digests differ.
    pub fn verify(data: &[u8], expected: &str) -> Result<(), GpgError> {
        let expected_hash = expected.split_whitespace().next().unwrap_or("").trim();
        let actual = hex(data);
        // Non-constant-time compare is fine — see `sha256::verify`.
        if actual.eq_ignore_ascii_case(expected_hash) {
            Ok(())
        } else {
            Err(GpgError::HashMismatch {
                expected: expected_hash.to_owned(),
                actual,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound;
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::{PublicKeyTrait, SecretKeyTrait};
    use pgp::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedSecretKey};
    use rand::rngs::OsRng;

    use super::{sha256, verify_bytes};

    /// Generates a fresh signing keypair (fast EdDSA-legacy curve).
    fn keypair(user: &str) -> SignedSecretKey {
        let mut builder = SecretKeyParamsBuilder::default();
        builder
            .key_type(KeyType::EdDSALegacy)
            .can_sign(true)
            .primary_user_id(user.to_owned());
        let params = builder.build().expect("valid key params");
        let secret = params.generate(OsRng).expect("key generation");
        secret.sign(OsRng, String::new).expect("self-sign key")
    }

    /// Returns the ASCII-armored public key for `key`.
    fn armored_public_key(key: &SignedSecretKey) -> Vec<u8> {
        key.public_key()
            .sign(OsRng, key, String::new)
            .expect("sign public key")
            .to_armored_bytes(ArmorOptions::default())
            .expect("armor public key")
    }

    /// Produces an ASCII-armored detached signature of `data` by `key`.
    fn detached_signature(key: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
        let mut config = SignatureConfig::v4(
            SignatureType::Binary,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::SHA2_256,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            )),
            Subpacket::regular(SubpacketData::Issuer(key.key_id())),
        ];
        let signature = config
            .sign(key, String::new, data)
            .expect("create detached signature");
        pgp::StandaloneSignature::new(signature)
            .to_armored_bytes(ArmorOptions::default())
            .expect("armor signature")
    }

    #[test]
    fn verifies_a_valid_detached_signature() {
        let key = keypair("Nomad Test <test@nomad.invalid>");
        let data = b"nomad portable package contents";
        let sig = detached_signature(&key, data);
        let pubkey = armored_public_key(&key);

        verify_bytes(data, &sig, &pubkey).expect("valid signature must verify");
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = keypair("Nomad Test <test@nomad.invalid>");
        let sig = detached_signature(&key, b"original package contents");
        let pubkey = armored_public_key(&key);

        let err = verify_bytes(b"tampered package contents", &sig, &pubkey)
            .expect_err("a modified payload must not verify");
        assert!(matches!(err, super::GpgError::Invalid(_)));
    }

    #[test]
    fn rejects_a_signature_from_the_wrong_key() {
        let signer = keypair("Signer <signer@nomad.invalid>");
        let attacker = keypair("Attacker <attacker@nomad.invalid>");
        let data = b"nomad portable package contents";
        let sig = detached_signature(&signer, data);
        let wrong_pubkey = armored_public_key(&attacker);

        let err = verify_bytes(data, &sig, &wrong_pubkey)
            .expect_err("a signature from another key must not verify");
        assert!(matches!(err, super::GpgError::Invalid(_)));
    }

    #[test]
    fn rejects_unparseable_signature_data() {
        let key = keypair("Nomad Test <test@nomad.invalid>");
        let pubkey = armored_public_key(&key);

        let err = verify_bytes(b"data", b"not a signature", &pubkey)
            .expect_err("garbage signature data must be rejected");
        assert!(matches!(err, super::GpgError::SignatureData(_)));
    }

    #[test]
    fn sha256_accepts_a_matching_hash() {
        // Known SHA-256 of the empty input.
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(sha256::hex(b""), empty);
        sha256::verify(b"", empty).expect("matching hash must verify");
    }

    #[test]
    fn sha256_is_case_insensitive() {
        let upper = sha256::hex(b"nomad").to_uppercase();
        sha256::verify(b"nomad", &upper).expect("upper-case hex must verify");
    }

    #[test]
    fn sha256_rejects_a_mismatched_hash() {
        let err =
            sha256::verify(b"nomad", &"0".repeat(64)).expect_err("a wrong hash must be rejected");
        assert!(matches!(err, super::GpgError::HashMismatch { .. }));
    }
}
