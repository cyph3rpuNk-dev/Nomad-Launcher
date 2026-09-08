//! Portable-folder ownership.
//!
//! Historically every launcher placed `Browser/`, `Data/`, and `Nomad/`
//! beside itself without recording which browser family owned those paths.
//! Two different launcher executables in one folder could therefore replace
//! each other's browser bundle and reuse an incompatible profile. The marker
//! in this module turns that silent collision into a fail-closed error.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::browsers::{BrowserError, Result};

const FILE_NAME: &str = "instance.toml";
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstanceIdentity {
    schema_version: u32,
    browser_id: String,
}

/// Ensures that `base` belongs to `browser_id`.
///
/// A missing marker is claimed atomically only when `claim_if_missing` is
/// true. An existing marker must parse, use the supported schema, and name the
/// same browser. No browser or profile files are touched when validation
/// fails.
pub(crate) fn ensure(base: &Path, browser_id: &str, claim_if_missing: bool) -> Result<()> {
    if !valid_browser_id(browser_id) {
        return Err(BrowserError::Ownership(format!(
            "invalid browser identity `{browser_id}`"
        )));
    }

    let nomad_dir = crate::config::nomad_subdir(base);
    let marker = nomad_dir.join(FILE_NAME);
    if marker.exists() {
        return validate_existing(&marker, browser_id);
    }
    if !claim_if_missing {
        return Err(BrowserError::Ownership(
            "this portable folder is unclaimed; run the launcher directly once before using an OS protocol handler"
                .to_owned(),
        ));
    }

    std::fs::create_dir_all(&nomad_dir)?;
    let identity = InstanceIdentity {
        schema_version: SCHEMA_VERSION,
        browser_id: browser_id.to_owned(),
    };
    let serialized = toml::to_string(&identity)
        .map_err(|e| BrowserError::Ownership(format!("could not serialize identity: {e}")))?;

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(mut file) => {
            if let Err(error) = file
                .write_all(serialized.as_bytes())
                .and_then(|()| file.sync_all())
            {
                let _ = std::fs::remove_file(&marker);
                return Err(BrowserError::Io(error));
            }
            tracing::info!(
                browser = browser_id,
                ?marker,
                "portable folder ownership recorded"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another launcher may have claimed the folder between the
            // existence check and create_new. Validate the winner.
            validate_existing(&marker, browser_id)
        }
        Err(error) => Err(BrowserError::Io(error)),
    }
}

fn validate_existing(marker: &Path, browser_id: &str) -> Result<()> {
    let raw = std::fs::read_to_string(marker).map_err(|error| {
        BrowserError::Ownership(format!(
            "could not read portable-folder marker `{}`: {error}",
            marker.display()
        ))
    })?;
    let identity: InstanceIdentity = toml::from_str(&raw).map_err(|error| {
        BrowserError::Ownership(format!(
            "portable-folder marker `{}` is invalid: {error}; refusing to guess ownership",
            marker.display()
        ))
    })?;
    if identity.schema_version != SCHEMA_VERSION {
        return Err(BrowserError::Ownership(format!(
            "portable-folder marker uses unsupported schema {}; expected {}",
            identity.schema_version, SCHEMA_VERSION
        )));
    }
    if identity.browser_id != browser_id {
        return Err(BrowserError::Ownership(format!(
            "this portable folder belongs to `{}`, but the running launcher is `{browser_id}`; move each Nomad launcher to its own folder",
            identity.browser_id
        )));
    }
    Ok(())
}

fn valid_browser_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::ensure;

    #[test]
    fn first_launcher_claims_folder_and_same_launcher_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        ensure(dir.path(), "ungoogled-chromium", true).expect("first claim");
        ensure(dir.path(), "ungoogled-chromium", true).expect("same owner");

        let marker = std::fs::read_to_string(dir.path().join("Nomad/instance.toml"))
            .expect("marker readable");
        assert!(marker.contains("browser_id = \"ungoogled-chromium\""));
    }

    #[test]
    fn different_launcher_is_rejected_without_rewriting_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        ensure(dir.path(), "ungoogled-chromium", true).expect("first claim");
        let marker = dir.path().join("Nomad/instance.toml");
        let before = std::fs::read(&marker).expect("marker readable");

        let error = ensure(dir.path(), "helium", true).expect_err("mismatch must fail");
        assert!(error
            .to_string()
            .contains("belongs to `ungoogled-chromium`"));
        assert_eq!(std::fs::read(marker).expect("marker readable"), before);
    }

    #[test]
    fn corrupt_marker_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nomad = dir.path().join("Nomad");
        std::fs::create_dir(&nomad).expect("nomad dir");
        std::fs::write(nomad.join("instance.toml"), "not = [toml").expect("write corrupt marker");

        let error = ensure(dir.path(), "floorp", true).expect_err("corrupt marker must fail");
        assert!(error.to_string().contains("refusing to guess ownership"));
    }

    #[test]
    fn invalid_browser_id_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(ensure(dir.path(), "../../helium", true).is_err());
        assert!(!dir.path().join("Nomad").exists());
    }

    #[test]
    fn protocol_launch_cannot_claim_an_unowned_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = ensure(dir.path(), "helium", false).expect_err("claim must be refused");
        assert!(error.to_string().contains("unclaimed"));
        assert!(!dir.path().join("Nomad").exists());
    }
}
