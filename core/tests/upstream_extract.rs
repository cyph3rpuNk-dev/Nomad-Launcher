//! Live end-to-end update compatibility checks.
//!
//! Metadata-only checks catch renamed checksum files but not a changed archive
//! layout or executable path. This ignored test downloads, verifies, and
//! extracts the current Floorp release into a temporary directory without
//! launching it or touching user configuration.

use nomad_core::updater::{self, UpdateOptions, UpdateOutcome};
use nomad_core::{Arch, BrowserFamily, Floorp};

#[tokio::test]
#[ignore = "downloads and extracts the current upstream release"]
async fn floorp_release_downloads_verifies_and_extracts() {
    let temp = tempfile::tempdir().expect("temporary compatibility directory");
    let install_dir = temp.path().join("Browser");
    let browser = Floorp::new(Arch::X64);

    let outcome = updater::update(
        &browser,
        &install_dir,
        UpdateOptions {
            check_on_launch: true,
            auto_download: true,
        },
    )
    .await
    .unwrap_or_else(|error| {
        panic!("Floorp's live download/verification/extraction pipeline failed: {error}")
    });

    assert!(
        matches!(outcome, UpdateOutcome::Updated(_)),
        "a fresh temporary install must produce Updated, got {outcome:?}"
    );
    let command = browser.launch_command(&install_dir, &[]);
    let executable = std::path::Path::new(command.get_program());
    assert!(
        executable.is_file(),
        "Floorp extracted but its configured launch target does not exist: {}",
        executable.display()
    );
    assert!(
        browser.installed_version(&install_dir).is_some(),
        "the staged version marker did not survive the atomic swap"
    );
}
