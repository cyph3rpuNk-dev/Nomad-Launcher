//! Mandatory, read-only layout checks for authenticated staged packages.
//!
//! These contracts cover a minimum set of critical files, not an exhaustive
//! package inventory or runtime compatibility. They never execute the package
//! or replace signature verification.

use std::path::{Component, Path};

use super::{BrowserError, Result};

const CHROMIUM_RUNTIME: &[&str] = &[
    "chrome.dll",
    "resources.pak",
    "icudtl.dat",
    "chrome_100_percent.pak",
    "chrome_200_percent.pak",
];
const GECKO_RUNTIME: &[&str] = &["xul.dll", "application.ini", "omni.ja", "browser/omni.ja"];

/// Explicit package layout required before an update may replace the browser.
/// Each executable name is one filename at the staging root. Every adapter
/// must declare a layout; browser-specific validation cannot bypass this gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedInstallLayout {
    /// Chromium executable plus DLL, resource bundle, ICU data and both PAKs.
    Chromium(&'static str),
    /// Gecko executable plus XUL, application metadata and both omnijars.
    Gecko(&'static str),
    /// An authenticated self-contained portable executable (Bitwarden).
    PortableExecutable(&'static str),
}

impl StagedInstallLayout {
    pub(crate) fn validate(self, stage: &Path) -> Result<()> {
        let (executable, runtime) = match self {
            Self::Chromium(name) => (name, CHROMIUM_RUNTIME),
            Self::Gecko(name) => (name, GECKO_RUNTIME),
            Self::PortableExecutable(name) => (name, &[][..]),
        };
        // Declarations come from reviewed adapters, not upstream metadata.
        // Refuse a malformed declaration instead of resolving a foreign path.
        let mut parts = Path::new(executable).components();
        if executable.is_empty()
            || executable.contains(['/', '\\', ':'])
            || executable.ends_with(['.', ' '])
            || !matches!(parts.next(), Some(Component::Normal(_)))
            || parts.next().is_some()
        {
            return Err(incompatible(
                executable,
                "invalid staged executable declaration",
            ));
        }
        let root = metadata(stage, "staging root")?;
        if !root.is_dir() || is_link(&root) {
            return Err(incompatible(
                "staging root",
                "must be an ordinary directory",
            ));
        }
        for name in std::iter::once(executable).chain(runtime.iter().copied()) {
            validate_file(stage, name)?;
        }
        Ok(())
    }
}

fn incompatible(name: &str, reason: &str) -> BrowserError {
    BrowserError::Compatibility(format!(
        "required staged entry `{name}` {reason}; the working installation was not replaced"
    ))
}

fn metadata(path: &Path, name: &str) -> Result<std::fs::Metadata> {
    std::fs::symlink_metadata(path)
        .map_err(|e| incompatible(name, &format!("is missing or unreadable: {e}")))
}

fn validate_file(stage: &Path, name: &str) -> Result<()> {
    let mut path = stage.to_path_buf();
    let mut parts = Path::new(name).components().peekable();
    while let Some(part) = parts.next() {
        path.push(part.as_os_str());
        let entry = metadata(&path, name)?;
        if is_link(&entry) {
            return Err(incompatible(
                name,
                "must not resolve through a symlink or reparse point",
            ));
        }
        if parts.peek().is_some() {
            if !entry.is_dir() {
                return Err(incompatible(name, "has a non-directory parent"));
            }
        } else if !entry.is_file() || entry.len() == 0 {
            return Err(incompatible(name, "must be a nonempty regular file"));
        }
    }
    Ok(())
}

fn is_link(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(stage: &Path, layout: StagedInstallLayout) {
        let (executable, files) = match layout {
            StagedInstallLayout::Chromium(name) => (name, CHROMIUM_RUNTIME),
            StagedInstallLayout::Gecko(name) => (name, GECKO_RUNTIME),
            StagedInstallLayout::PortableExecutable(name) => (name, &[][..]),
        };
        for name in std::iter::once(executable).chain(files.iter().copied()) {
            let path = stage.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"inert fixture; never executed").unwrap();
        }
    }

    #[test]
    fn complete_layout_checks_are_read_only() {
        for layout in [
            StagedInstallLayout::Chromium("chrome.exe"),
            StagedInstallLayout::Gecko("firefox.exe"),
            StagedInstallLayout::PortableExecutable("Bitwarden-Portable.exe"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let stage = temp.path().join("Browser.stage");
            fixture(&stage, layout);
            layout.validate(&stage).unwrap();
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
            for marker in [".nomad-version", ".branding-patched", "Nomad", "Data"] {
                assert!(!stage.join(marker).exists());
            }
        }
    }

    #[test]
    fn stage_root_must_be_a_directory_and_executable_must_be_at_root() {
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("Browser.stage");
        let layout = StagedInstallLayout::PortableExecutable("app.exe");
        assert!(layout.validate(&stage).is_err());
        std::fs::write(&stage, b"wrong type").unwrap();
        assert!(layout.validate(&stage).is_err());
        std::fs::remove_file(&stage).unwrap();
        std::fs::create_dir_all(stage.join("bin")).unwrap();
        std::fs::write(stage.join("bin/app.exe"), b"wrong layout").unwrap();
        assert!(layout.validate(&stage).is_err());
    }

    #[test]
    fn malformed_executable_declarations_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        for name in [
            "",
            ".",
            "..",
            "../app.exe",
            "bin/app.exe",
            "bin\\app.exe",
            "/app.exe",
            "C:app.exe",
            "C:/app.exe",
            "./app.exe",
            "app.exe.",
            "app.exe ",
        ] {
            let result = StagedInstallLayout::PortableExecutable(name).validate(temp.path());
            assert!(
                matches!(result, Err(BrowserError::Compatibility(ref message))
                if message.contains("declaration")),
                "{name}: {result:?}"
            );
        }
    }

    #[test]
    fn nested_required_files_cannot_have_a_file_as_parent() {
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("Browser.stage");
        let layout = StagedInstallLayout::Gecko("firefox.exe");
        fixture(&stage, layout);
        std::fs::remove_file(stage.join("browser/omni.ja")).unwrap();
        std::fs::remove_dir(stage.join("browser")).unwrap();
        std::fs::write(stage.join("browser"), b"not a directory").unwrap();
        let error = layout.validate(&stage).unwrap_err();
        assert!(error.to_string().contains("non-directory parent"));
    }

    #[test]
    fn required_paths_reject_directory_links() {
        let temp = tempfile::tempdir().unwrap();
        let real_stage = temp.path().join("real-stage");
        let stage_link = temp.path().join("stage-link");
        let portable = StagedInstallLayout::PortableExecutable("app.exe");
        fixture(&real_stage, portable);
        link_directory(&temp, &stage_link, &real_stage);
        assert!(portable.validate(&stage_link).is_err());
        assert_eq!(
            std::fs::read(real_stage.join("app.exe")).unwrap(),
            b"inert fixture; never executed"
        );

        let stage = temp.path().join("Browser.stage");
        let gecko = StagedInstallLayout::Gecko("firefox.exe");
        fixture(&stage, gecko);
        let target = temp.path().join("linked-runtime");
        std::fs::rename(stage.join("browser"), &target).unwrap();
        link_directory(&temp, &stage.join("browser"), &target);
        let result = gecko.validate(&stage);
        assert!(matches!(result, Err(BrowserError::Compatibility(ref m))
            if m.contains("symlink or reparse point")));
        assert_eq!(
            std::fs::read(target.join("omni.ja")).unwrap(),
            b"inert fixture; never executed"
        );
    }

    fn link_directory(temp: &tempfile::TempDir, link: &Path, target: &Path) {
        let root = temp.path().canonicalize().unwrap();
        assert!(link
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(&root));
        assert!(target.canonicalize().unwrap().starts_with(&root));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            for path in [link, target] {
                assert!(path
                    .to_str()
                    .unwrap()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || r"\/:. _-".contains(c)));
            }
            let cmd = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe");
            let arguments = format!(
                r#"/d /s /c "mklink /J "{}" "{}"""#,
                link.to_string_lossy().replace('/', "\\"),
                target.to_string_lossy().replace('/', "\\")
            );
            let result = std::process::Command::new(cmd)
                .raw_arg(arguments)
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "fixture junction failed: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(target, link).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn required_executable_cannot_be_a_file_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("Browser.stage");
        std::fs::create_dir_all(&stage).unwrap();
        let external = temp.path().join("app.exe");
        std::fs::write(&external, b"foreign fixture").unwrap();
        std::os::unix::fs::symlink(&external, stage.join("app.exe")).unwrap();
        assert!(StagedInstallLayout::PortableExecutable("app.exe")
            .validate(&stage)
            .is_err());
    }
}
