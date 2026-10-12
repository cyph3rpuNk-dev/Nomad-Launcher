//! Package installation shared by all browser verticals.
//!
//! Two upstream package shapes are handled:
//!
//! * **ZIP archives** — stripped of a single shared top-level directory so the
//!   browser executable lands directly in `install_dir`.
//! * **NSIS installers** — extracted as archives via a bundled 7-Zip console
//!   (`7z.exe` + `7z.dll` embedded with `include_bytes!`). The installer is
//!   never *executed*, so no registry entries, shortcuts, `%PROGRAMDATA%` or
//!   `%LOCALAPPDATA%` folders are created.
//!
//! Both modes produce the browser tree at `install_dir/<browser>.exe`.

use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::browsers::{BrowserError, Result};

/// Embedded 7-Zip console executable. Extracted to a temp dir on first use of
/// `extract_with_7zip`. License: LGPLv2.1 — see `core/payloads/7zip/LICENSE.txt`.
const SEVENZIP_EXE: &[u8] = include_bytes!("../payloads/7zip/7z.exe");

/// Embedded 7-Zip archive engine. `7z.exe` loads this from its own directory.
const SEVENZIP_DLL: &[u8] = include_bytes!("../payloads/7zip/7z.dll");

/// Returns the single shared top-level directory across all `names`, if there
/// is exactly one — so it can be stripped to flatten the install.
fn common_top_dir(names: &[String]) -> Option<String> {
    let mut top: Option<&str> = None;
    for name in names {
        let first = name.split('/').next().filter(|s| !s.is_empty())?;
        match top {
            None => top = Some(first),
            Some(t) if t == first => {}
            Some(_) => return None,
        }
    }
    top.map(|t| format!("{t}/"))
}

/// Whether `relative` (a normalized, forward-slashed zip entry path) is safe to
/// join onto an extraction root. Rejects any parent-dir, filesystem-root, or
/// Windows drive-prefix component — each would let `Path::join` escape the
/// destination directory (directory traversal). Shared by every archive
/// extractor so the guard cannot drift between them.
pub(crate) fn is_safe_zip_path(relative: &str) -> bool {
    !Path::new(relative).components().any(|c| {
        matches!(
            c,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    })
}

/// Cumulative decompressed-size ceiling for browser archives. The largest
/// legitimate package (ungoogled-chromium) expands to well under 2 GiB; a
/// crafted high-ratio archive past this aborts extraction instead of filling
/// the portable drive (the 1 GiB download cap only bounds the *compressed*
/// input).
const MAX_DECOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Copies one zip entry to `out`, charging it against `remaining` — the
/// archive's cumulative decompressed budget.
///
/// # Errors
/// Returns [`BrowserError::Extract`] once the budget is exhausted (decompression
/// bomb) and [`BrowserError::Io`] on write failure.
pub(crate) fn copy_entry_capped(
    entry: impl std::io::Read,
    out: &mut impl std::io::Write,
    remaining: &mut u64,
) -> Result<()> {
    // Reading budget + 1 proves the archive exceeds it without ever writing
    // unbounded data; the partially-written file dies with the staging dir.
    let copied = std::io::copy(&mut entry.take(*remaining + 1), out)?;
    if copied > *remaining {
        return Err(BrowserError::Extract(
            "archive exceeds the decompressed-size budget (possible zip bomb)".to_owned(),
        ));
    }
    *remaining -= copied;
    Ok(())
}

/// Extracts a zip archive into `install_dir`, stripping a single shared
/// top-level directory so the executable lands directly in `install_dir`.
///
/// Path entries that would escape `install_dir` (via `..`, a leading `/`, or
/// a Windows drive prefix such as `C:/…`) are silently skipped. Cumulative
/// decompressed output is capped at [`MAX_DECOMPRESSED_BYTES`].
///
/// # Errors
/// Returns [`BrowserError::Extract`] if the archive cannot be read, is
/// malformed, or exceeds the decompressed-size cap, and [`BrowserError::Io`]
/// if a file cannot be written.
pub(crate) fn extract_zip(package: &Path, install_dir: &Path) -> Result<()> {
    extract_zip_with_budget(package, install_dir, MAX_DECOMPRESSED_BYTES)
}

fn extract_zip_with_budget(package: &Path, install_dir: &Path, budget: u64) -> Result<()> {
    crate::fs_safety::ensure_directory(install_dir)?;
    crate::fs_safety::ensure_file(package)?;
    let mut remaining = budget;
    let file = File::open(package)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| BrowserError::Extract(e.to_string()))?;

    let names: Vec<String> = (0..archive.len())
        .map(|i| {
            archive
                .by_index(i)
                .map(|e| e.name().replace('\\', "/"))
                .map_err(|e| BrowserError::Extract(e.to_string()))
        })
        .collect::<Result<_>>()?;
    let strip = common_top_dir(&names);

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| BrowserError::Extract(e.to_string()))?;
        let name = entry.name().replace('\\', "/");
        if name.contains("..") || name.starts_with('/') {
            continue;
        }
        let relative = strip
            .as_deref()
            .and_then(|prefix| name.strip_prefix(prefix))
            .unwrap_or(&name)
            .trim_start_matches('/');
        if relative.is_empty() {
            continue;
        }
        if !is_safe_zip_path(relative) {
            tracing::warn!(entry = %name, "skipping zip entry with unsafe path");
            continue;
        }

        let out = install_dir.join(relative);
        if entry.is_dir() || name.ends_with('/') {
            crate::fs_safety::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                crate::fs_safety::create_dir_all(parent)?;
            }
            crate::fs_safety::ensure_file(&out)?;
            let mut out_file = File::create(&out)?;
            copy_entry_capped(&mut entry, &mut out_file, &mut remaining)?;
        }
    }
    Ok(())
}

/// Extracts a Windows NSIS installer **as an archive** using the bundled
/// 7-Zip console. The installer is never executed, so no registry entries,
/// shortcuts, or system-wide directories are created — only files land under
/// `install_dir`. After extraction the install tree is flattened so that
/// `marker_exe` lands directly in `install_dir`.
///
/// # Errors
/// Returns [`BrowserError::Extract`] on 7-Zip spawn failure, non-zero exit, or
/// when `marker_exe` cannot be located, or an extraction budget/deadline is exceeded.
pub(crate) fn extract_nsis_with_7zip(
    installer: &Path,
    install_dir: &Path,
    marker_exe: &str,
) -> Result<()> {
    extract_nsis_with_limits(
        installer,
        install_dir,
        marker_exe,
        MAX_DECOMPRESSED_BYTES,
        std::time::Duration::from_mins(10),
    )
}

fn extract_nsis_with_limits(
    installer: &Path,
    install_dir: &Path,
    marker_exe: &str,
    max_bytes: u64,
    timeout: std::time::Duration,
) -> Result<()> {
    crate::fs_safety::ensure_file(installer)?;
    crate::fs_safety::create_dir_all(install_dir)?;

    let tools = stage_seven_zip(install_dir)?;
    let raw_dir = install_dir.join("__nomad_extract_raw");
    crate::fs_safety::ensure_directory(&raw_dir)?;
    if raw_dir.exists() {
        std::fs::remove_dir_all(&raw_dir)?;
    }
    crate::fs_safety::create_dir_all(&raw_dir)?;

    let mut command = Command::new(&tools.exe);
    command
        .arg("x")
        .arg(installer)
        .arg(format!("-o{}", raw_dir.display()))
        .arg("-y")
        .arg("-bso0")
        .arg("-bse0");
    run_bounded_extractor(&mut command, &raw_dir, max_bytes, timeout)?;

    crate::fs_safety::ensure_tree(&raw_dir)?;
    let exe_dir = find_marker_dir(&raw_dir, marker_exe)
        .ok_or_else(|| BrowserError::Extract(format!("{marker_exe} not found after extraction")))?;
    flatten_into(&exe_dir, install_dir)?;
    let _ = std::fs::remove_dir_all(&raw_dir);

    // Strip NSIS metadata files left at the root by 7-Zip's NSIS handler.
    for junk in [
        "$PLUGINSDIR",
        "[NSIS].nsi",
        "uninstall.exe",
        "Uninstall.exe",
    ] {
        let p = install_dir.join(junk);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&p);
    }
    Ok(())
}

/// Poll the owned extractor and its ordinary output tree. This is an observed
/// size limit, not an OS disk quota: output may overshoot between scans.
fn run_bounded_extractor(
    command: &mut Command,
    output: &Path,
    max_bytes: u64,
    timeout: std::time::Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    // Never inherit the UI's console or allow captured pipes to fill up.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command
        .spawn()
        .map_err(|error| BrowserError::Extract(format!("failed to spawn extractor: {error}")))?;
    let result = loop {
        if let Err(error) = check_extracted_budget(output, max_bytes, deadline) {
            break Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Recheck after exit: the last scan can precede the last write.
                break if status.success() {
                    check_extracted_budget(output, max_bytes, deadline)
                } else {
                    Err(BrowserError::Extract(format!(
                        "extractor exited with status {status}"
                    )))
                };
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(error) => break Err(error.into()),
        }
    };
    if result.is_err() {
        // Stop and reap before the staging/helper directories may be dropped.
        // A natural exit between polling and kill is also safe to reap.
        if let Err(error) = child.kill() {
            if child.try_wait()?.is_none() {
                return Err(BrowserError::Extract(format!(
                    "cannot stop extractor: {error}"
                )));
            }
        }
        child.wait()?;
    }
    result
}

fn check_extracted_budget(root: &Path, max_bytes: u64, deadline: std::time::Instant) -> Result<()> {
    check_extracted_budget_with_entries(root, max_bytes, 100_000, deadline)
}

fn check_extracted_budget_with_entries(
    root: &Path,
    max_bytes: u64,
    max_entries: usize,
    deadline: std::time::Instant,
) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut bytes = 0_u64;
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        check_extraction_deadline(deadline)?;
        crate::fs_safety::ensure_directory(&directory)?;
        for entry in std::fs::read_dir(directory)? {
            check_extraction_deadline(deadline)?;
            let path = entry?.path();
            entries += 1;
            if entries > max_entries {
                return Err(BrowserError::Extract(format!(
                    "extraction exceeds the {max_entries}-entry budget"
                )));
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                crate::fs_safety::ensure_directory(&path)?;
                pending.push(path);
            } else {
                crate::fs_safety::ensure_file(&path)?;
                if !metadata.is_file() {
                    return Err(BrowserError::Extract(
                        "extractor produced a non-regular file".into(),
                    ));
                }
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| BrowserError::Extract("extracted-size overflow".into()))?;
                if bytes > max_bytes {
                    return Err(BrowserError::Extract(format!(
                        "extraction exceeds the {max_bytes} B budget"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn check_extraction_deadline(deadline: std::time::Instant) -> Result<()> {
    if std::time::Instant::now() >= deadline {
        Err(BrowserError::Extract("extraction deadline exceeded".into()))
    } else {
        Ok(())
    }
}

/// Moves every entry of `install_dir/<subdir>/` up into `install_dir/` and
/// removes the now-empty `<subdir>`. Used for ZIPs whose useful contents are
/// nested inside a brand-named directory rather than at the root (e.g.
/// `LibreWolf`'s portable bundle wraps the actual browser in `LibreWolf/`).
///
/// If a target name in `install_dir` already exists, that entry is skipped to
/// avoid overwriting it. Returns the number of entries successfully promoted.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the nested directory can be read but a
/// move fails for a non-conflict reason.
pub(crate) fn promote_subdir(install_dir: &Path, subdir: &str) -> Result<u32> {
    crate::fs_safety::ensure_directory(install_dir)?;
    let nested = install_dir.join(subdir);
    crate::fs_safety::ensure_tree(&nested)?;
    if !nested.is_dir() {
        return Ok(0);
    }
    let mut moved: u32 = 0;
    for entry in std::fs::read_dir(&nested)? {
        let entry = entry?;
        let src = entry.path();
        let dst = install_dir.join(entry.file_name());
        if dst.exists() {
            tracing::warn!(
                src = %src.display(),
                dst = %dst.display(),
                "promote_subdir: target exists, skipping"
            );
            continue;
        }
        std::fs::rename(&src, &dst)?;
        moved += 1;
    }
    // The nested dir should now be empty; ignore failures (caller can retry).
    let _ = std::fs::remove_dir(&nested);
    if moved > 0 {
        tracing::info!(
            subdir,
            moved,
            "promoted nested browser directory to install root"
        );
    }
    Ok(moved)
}

/// Removes auxiliary executables that Mozilla-family installers ship alongside
/// the browser binary. Each of these is spawned by `firefox.exe` (or `floorp`/
/// `waterfox`) on startup and writes working data to `%LOCALAPPDATA%\Mozilla\`
/// or `%PROGRAMDATA%\Mozilla-<GUID>\` — *before* `policies.json` is even read.
/// Removing the binaries themselves is the only reliable way to suppress those
/// host-system traces (the corresponding Firefox features are already disabled
/// by our `user.js` / `policies.json`, so the missing executables are never
/// needed for normal browsing).
///
/// All operations are best-effort: missing files are silently ignored, since
/// individual Mozilla forks ship slightly different subsets of these helpers.
pub(crate) fn strip_mozilla_runtime_extras(install_dir: &Path) {
    const JUNK: &[&str] = &[
        // Creates %PROGRAMDATA%\Mozilla-<GUID>\ on first launch.
        "default-browser-agent.exe",
        "default-agent.exe",
        // Sends telemetry pings — telemetry is disabled by our policies.
        "pingsender.exe",
        // Maintenance Service writes %PROGRAMDATA%\Mozilla\ for elevated updates.
        "maintenanceservice.exe",
        "maintenanceservice_installer.exe",
        // Crash reporter writes %LOCALAPPDATA%\Mozilla\Firefox\Crash Reports\.
        "crashreporter.exe",
        "minidump-analyzer.exe",
        // Updater writes %LOCALAPPDATA%\Mozilla\updates\.
        "updater.exe",
        "updateagent.exe",
    ];
    let mut removed = 0;
    for name in JUNK {
        if std::fs::remove_file(install_dir.join(name)).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(
            count = removed,
            "stripped Mozilla auxiliary executables from install_dir"
        );
    }
}

struct SevenZipTools {
    exe: PathBuf,
    /// Temp dir holding `7z.exe` + `7z.dll`. Cleaned up when dropped.
    _dir: TempDir,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes the embedded 7-Zip console to a fresh subdirectory of `base` — the
/// portable install dir — so extraction/branding scratch stays inside the Nomad
/// directory rather than `%LOCALAPPDATA%\Temp` (no-trace; CLAUDE.md invariant
/// #1). The subdir name is unique per call so concurrent runs do not race on
/// Drop, which also removes the dir.
fn stage_seven_zip(base: &Path) -> Result<SevenZipTools> {
    use std::hash::{BuildHasher, RandomState};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);

    crate::fs_safety::create_dir_all(base)?;
    // Unpredictable name (OS-seeded `RandomState`) so an attacker cannot
    // pre-create the staging dir with a planted `7z.dll`; `create_dir` (not
    // `create_dir_all`) then fails if the path already exists rather than
    // writing 7-Zip into a directory we do not exclusively own (CWE-377/427).
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let token = RandomState::new().hash_one((std::process::id(), n));
    let dir = base.join(format!("nomad-7z-{token:016x}"));
    std::fs::create_dir(&dir)?;
    let exe = dir.join("7z.exe");
    crate::fs_safety::write(&exe, SEVENZIP_EXE)?;
    crate::fs_safety::write(dir.join("7z.dll"), SEVENZIP_DLL)?;
    Ok(SevenZipTools {
        exe,
        _dir: TempDir(dir),
    })
}

/// Recursively walks `root` looking for the first directory containing a file
/// whose name equals `marker_exe` (case-insensitive). Returns that directory.
fn find_marker_dir(root: &Path, marker_exe: &str) -> Option<PathBuf> {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut subdirs: Vec<PathBuf> = Vec::new();
        let mut has_marker = false;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                subdirs.push(path);
            } else if let Some(name) = path.file_name() {
                if name.to_string_lossy().eq_ignore_ascii_case(marker_exe) {
                    has_marker = true;
                }
            }
        }
        if has_marker {
            return Some(dir);
        }
        stack.extend(subdirs);
    }
    None
}

/// Moves every direct child of `src` into `dest`, replacing entries with the
/// same name. Removes `src` and any now-empty ancestors up to (but excluding)
/// `dest` when it has finished.
fn flatten_into(src: &Path, dest: &Path) -> Result<()> {
    crate::fs_safety::ensure_tree(src)?;
    crate::fs_safety::ensure_tree(dest)?;
    if src == dest {
        return Ok(());
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if to.exists() {
            if to.is_dir() {
                let _ = std::fs::remove_dir_all(&to);
            } else {
                let _ = std::fs::remove_file(&to);
            }
        }
        std::fs::rename(&from, &to)?;
    }
    let _ = std::fs::remove_dir(src);
    // Walk upward and remove empty ancestors stopping before `dest`.
    let mut current = src.parent();
    while let Some(p) = current {
        if p == dest || !p.starts_with(dest) {
            break;
        }
        if std::fs::remove_dir(p).is_err() {
            break;
        }
        current = p.parent();
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write;

    #[test]
    fn embedded_7zip_matches_reviewed_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../payloads/7zip/manifest.json")).unwrap();
        for (name, bytes) in [
            ("7z.exe", SEVENZIP_EXE),
            ("7z.dll", SEVENZIP_DLL),
            (
                "LICENSE.txt",
                include_bytes!("../payloads/7zip/LICENSE.txt").as_slice(),
            ),
        ] {
            let expected = manifest["files"][name]
                .as_str()
                .expect("reviewed digest is required");
            crate::gpg::sha256::verify(bytes, expected).unwrap_or_else(|error| {
                panic!("bundled {name} differs from the reviewed manifest: {error}")
            });
        }
        assert_eq!(manifest["architecture"], "x86_64");
        for bytes in [SEVENZIP_EXE, SEVENZIP_DLL] {
            assert_eq!(&bytes[..2], b"MZ");
            let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
            assert_eq!(&bytes[offset..offset + 4], b"PE\0\0");
            assert_eq!(
                u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().unwrap()),
                0x8664,
                "the bundled extractor must match the x64 release target"
            );
        }
    }

    // Child runs this same inert test helper, never an installer or browser.
    #[test]
    fn extractor_process_fixture() {
        let Some(output) = std::env::var_os("NOMAD_EXTRACTOR_TEST_OUTPUT") else {
            return;
        };
        let mode = std::env::var("NOMAD_EXTRACTOR_TEST_MODE").unwrap();
        if mode == "oversize" {
            std::fs::write(Path::new(&output).join("inert.bin"), [0; 512]).unwrap();
        }
        if mode == "exit-oversize" {
            std::fs::write(Path::new(&output).join("inert.bin"), [0; 512]).unwrap();
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
        // Kill/reap must prevent this delayed write, even after failure returns.
        std::fs::write(Path::new(&output).join("still-running"), b"bad").unwrap();
    }

    fn fixture_command(output: &Path, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "extract::tests::extractor_process_fixture"])
            .env("NOMAD_EXTRACTOR_TEST_OUTPUT", output)
            .env("NOMAD_EXTRACTOR_TEST_MODE", mode);
        command
    }

    #[test]
    fn extractor_deadline_kills_and_reaps_child() {
        let dir = tempfile::tempdir().unwrap();
        let start = std::time::Instant::now();
        let mut command = fixture_command(dir.path(), "sleep");
        let error = run_bounded_extractor(
            &mut command,
            dir.path(),
            1024,
            std::time::Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(start.elapsed() < std::time::Duration::from_secs(4));
        assert!(!dir.path().join("still-running").exists());
        // Removing the directory after reaping cannot race with a live writer.
        dir.close().unwrap();
    }

    #[test]
    fn extractor_budget_kills_and_reaps_running_child() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = fixture_command(dir.path(), "oversize");
        let error = run_bounded_extractor(
            &mut command,
            dir.path(),
            64,
            std::time::Duration::from_secs(4),
        )
        .unwrap_err();
        assert!(error.to_string().contains("budget"));
        assert!(!dir.path().join("still-running").exists());
        dir.close().unwrap();
    }

    #[test]
    fn successful_extractor_exit_still_checks_final_output_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = fixture_command(dir.path(), "exit-oversize");
        assert!(run_bounded_extractor(
            &mut command,
            dir.path(),
            64,
            std::time::Duration::from_secs(4)
        )
        .is_err());
    }

    #[test]
    fn zero_length_files_still_consume_the_entry_budget() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("one"), b"").unwrap();
        std::fs::write(dir.path().join("two"), b"").unwrap();
        let error = check_extracted_budget_with_entries(
            dir.path(),
            1024,
            1,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(error.to_string().contains("entry budget"));
    }

    #[test]
    fn extractor_nonzero_exit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.arg("--not-a-test-harness-option");
        assert!(run_bounded_extractor(
            &mut command,
            dir.path(),
            1024,
            std::time::Duration::from_secs(4)
        )
        .is_err());
    }

    #[test]
    fn bundled_extraction_rejects_output_over_the_budget_before_promotion() {
        let fixture = tempfile::tempdir().unwrap();
        let archive = fixture.path().join("pkg.zip");
        let output = fixture.path().join("Browser.stage");
        let active = fixture.path().join("Browser");
        let profile = fixture.path().join("Data");
        std::fs::create_dir(&active).unwrap();
        std::fs::create_dir(&profile).unwrap();
        std::fs::write(active.join("firefox.exe"), b"working browser").unwrap();
        std::fs::write(profile.join("sentinel"), b"user data").unwrap();
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        zip.start_file(
            "bundle/firefox.exe",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&[b'x'; 512]).unwrap();
        zip.finish().unwrap();
        let result = extract_nsis_with_limits(
            &archive,
            &output,
            "firefox.exe",
            64,
            std::time::Duration::from_secs(10),
        );
        assert!(
            result.is_err(),
            "over-budget extracted output must not be promoted"
        );
        assert!(!output.join("firefox.exe").exists());
        assert_eq!(
            std::fs::read(active.join("firefox.exe")).unwrap(),
            b"working browser"
        );
        assert_eq!(
            std::fs::read(profile.join("sentinel")).unwrap(),
            b"user data"
        );
    }

    #[test]
    fn archive_promotion_rejects_linked_sources_without_removing_them() {
        let fixture = tempfile::tempdir().unwrap();
        let dest = fixture.path().join("stage");
        let foreign = fixture.path().join("foreign");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("file"), b"keep").unwrap();
        let linked = dest.join("LibreWolf");
        crate::tests::owned_directory_link(&fixture, &linked, &foreign);
        assert!(promote_subdir(&dest, "LibreWolf").is_err());
        assert!(flatten_into(&linked, &dest).is_err());
        assert_eq!(std::fs::read(foreign.join("file")).unwrap(), b"keep");
        assert!(linked.exists());
        assert!(!dest.join("file").exists());
    }

    #[test]
    fn zip_extraction_rejects_a_linked_output_parent() {
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("stage");
        let foreign = temp.path().join("foreign");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("victim"), b"foreign data").unwrap();
        crate::tests::owned_directory_link(&temp, &stage.join("nested"), &foreign);
        let archive = temp.path().join("pkg.zip");
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("bundle/nested/victim", options).unwrap();
        zip.write_all(b"replacement").unwrap();
        zip.start_file("bundle/readme", options).unwrap();
        zip.write_all(b"fixture").unwrap();
        zip.finish().unwrap();
        assert!(extract_zip(&archive, &stage).is_err());
        assert_eq!(
            std::fs::read(foreign.join("victim")).unwrap(),
            b"foreign data"
        );
    }

    use super::*;

    #[test]
    fn copy_entry_capped_enforces_the_cumulative_budget() {
        // Within budget: bytes flow through and the budget is charged.
        let mut remaining: u64 = 10;
        let mut out = Vec::new();
        copy_entry_capped(&mut &b"0123456789"[..], &mut out, &mut remaining).unwrap();
        assert_eq!(out, b"0123456789");
        assert_eq!(remaining, 0);

        // One byte over the (now exhausted) budget: Extract error.
        let err = copy_entry_capped(&mut &b"x"[..], &mut Vec::new(), &mut remaining)
            .expect_err("an exhausted budget must reject further bytes");
        assert!(matches!(err, BrowserError::Extract(_)), "got {err:?}");
    }

    #[test]
    fn extract_zip_rejects_an_archive_exceeding_the_decompressed_budget() {
        // The 1 GiB download cap bounds compressed input only; the
        // decompressed budget is what stops a high-ratio bomb from filling
        // the portable drive. Exercised with a tiny budget so the test
        // writes bytes, not gigabytes.
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("bomb.zip");
        let mut writer = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        writer.start_file("payload.bin", opts).unwrap();
        writer.write_all(&[0u8; 1024]).unwrap();
        writer.finish().unwrap();

        let install = dir.path().join("install");
        let err = extract_zip_with_budget(&zip_path, &install, 64)
            .expect_err("an over-budget archive must abort extraction");
        assert!(matches!(err, BrowserError::Extract(_)), "got {err:?}");

        // The same archive extracts fine under a sufficient budget.
        let install_ok = dir.path().join("install-ok");
        extract_zip_with_budget(&zip_path, &install_ok, 2048).unwrap();
        assert!(install_ok.join("payload.bin").is_file());
    }

    #[test]
    fn common_top_dir_detects_single_shared_root() {
        let names = vec![
            "browser-148/chrome.exe".to_owned(),
            "browser-148/resources/x.pak".to_owned(),
        ];
        assert_eq!(common_top_dir(&names).as_deref(), Some("browser-148/"));
    }

    #[test]
    fn common_top_dir_is_none_for_multiple_roots() {
        let names = vec!["a/x".to_owned(), "b/y".to_owned()];
        assert!(common_top_dir(&names).is_none());
    }

    #[test]
    fn extract_strips_the_shared_top_directory() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("pkg.zip");

        let mut writer = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        writer.start_file("browser-v1/browser.exe", opts).unwrap();
        writer.write_all(b"BINARY").unwrap();
        writer
            .start_file("browser-v1/resources/app.pak", opts)
            .unwrap();
        writer.write_all(b"PAK").unwrap();
        writer.finish().unwrap();

        let install = dir.path().join("install");
        extract_zip(&zip_path, &install).expect("extraction must succeed");

        assert_eq!(
            std::fs::read(install.join("browser.exe")).unwrap(),
            b"BINARY"
        );
        assert_eq!(
            std::fs::read(install.join("resources/app.pak")).unwrap(),
            b"PAK"
        );
    }

    #[test]
    fn extract_skips_path_traversal_entries() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("evil.zip");

        let mut writer = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        writer.start_file("../evil.txt", opts).unwrap();
        writer.write_all(b"ESCAPE").unwrap();
        writer.finish().unwrap();

        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        extract_zip(&zip_path, &install).expect("extraction must not fail on traversal entries");

        assert!(
            !dir.path().join("evil.txt").exists(),
            "path traversal entry must be skipped"
        );
    }

    #[test]
    fn extract_skips_drive_absolute_entries() {
        // An entry whose name is an absolute path with a drive prefix must not
        // escape install_dir. On Windows `install_dir.join("C:/…")` discards the
        // base, so without the component guard this would write outside (CWE-22).
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("evil.zip");

        // Target a path we control (a sibling temp dir) so the test is
        // non-destructive whether or not the guard holds.
        let escape_dir = tempfile::tempdir().unwrap();
        let escape_target = escape_dir.path().join("escaped.txt");
        let entry_name = escape_target.to_string_lossy().replace('\\', "/");

        let mut writer = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        writer.start_file(&entry_name, opts).unwrap();
        writer.write_all(b"ESCAPE").unwrap();
        // A legitimate sibling entry must still extract.
        writer.start_file("safe.txt", opts).unwrap();
        writer.write_all(b"SAFE").unwrap();
        writer.finish().unwrap();

        let install = dir.path().join("install");
        extract_zip(&zip_path, &install).expect("extraction must not fail on unsafe entries");

        assert!(
            !escape_target.exists(),
            "drive-absolute entry must be skipped, not written outside install_dir"
        );
        assert_eq!(
            std::fs::read(install.join("safe.txt")).unwrap(),
            b"SAFE",
            "legitimate entries must still extract"
        );
    }

    #[test]
    fn find_marker_dir_locates_nested_executable() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Files").join("Mozilla Firefox");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("firefox.exe"), b"x").unwrap();
        let found = find_marker_dir(dir.path(), "firefox.exe").unwrap();
        assert_eq!(found, nested);
    }

    #[test]
    fn find_marker_dir_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Floorp.exe"), b"x").unwrap();
        let found = find_marker_dir(dir.path(), "floorp.exe").unwrap();
        assert_eq!(found, dir.path());
    }

    #[test]
    fn find_marker_dir_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other.exe"), b"x").unwrap();
        assert!(find_marker_dir(dir.path(), "firefox.exe").is_none());
    }

    #[test]
    fn flatten_into_moves_children_and_cleans_up_empty_parents() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("install");
        std::fs::create_dir_all(&dest).unwrap();
        let nested = dest.join("Files").join("Mozilla Firefox");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("firefox.exe"), b"X").unwrap();
        std::fs::create_dir_all(nested.join("browser")).unwrap();
        std::fs::write(nested.join("browser/omni.ja"), b"Y").unwrap();

        flatten_into(&nested, &dest).unwrap();

        assert!(
            dest.join("firefox.exe").exists(),
            "exe must be at install root"
        );
        assert!(
            dest.join("browser/omni.ja").exists(),
            "subtree must be preserved"
        );
        assert!(!dest.join("Files").exists(), "empty parent must be removed");
    }

    #[test]
    fn stage_seven_zip_writes_and_runs() {
        let base = tempfile::tempdir().unwrap();
        let tools = stage_seven_zip(base.path()).expect("staging must succeed");
        assert!(tools.exe.exists(), "7z.exe must be staged");
        let dll = tools.exe.parent().unwrap().join("7z.dll");
        assert!(dll.exists(), "7z.dll must be staged beside 7z.exe");
        // Run with no args; 7-Zip prints its banner and exits non-zero.
        let output = Command::new(&tools.exe)
            .output()
            .expect("must be able to spawn 7z.exe");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("7-Zip"),
            "banner must contain '7-Zip' (got: {stdout})"
        );
    }

    #[test]
    fn stage_seven_zip_uses_unique_dirs_per_call() {
        // Each call must stage into its own freshly-created directory so an
        // attacker cannot predict or pre-create the staging path (F-05).
        let base = tempfile::tempdir().unwrap();
        let a = stage_seven_zip(base.path()).expect("staging must succeed");
        let b = stage_seven_zip(base.path()).expect("staging must succeed");
        let dir_a = a.exe.parent().unwrap();
        let dir_b = b.exe.parent().unwrap();
        assert_ne!(dir_a, dir_b, "staging dirs must be unique per call");
        assert!(dir_a
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("nomad-7z-"));
    }

    #[test]
    fn promote_subdir_flattens_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();
        let nested = install.join("LibreWolf");
        std::fs::create_dir_all(nested.join("subdir")).unwrap();
        std::fs::write(nested.join("librewolf.exe"), b"binary").unwrap();
        std::fs::write(nested.join("xul.dll"), b"library").unwrap();
        std::fs::write(nested.join("subdir").join("file"), b"x").unwrap();

        let moved = promote_subdir(install, "LibreWolf").unwrap();
        assert_eq!(moved, 3, "three top-level entries should move up");
        assert!(install.join("librewolf.exe").exists());
        assert!(install.join("xul.dll").exists());
        assert!(install.join("subdir").join("file").exists());
        assert!(!nested.exists(), "nested dir should be removed");
    }

    #[test]
    fn promote_subdir_skips_when_subdir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let moved = promote_subdir(dir.path(), "NotThere").unwrap();
        assert_eq!(moved, 0);
    }

    #[test]
    fn promote_subdir_preserves_existing_conflicting_target() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();
        let nested = install.join("LibreWolf");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(install.join("distribution"), b"existing").unwrap();
        std::fs::write(nested.join("librewolf.exe"), b"binary").unwrap();
        std::fs::write(nested.join("distribution"), b"from-bundle").unwrap();

        let moved = promote_subdir(install, "LibreWolf").unwrap();
        assert_eq!(moved, 1, "only the non-conflicting entry should move");
        assert!(install.join("librewolf.exe").exists());
        assert_eq!(
            std::fs::read(install.join("distribution")).unwrap(),
            b"existing",
            "pre-existing target must not be overwritten"
        );
    }

    #[test]
    fn strip_mozilla_runtime_extras_removes_known_junk_only() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();
        // The junk Mozilla helpers we want to remove
        let junk = [
            "default-browser-agent.exe",
            "pingsender.exe",
            "maintenanceservice.exe",
            "crashreporter.exe",
            "updater.exe",
        ];
        // Files that must be preserved
        let keep = [
            "firefox.exe",
            "xul.dll",
            "mozglue.dll",
            "nss3.dll",
            "Application.ini",
        ];
        for name in junk.iter().chain(keep.iter()) {
            std::fs::write(install.join(name), b"x").unwrap();
        }
        strip_mozilla_runtime_extras(install);
        for name in &junk {
            assert!(!install.join(name).exists(), "junk {name} must be removed");
        }
        for name in &keep {
            assert!(
                install.join(name).exists(),
                "core file {name} must be preserved"
            );
        }
    }

    #[test]
    fn strip_mozilla_runtime_extras_is_idempotent() {
        // Calling on an install dir without any junk must not panic.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("firefox.exe"), b"x").unwrap();
        strip_mozilla_runtime_extras(dir.path());
        strip_mozilla_runtime_extras(dir.path());
        assert!(dir.path().join("firefox.exe").exists());
    }

    #[test]
    fn extract_nsis_with_7zip_unpacks_a_real_zip() {
        // 7-Zip extracts ZIPs as well; this verifies the spawn/flatten pipeline
        // without needing a real NSIS installer fixture in tree.
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("pkg.zip");
        let mut w = zip::ZipWriter::new(File::create(&archive).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("toplevel/firefox.exe", opts).unwrap();
        w.write_all(b"BINARY").unwrap();
        w.start_file("toplevel/browser/omni.ja", opts).unwrap();
        w.write_all(b"OMNI").unwrap();
        w.finish().unwrap();

        let install = dir.path().join("install");
        extract_nsis_with_7zip(&archive, &install, "firefox.exe")
            .expect("7-Zip extraction must succeed");

        assert!(
            install.join("firefox.exe").exists(),
            "exe must land at root"
        );
        assert_eq!(
            std::fs::read(install.join("firefox.exe")).unwrap(),
            b"BINARY"
        );
        assert!(install.join("browser/omni.ja").exists());
        assert!(
            !install.join("__nomad_extract_raw").exists(),
            "raw dir must be removed"
        );
    }
}
