//! Browser branding — PE icon patching.
//!
//! A freshly installed Chromium-family browser ships with the stock blue
//! Chromium icon baked into the `RT_GROUP_ICON` / `RT_ICON` resources of its
//! `chrome.exe` and `chrome.dll`.  [`ensure_branding`] rewrites those
//! resources with custom (grayscale) icons so the browser's taskbar button,
//! Alt-Tab entry and window icon match the launcher's branding.
//!
//! Patching is idempotent: a `.branding-patched` marker file records a
//! fingerprint of the branding icons and the target binaries.  Branding is
//! re-applied only when that fingerprint changes — i.e. after a browser
//! update replaces the binaries, or after the launcher ships new icons.
//!
//! The actual resource surgery is Windows-only (`BeginUpdateResourceW` /
//! `UpdateResourceW` / `EndUpdateResourceW`); on other platforms
//! [`ensure_branding`] is a no-op.

use std::path::Path;

mod chromium;
pub use chromium::CHROMIUM;

/// Artifact compatibility replaces the Chromium major-version ceiling. This
/// hook is mandatory even for headless callers that supply no branding config.
pub(crate) fn validate_chromium_stage(stage: &Path) -> crate::browsers::Result<()> {
    use crate::browsers::BrowserError;

    // Never trust a success marker supplied inside an upstream archive.
    let marker = stage.join(".branding-patched");
    if marker.exists() {
        std::fs::remove_file(marker)?;
    }
    for name in [
        "chrome.exe",
        "chrome.dll",
        "resources.pak",
        "icudtl.dat",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
    ] {
        if !std::fs::metadata(stage.join(name)).is_ok_and(|m| m.is_file() && m.len() > 0) {
            return Err(BrowserError::Compatibility(format!(
                "required Chromium file `{name}` is missing or empty; the working browser was not replaced"
            )));
        }
    }
    for name in ["chrome_100_percent.pak", "chrome_200_percent.pak"] {
        let bytes = std::fs::read(stage.join(name))?;
        let patches: Vec<&PakPatch> = CHROMIUM
            .pak_patches
            .iter()
            .filter(|p| p.pak_file == name)
            .collect();
        let compatible =
            rebuild_pak_with(&bytes, |resources| apply_logo_patches(resources, &patches))
                .is_ok_and(|(_, complete)| complete);
        if !compatible {
            return Err(BrowserError::Compatibility(format!(
                "required Chromium logos in `{name}` are missing, changed, or ambiguous; the working browser was not replaced"
            )));
        }
    }
    #[cfg(windows)]
    for (name, group) in [("chrome.exe", 100), ("chrome.dll", 101)] {
        read_pe_resource(&stage.join(name), RT_GROUP_ICON, &ResName::Id(group), false).map_err(
            |error| {
                BrowserError::Compatibility(format!(
                    "required Chromium icon group {group} in `{name}` is incompatible: {error}"
                ))
            },
        )?;
    }
    if !ensure_branding(stage, &CHROMIUM) {
        return Err(BrowserError::Compatibility(
            "required Chromium branding could not be applied; the working browser was not replaced"
                .to_owned(),
        ));
    }
    #[cfg(windows)]
    for name in ["chrome_100_percent.pak", "chrome_200_percent.pak"] {
        let bytes = std::fs::read(stage.join(name))?;
        let patches: Vec<&PakPatch> = CHROMIUM
            .pak_patches
            .iter()
            .filter(|p| p.pak_file == name)
            .collect();
        if !rebuild_pak_with(&bytes, |resources| apply_logo_patches(resources, &patches))
            .is_ok_and(|(patched, complete)| complete && patched == bytes)
        {
            let _ = std::fs::remove_file(stage.join(".branding-patched"));
            return Err(BrowserError::Compatibility(format!(
                "Chromium branding readback failed for `{name}`; the working browser was not replaced"
            )));
        }
    }
    Ok(())
}

// ── Public configuration types ───────────────────────────────────────────────

/// Resource name of an `RT_GROUP_ICON` to replace.
#[derive(Debug, Clone, Copy)]
pub enum BrandingGroup {
    /// A numeric resource identifier (e.g. `100`).
    Id(u16),
    /// A named resource (e.g. `"IDR_MAINFRAME"`).
    Named(&'static str),
}

/// One icon group to overwrite, paired with the `.ico` to write in its place.
#[derive(Debug, Clone, Copy)]
pub struct BrandingIcon {
    /// The `RT_GROUP_ICON` resource to replace.
    pub group: BrandingGroup,
    /// Raw `.ico` file bytes, embedded via `include_bytes!`.
    pub ico: &'static [u8],
}

/// A resource replacement to apply inside a Chromium PAK file after install.
///
/// Chromium PAK files bundle UI assets into a single binary blob keyed by
/// grit-generated integer IDs.  Nomad uses this to replace the product logo
/// shown on `chrome://settings/help` with the grayscale icon already used for
/// the taskbar and Alt-Tab entry (Stage 2).
#[derive(Debug, Clone, Copy)]
pub struct PakPatch {
    /// PAK file path relative to the browser install directory —
    /// e.g. `"chrome_100_percent.pak"`.
    pub pak_file: &'static str,
    /// Historical Chromium grit ID, retained as a diagnostic hint only.
    pub resource_id: u16,
    /// Known upstream logo. Resource IDs are hints only; decoded pixels must
    /// identify exactly one resource, even when grit renumbers the archive.
    pub expected_png_bytes: &'static [u8],
    /// Raw PNG bytes of the replacement image, embedded via `include_bytes!`.
    pub png_bytes: &'static [u8],
}

/// Branding configuration for a browser family.
#[derive(Debug, Clone, Copy)]
pub struct Branding {
    /// PE files inside the install directory to patch, relative to it —
    /// e.g. `&["chrome.exe", "chrome.dll"]`.
    pub targets: &'static [&'static str],
    /// Icon groups to replace in each target file.
    pub icons: &'static [BrandingIcon],
    /// PAK resource patches applied after PE icon patching.
    /// Pass `&[]` to skip PAK patching.
    pub pak_patches: &'static [PakPatch],
}

/// Name of the marker file recording the fingerprint of applied branding.
#[cfg(windows)]
const MARKER: &str = ".branding-patched";

// ── Public entry points ──────────────────────────────────────────────────────

/// Returns `true` if branding still needs to be applied to the install at
/// `install_dir`.
///
/// Branding is pending when the `.branding-patched` marker is missing, or when
/// its recorded fingerprint no longer matches the current one (see
/// `branding_fingerprint`) — meaning a browser update replaced the binaries
/// or the launcher shipped new icons. Used by the launcher pipeline to decide
/// whether to show an "Applying branding…" status before [`ensure_branding`].
#[cfg(windows)]
#[must_use]
pub fn is_pending(install_dir: &Path, branding: &Branding) -> bool {
    let marker = install_dir.join(MARKER);
    match std::fs::read_to_string(&marker) {
        Ok(recorded) => recorded.trim() != branding_fingerprint(install_dir, branding),
        Err(_) => true,
    }
}

/// Branding is never pending on non-Windows targets (PE patching is a no-op).
#[cfg(not(windows))]
#[must_use]
pub fn is_pending(_install_dir: &Path, _branding: &Branding) -> bool {
    false
}

/// Applies `branding` to the browser install at `install_dir`, unless the
/// current branding fingerprint already matches the marker.
///
/// Branding is purely cosmetic, so any failure is logged and swallowed — the
/// browser still launches, just with its stock icon. The marker (recording the
/// new fingerprint) is written only when every target file is patched
/// successfully, so a partial failure is retried on the next launch.
/// The boolean result lets staged-update callers treat an incomplete overlay
/// as fatal before the atomic swap, while launch-time callers may continue
/// with stock branding and retry on the next run.
#[cfg(windows)]
#[must_use]
pub fn ensure_branding(install_dir: &Path, branding: &Branding) -> bool {
    if !is_pending(install_dir, branding) {
        return true;
    }

    let mut all_ok = true;
    for file in branding.targets {
        let path = install_dir.join(file);
        if !path.exists() {
            tracing::warn!(file = %file, "branding target not found; skipping");
            all_ok = false;
            continue;
        }
        if !is_writable(&path) {
            tracing::warn!(
                file = %file,
                "branding target is locked; skipping (is the browser running?)"
            );
            all_ok = false;
            continue;
        }
        match patch_pe_icons(&path, branding.icons) {
            Ok(()) => tracing::info!(file = %file, "branding icons applied"),
            Err(e) => {
                all_ok = false;
                tracing::warn!(file = %file, error = %e, "branding patch failed");
            }
        }
    }

    if !branding.pak_patches.is_empty() && !apply_pak_patches(install_dir, branding.pak_patches) {
        all_ok = false;
    }

    if !all_ok {
        return false;
    }
    let marker = install_dir.join(MARKER);
    let fingerprint = branding_fingerprint(install_dir, branding);
    if let Err(e) = std::fs::write(&marker, fingerprint) {
        tracing::warn!(error = %e, "could not write branding marker");
        return false;
    }
    true
}

/// PE icon branding is a no-op on non-Windows targets.
#[cfg(not(windows))]
#[must_use]
pub fn ensure_branding(_install_dir: &Path, _branding: &Branding) -> bool {
    tracing::debug!("PE icon branding is supported only on Windows");
    true
}

/// Computes a fingerprint of the current branding state: a SHA-256 digest over
/// the embedded branding icons plus the on-disk size of each target PE file.
///
/// Recorded in the `.branding-patched` marker. The digest changes when the
/// launcher ships new branding icons, and the target sizes change when a
/// browser update replaces the binaries — both cases that require re-patching.
#[cfg(any(windows, test))]
fn branding_fingerprint(install_dir: &Path, branding: &Branding) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for icon in branding.icons {
        hasher.update((icon.ico.len() as u64).to_le_bytes());
        hasher.update(icon.ico);
    }
    for file in branding.targets {
        let size = std::fs::metadata(install_dir.join(file)).map_or(0, |m| m.len());
        hasher.update(file.as_bytes());
        hasher.update(size.to_le_bytes());
    }
    for patch in branding.pak_patches {
        hasher.update(patch.pak_file.as_bytes());
        hasher.update(patch.resource_id.to_le_bytes());
        hasher.update(patch.expected_png_bytes);
        hasher.update((patch.png_bytes.len() as u64).to_le_bytes());
        hasher.update(patch.png_bytes);
        let size = std::fs::metadata(install_dir.join(patch.pak_file)).map_or(0, |m| m.len());
        hasher.update(size.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

// ── ICO parsing (shared by the Windows patcher and unit tests) ───────────────

/// One frame of a parsed `.ico` file.
#[cfg(any(windows, test))]
struct IcoFrame {
    /// Width in pixels (`0` encodes 256).
    width: u8,
    /// Height in pixels (`0` encodes 256).
    height: u8,
    /// Palette colour count (`0` for ≥ 8 bpp).
    color_count: u8,
    /// Colour planes.
    planes: u16,
    /// Bits per pixel.
    bit_count: u16,
    /// Raw encoded frame bytes (BMP/DIB or PNG) — exactly the payload an
    /// `RT_ICON` resource stores.
    data: Vec<u8>,
}

/// Parses a `.ico` file into its frames, or `None` if the data is malformed.
#[cfg(any(windows, test))]
fn parse_ico(bytes: &[u8]) -> Option<Vec<IcoFrame>> {
    // ICONDIR header: idReserved(2) idType(2) idCount(2).
    if bytes.len() < 6 {
        return None;
    }
    let count = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    let mut frames = Vec::with_capacity(count);

    for i in 0..count {
        // ICONDIRENTRY records are 16 bytes each, starting at offset 6.
        let e = 6 + i * 16;
        if e + 16 > bytes.len() {
            return None;
        }
        let size =
            u32::from_le_bytes([bytes[e + 8], bytes[e + 9], bytes[e + 10], bytes[e + 11]]) as usize;
        let off = u32::from_le_bytes([bytes[e + 12], bytes[e + 13], bytes[e + 14], bytes[e + 15]])
            as usize;
        let end = off.checked_add(size)?;
        if end > bytes.len() {
            return None;
        }
        frames.push(IcoFrame {
            width: bytes[e],
            height: bytes[e + 1],
            color_count: bytes[e + 2],
            planes: u16::from_le_bytes([bytes[e + 4], bytes[e + 5]]),
            bit_count: u16::from_le_bytes([bytes[e + 6], bytes[e + 7]]),
            data: bytes[off..end].to_vec(),
        });
    }

    if frames.is_empty() {
        None
    } else {
        Some(frames)
    }
}

/// Builds a `GRPICONDIR` blob — the payload of an `RT_GROUP_ICON` resource —
/// referencing `RT_ICON` resources with IDs `first_id, first_id + 1, …`.
#[cfg(any(windows, test))]
fn build_group_icon(frames: &[IcoFrame], first_id: u16) -> Vec<u8> {
    let count = u16::try_from(frames.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(6 + frames.len() * 14);
    out.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    out.extend_from_slice(&1u16.to_le_bytes()); // idType = 1 (icon)
    out.extend_from_slice(&count.to_le_bytes()); // idCount

    // Each GRPICONDIRENTRY is 14 bytes: like an ICONDIRENTRY but with a 2-byte
    // resource ID in place of the 4-byte file offset.
    let mut id = first_id;
    for f in frames {
        let bytes_in_res = u32::try_from(f.data.len()).unwrap_or(u32::MAX);
        out.push(f.width);
        out.push(f.height);
        out.push(f.color_count);
        out.push(0); // bReserved
        out.extend_from_slice(&f.planes.to_le_bytes());
        out.extend_from_slice(&f.bit_count.to_le_bytes());
        out.extend_from_slice(&bytes_in_res.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
        id = id.saturating_add(1);
    }
    out
}

// ── Windows PE resource patching ─────────────────────────────────────────────

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE};
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::{
    BeginUpdateResourceW, EndUpdateResourceW, FindResourceExW, FindResourceW, LoadLibraryExW,
    LoadResource, LockResource, SizeofResource, UpdateResourceW,
    LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE, LOAD_LIBRARY_AS_IMAGE_RESOURCE,
};

/// `RT_ICON` resource type.
#[cfg(windows)]
const RT_ICON: u16 = 3;
/// `RT_GROUP_ICON` resource type.
#[cfg(windows)]
const RT_GROUP_ICON: u16 = 14;
/// `LANG_ENGLISH` / `SUBLANG_ENGLISH_US` — the language Chromium's icon
/// resources live under.
#[cfg(windows)]
const LANG_EN_US: u16 = 0x0409;
/// First `RT_ICON` ID assigned to the first group's frames.
#[cfg(windows)]
const ICON_ID_BASE: u16 = 5000;
/// ID spacing between successive icon groups (each group has < 100 frames).
#[cfg(windows)]
const ICON_ID_STRIDE: u16 = 100;

/// Failure from a PE resource-update operation.
#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
enum BrandingError {
    /// `BeginUpdateResourceW` failed (file missing, read-only, or locked).
    #[error("BeginUpdateResource failed (OS error {0})")]
    BeginUpdate(u32),
    /// `UpdateResourceW` failed for one resource.
    #[error("UpdateResource failed (OS error {0})")]
    UpdateResource(u32),
    /// `EndUpdateResourceW` failed while committing.
    #[error("EndUpdateResource failed (OS error {0})")]
    EndUpdate(u32),
    /// An embedded `.ico` could not be parsed.
    #[error("malformed .ico data")]
    BadIco,
    #[error("PE resource read failed: {0}")]
    ResourceRead(String),
    #[error("PE icon readback did not match the required overlay")]
    ResourceMismatch,
}

/// A resource-only mapping: no entry point, imports, or browser code is run.
#[cfg(windows)]
struct ResourceModule(HMODULE);

#[cfg(windows)]
impl Drop for ResourceModule {
    fn drop(&mut self) {
        // SAFETY: this handle is owned and came from LoadLibraryExW below.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

#[cfg(windows)]
fn read_pe_resource(
    path: &Path,
    resource_type: u16,
    name: &ResName<'_>,
    exact_language: bool,
) -> Result<Vec<u8>, BrandingError> {
    let path = path
        .canonicalize()
        .map_err(|e| BrandingError::ResourceRead(e.to_string()))?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: absolute NUL-terminated path; DATAFILE/IMAGE_RESOURCE explicitly
    // map bytes without executing code, resolving imports, or calling DllMain.
    let handle = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
    };
    if handle.is_null() {
        return Err(BrandingError::ResourceRead(last_error().to_string()));
    }
    let module = ResourceModule(handle);
    let named: Vec<u16>;
    let name_ptr = match name {
        ResName::Id(id) => usize::from(*id) as *const u16,
        ResName::Named(value) => {
            named = value.encode_utf16().chain(Some(0)).collect();
            named.as_ptr()
        }
    };
    let type_ptr = usize::from(resource_type) as *const u16;
    // SAFETY: module is a live resource mapping and names use the Win32
    // integer-resource convention or a live NUL-terminated string.
    let resource = unsafe {
        if exact_language {
            FindResourceExW(module.0, type_ptr, name_ptr, LANG_EN_US)
        } else {
            FindResourceW(module.0, name_ptr, type_ptr)
        }
    };
    if resource.is_null() {
        return Err(BrandingError::ResourceRead(last_error().to_string()));
    }
    // SAFETY: the resource belongs to this live mapping. Data is copied before
    // the mapping is released, and the length is supplied by the Windows loader.
    unsafe {
        let size = SizeofResource(module.0, resource) as usize;
        let data = LockResource(LoadResource(module.0, resource));
        if data.is_null() || size == 0 {
            return Err(BrandingError::ResourceRead(last_error().to_string()));
        }
        Ok(std::slice::from_raw_parts(data.cast::<u8>(), size).to_vec())
    }
}

/// Returns the calling thread's last Win32 error code.
#[cfg(windows)]
fn last_error() -> u32 {
    // SAFETY: `GetLastError` has no preconditions.
    unsafe { GetLastError() }
}

/// A resource name: either a numeric ID or a named string.
#[cfg(windows)]
enum ResName<'a> {
    /// Numeric resource identifier.
    Id(u16),
    /// Named resource.
    Named(&'a str),
}

/// Returns `true` if `path` can be opened for writing — i.e. it is not locked
/// by a running process such as the browser itself.
///
/// `BeginUpdateResourceW` would fail on a locked file anyway; this pre-check
/// lets [`ensure_branding`] skip cleanly (and retry next launch) instead of
/// surfacing a confusing mid-patch error.
#[cfg(windows)]
fn is_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .is_ok()
}

/// Replaces every icon group in `icons` inside the PE file at `path`.
///
/// Existing resources other than the patched icon groups (version info,
/// manifest, string tables, …) are preserved.
#[cfg(windows)]
fn patch_pe_icons(path: &Path, icons: &[BrandingIcon]) -> Result<(), BrandingError> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 string. The `0`
    // (FALSE) keeps the file's existing resources rather than wiping them.
    let handle = unsafe { BeginUpdateResourceW(wide_path.as_ptr(), 0) };
    if handle.is_null() {
        return Err(BrandingError::BeginUpdate(last_error()));
    }

    let patch_result = patch_groups(handle, icons);

    // Commit on success, discard the staged changes on failure.
    let discard = i32::from(patch_result.is_err());
    // SAFETY: `handle` is the value returned by `BeginUpdateResourceW`.
    let end_ok = unsafe { EndUpdateResourceW(handle, discard) };

    patch_result?;
    if end_ok == 0 {
        return Err(BrandingError::EndUpdate(last_error()));
    }
    verify_pe_icons(path, icons)?;
    Ok(())
}

#[cfg(windows)]
fn verify_pe_icons(path: &Path, icons: &[BrandingIcon]) -> Result<(), BrandingError> {
    let mut first_id = ICON_ID_BASE;
    for icon in icons {
        let frames = parse_ico(icon.ico).ok_or(BrandingError::BadIco)?;
        let name = match icon.group {
            BrandingGroup::Id(id) => ResName::Id(id),
            BrandingGroup::Named(value) => ResName::Named(value),
        };
        if read_pe_resource(path, RT_GROUP_ICON, &name, true)?
            != build_group_icon(&frames, first_id)
        {
            return Err(BrandingError::ResourceMismatch);
        }
        let mut id = first_id;
        for frame in frames {
            if read_pe_resource(path, RT_ICON, &ResName::Id(id), true)? != frame.data {
                return Err(BrandingError::ResourceMismatch);
            }
            id += 1;
        }
        first_id += ICON_ID_STRIDE;
    }
    Ok(())
}

/// Stages every icon group into an open `BeginUpdateResource` handle.
#[cfg(windows)]
fn patch_groups(handle: HANDLE, icons: &[BrandingIcon]) -> Result<(), BrandingError> {
    let mut first_id: u16 = ICON_ID_BASE;

    for icon in icons {
        let frames = parse_ico(icon.ico).ok_or(BrandingError::BadIco)?;

        // Each frame becomes an individual RT_ICON resource.
        let mut icon_id = first_id;
        for frame in &frames {
            update_resource(handle, RT_ICON, &ResName::Id(icon_id), &frame.data)?;
            icon_id = icon_id.saturating_add(1);
        }

        // The GRPICONDIR referencing those frames becomes the RT_GROUP_ICON.
        let group = build_group_icon(&frames, first_id);
        let name = match icon.group {
            BrandingGroup::Id(id) => ResName::Id(id),
            BrandingGroup::Named(s) => ResName::Named(s),
        };
        update_resource(handle, RT_GROUP_ICON, &name, &group)?;

        first_id = first_id.saturating_add(ICON_ID_STRIDE);
    }
    Ok(())
}

/// Stages a single resource (`UpdateResourceW`) into an open update handle.
#[cfg(windows)]
fn update_resource(
    handle: HANDLE,
    res_type: u16,
    name: &ResName,
    data: &[u8],
) -> Result<(), BrandingError> {
    // Integer resource identifiers are passed as pointers whose numeric value
    // *is* the identifier (the MAKEINTRESOURCE convention).
    let type_ptr = res_type as usize as *const u16;

    let wide_name: Vec<u16>;
    let name_ptr = match *name {
        ResName::Id(id) => id as usize as *const u16,
        ResName::Named(s) => {
            wide_name = s.encode_utf16().chain(std::iter::once(0)).collect();
            wide_name.as_ptr()
        }
    };

    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    // SAFETY: `handle` came from `BeginUpdateResourceW`; `type_ptr`/`name_ptr`
    // follow the MAKEINTRESOURCE / NUL-terminated-wide-string contract; `data`
    // is valid for `len` bytes.
    let ok = unsafe {
        UpdateResourceW(
            handle,
            type_ptr,
            name_ptr,
            LANG_EN_US,
            data.as_ptr().cast(),
            len,
        )
    };
    if ok == 0 {
        return Err(BrandingError::UpdateResource(last_error()));
    }
    Ok(())
}

// ── Chromium PAK file patching ────────────────────────────────────────────────

/// Failure from a PAK resource-replacement operation.
#[derive(Debug, thiserror::Error)]
enum PakError {
    #[error("file too short to be a valid PAK")]
    TooShort,
    #[error("unsupported PAK version {0}; only version 5 is supported")]
    UnsupportedVersion(u32),
    #[error("resource offset out of bounds in PAK")]
    InvalidOffset,
    #[error("invalid PAK resource or alias table")]
    InvalidTable,
    #[error("PAK file too large for 32-bit offset field")]
    OffsetOverflow,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Width and height read from a PNG's IHDR header, or `None` if `bytes` is not
/// a PNG. Only the 8-byte signature + IHDR dimensions are inspected.
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes[12..16] != *b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    Some((w, h))
}

/// `true` when `existing` and `replacement` are both PNGs of identical
/// dimensions — the guard that a PAK resource ID still points at the logo we
/// expect before overwriting it. grit can renumber resource IDs between
/// Chromium versions, so a blind replace could clobber the wrong resource.
fn png_dims_match(existing: &[u8], replacement: &[u8]) -> bool {
    matches!(
        (png_dimensions(existing), png_dimensions(replacement)),
        (Some(a), Some(b)) if a == b
    )
}

/// Decode only small logo-sized PNGs, with a bounded decoder allocation.
/// Compare pixels rather than compressed bytes so PNG recompression is harmless.
fn logo_pixels(bytes: &[u8]) -> Option<Vec<u8>> {
    let (width, height) = png_dimensions(bytes)?;
    if width == 0 || height == 0 || width > 64 || height > 64 || bytes.len() > 256 * 1024 {
        return None;
    }
    let mut decoder = png::Decoder::new(bytes);
    decoder.set_limits(png::Limits { bytes: 1024 * 1024 });
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buffer).ok()?;
    let samples = &buffer[..info.buffer_size()];
    let pixels = match info.color_type {
        png::ColorType::Rgba => samples.to_vec(),
        png::ColorType::Rgb => samples
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        png::ColorType::Grayscale => samples.iter().flat_map(|&p| [p, p, p, 255]).collect(),
        png::ColorType::GrayscaleAlpha => samples
            .chunks_exact(2)
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        png::ColorType::Indexed => return None,
    };
    Some(pixels)
}

/// Resolve every required logo before mutating any resource. Neither a matching
/// grit ID nor matching dimensions alone proves that an image is our logo.
fn apply_logo_patches(resources: &mut [(u16, Vec<u8>)], patches: &[&PakPatch]) -> bool {
    let mut resolved = Vec::new();
    for patch in patches {
        let Some(expected) = logo_pixels(patch.expected_png_bytes) else {
            return false;
        };
        let Some(replacement) = logo_pixels(patch.png_bytes) else {
            return false;
        };
        if !png_dims_match(patch.expected_png_bytes, patch.png_bytes) {
            return false;
        }
        let matches: Vec<u16> = resources
            .iter()
            .filter(|(_, data)| png_dims_match(data, patch.expected_png_bytes))
            .filter(|(_, data)| {
                logo_pixels(data).is_some_and(|pixels| pixels == expected || pixels == replacement)
            })
            .map(|(id, _)| *id)
            .collect();
        if matches.len() != 1 || resolved.iter().any(|(id, _)| *id == matches[0]) {
            tracing::warn!(
                file = patch.pak_file,
                matches = matches.len(),
                "required Chromium logo is missing or ambiguous; refusing overlay"
            );
            return false;
        }
        resolved.push((matches[0], patch.png_bytes));
    }
    apply_resource_patches(resources, &resolved)
}

/// Overwrites the resources named in `patches`. For image (PNG) replacements —
/// the logo patches — a resource is only overwritten when its current bytes are
/// a PNG of the same dimensions, so a grit-renumbered ID (Chromium can renumber
/// resource IDs between versions) is skipped with a loud warning instead of
/// clobbering whatever now lives at that ID. Non-image replacements (only used
/// by the low-level offset tests) are written unconditionally.
fn apply_resource_patches(resources: &mut [(u16, Vec<u8>)], patches: &[(u16, &[u8])]) -> bool {
    let mut complete = true;
    for &(target_id, replacement) in patches {
        let Some((_, data)) = resources.iter_mut().find(|(id, _)| *id == target_id) else {
            tracing::warn!(
                resource_id = target_id,
                "PAK resource id not found (Chromium may have renumbered grit IDs); \
                 skipping logo patch"
            );
            complete = false;
            continue;
        };
        if png_dimensions(replacement).is_some() && !png_dims_match(data.as_slice(), replacement) {
            tracing::warn!(
                resource_id = target_id,
                "PAK resource is not the expected logo image (Chromium may have renumbered \
                 grit IDs); skipping to avoid clobbering the wrong resource"
            );
            complete = false;
            continue;
        }
        *data = replacement.to_vec();
    }
    complete
}

/// Parses a version-5 Chromium PAK, applies the supplied resource transformation,
/// and rebuilds all offsets while preserving alias indexes.
///
/// Version-5 layout (all little-endian):
/// ```text
/// [u32 version=5][u32 encoding][u16 resource_count][u16 alias_count]
/// [resource_count × (u16 id, u32 offset)]
/// [u16 0 sentinel][u32 end_offset]
/// [alias_count × (u16 alias_id, u16 canonical_entry_index)]
/// [resource data …]
/// ```
///
/// The callback reports whether all required resources were compatible.
fn rebuild_pak_with(
    bytes: &[u8],
    patch_resources: impl FnOnce(&mut [(u16, Vec<u8>)]) -> bool,
) -> Result<(Vec<u8>, bool), PakError> {
    if bytes.len() < 12 {
        return Err(PakError::TooShort);
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if version != 5 {
        return Err(PakError::UnsupportedVersion(version));
    }
    let encoding = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let resource_count = usize::from(u16::from_le_bytes([bytes[8], bytes[9]]));
    let alias_count = usize::from(u16::from_le_bytes([bytes[10], bytes[11]]));

    let entries_end = 12 + resource_count * 6;
    let end_offset_pos = entries_end + 2; // skip u16 sentinel
    let alias_start = end_offset_pos + 4;
    let alias_end = alias_start + alias_count * 4;
    if bytes.len() < alias_end {
        return Err(PakError::TooShort);
    }

    let end_offset = usize::try_from(u32::from_le_bytes([
        bytes[end_offset_pos],
        bytes[end_offset_pos + 1],
        bytes[end_offset_pos + 2],
        bytes[end_offset_pos + 3],
    ]))
    .unwrap_or(usize::MAX);
    let alias_bytes = bytes[alias_start..alias_end].to_vec();
    if end_offset < alias_end || end_offset > bytes.len() {
        return Err(PakError::InvalidOffset);
    }
    for alias in alias_bytes.chunks_exact(4) {
        if usize::from(u16::from_le_bytes([alias[2], alias[3]])) >= resource_count {
            return Err(PakError::InvalidTable);
        }
    }

    // Parse entries.
    let mut entries: Vec<(u16, usize)> = Vec::with_capacity(resource_count);
    for i in 0..resource_count {
        let p = 12 + i * 6;
        let id = u16::from_le_bytes([bytes[p], bytes[p + 1]]);
        let off = usize::try_from(u32::from_le_bytes([
            bytes[p + 2],
            bytes[p + 3],
            bytes[p + 4],
            bytes[p + 5],
        ]))
        .unwrap_or(usize::MAX);
        if id == 0 || entries.last().is_some_and(|&(previous, _)| previous >= id) {
            return Err(PakError::InvalidTable);
        }
        entries.push((id, off));
    }

    // Extract resource data.
    let mut resources: Vec<(u16, Vec<u8>)> = Vec::with_capacity(resource_count);
    for i in 0..entries.len() {
        let (id, off) = entries[i];
        let next = if i + 1 < entries.len() {
            entries[i + 1].1
        } else {
            end_offset
        };
        if off < alias_end || off > bytes.len() || next > bytes.len() || off > next {
            return Err(PakError::InvalidOffset);
        }
        resources.push((id, bytes[off..next].to_vec()));
    }

    let complete = patch_resources(&mut resources);

    Ok((encode_pak(encoding, &alias_bytes, &resources)?, complete))
}

fn encode_pak(
    encoding: u32,
    alias_bytes: &[u8],
    resources: &[(u16, Vec<u8>)],
) -> Result<Vec<u8>, PakError> {
    let resource_count = resources.len();
    let alias_count = alias_bytes.len() / 4;

    // Compute new offsets.
    // Layout: header(12) + entries(n×6) + sentinel(2) + end_offset(4) + aliases + data
    let new_data_start = 12 + resource_count * 6 + 6 + alias_count * 4;
    let mut new_offsets: Vec<usize> = Vec::with_capacity(resource_count);
    let mut cursor = new_data_start;
    for (_, data) in resources {
        new_offsets.push(cursor);
        cursor += data.len();
    }
    let new_end_offset = cursor;

    // Build output.
    let mut out = Vec::with_capacity(new_end_offset);
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&encoding.to_le_bytes());
    out.extend_from_slice(
        &u16::try_from(resource_count)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&u16::try_from(alias_count).unwrap_or(u16::MAX).to_le_bytes());
    for (i, &(id, _)) in resources.iter().enumerate() {
        out.extend_from_slice(&id.to_le_bytes());
        let off32 = u32::try_from(new_offsets[i]).map_err(|_| PakError::OffsetOverflow)?;
        out.extend_from_slice(&off32.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes()); // sentinel
    let end32 = u32::try_from(new_end_offset).map_err(|_| PakError::OffsetOverflow)?;
    out.extend_from_slice(&end32.to_le_bytes());
    out.extend_from_slice(alias_bytes);
    for (_, data) in &resources {
        out.extend_from_slice(data);
    }
    Ok(out)
}

#[cfg(test)]
fn rebuild_pak(bytes: &[u8], patches: &[(u16, &[u8])]) -> Result<(Vec<u8>, bool), PakError> {
    rebuild_pak_with(bytes, |resources| {
        apply_resource_patches(resources, patches)
    })
}

/// Applies all `pak_patches` whose `pak_file` lives under `install_dir`.
/// Returns `true` if every patch succeeded.
#[cfg(windows)]
fn apply_pak_patches(install_dir: &Path, patches: &[PakPatch]) -> bool {
    let mut all_ok = true;
    let mut done: Vec<&str> = Vec::new();
    for patch in patches {
        if done.contains(&patch.pak_file) {
            continue;
        }
        done.push(patch.pak_file);
        let file_patches: Vec<&PakPatch> = patches
            .iter()
            .filter(|p| p.pak_file == patch.pak_file)
            .collect();
        let path = install_dir.join(patch.pak_file);
        if !path.exists() {
            tracing::warn!(file = %patch.pak_file, "PAK file not found; skipping logo patch");
            all_ok = false;
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(file = %patch.pak_file, error = %e, "could not read PAK for patching");
                all_ok = false;
                continue;
            }
        };
        match rebuild_pak_with(&data, |resources| {
            apply_logo_patches(resources, &file_patches)
        }) {
            Ok((new_pak, complete)) => {
                if !complete {
                    // A success marker must mean every required resource was
                    // patched. Leave it absent so a compatible launcher can retry.
                    all_ok = false;
                    continue;
                }
                // Atomic write: temp file beside the target, then rename.
                // A plain overwrite truncates first; power-loss mid-write on
                // USB leaves a corrupt PAK that never self-heals (the branding
                // marker is only written after a clean swap).
                let mut tmp_os = path.as_os_str().to_owned();
                tmp_os.push(".tmp");
                let tmp_path = std::path::PathBuf::from(tmp_os);
                match std::fs::write(&tmp_path, &new_pak)
                    .and_then(|()| std::fs::rename(&tmp_path, &path))
                {
                    Ok(()) => {
                        if std::fs::read(&path).is_ok_and(|written| written == new_pak) {
                            tracing::info!(file = %patch.pak_file, "PAK logo patched and verified");
                        } else {
                            all_ok = false;
                            tracing::warn!(file = %patch.pak_file, "PAK readback did not match");
                        }
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        tracing::warn!(file = %patch.pak_file, error = %e, "could not write patched PAK");
                        all_ok = false;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(file = %patch.pak_file, error = %e, "PAK rebuild failed");
                all_ok = false;
            }
        }
    }
    all_ok
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{branding_fingerprint, build_group_icon, parse_ico, rebuild_pak};
    use super::{Branding, BrandingGroup, BrandingIcon, PakError};

    /// Builds a minimal valid 1-frame `.ico` (1×2 px, 32 bpp, 4 dummy bytes).
    fn tiny_ico() -> Vec<u8> {
        let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let mut v = Vec::new();
        v.extend_from_slice(&0u16.to_le_bytes()); // idReserved
        v.extend_from_slice(&1u16.to_le_bytes()); // idType = icon
        v.extend_from_slice(&1u16.to_le_bytes()); // idCount
                                                  // ICONDIRENTRY (16 bytes)
        v.push(1); // width
        v.push(2); // height
        v.push(0); // colour count
        v.push(0); // reserved
        v.extend_from_slice(&1u16.to_le_bytes()); // planes
        v.extend_from_slice(&32u16.to_le_bytes()); // bit count
        v.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes()); // bytes in res
        v.extend_from_slice(&22u32.to_le_bytes()); // image offset (6 + 16)
        v.extend_from_slice(&data); // image data
        v
    }

    #[test]
    fn parse_ico_reads_a_frame() {
        let frames = parse_ico(&tiny_ico()).expect("valid ico");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].width, 1);
        assert_eq!(frames[0].height, 2);
        assert_eq!(frames[0].bit_count, 32);
        assert_eq!(frames[0].data, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_ico_rejects_malformed_input() {
        assert!(parse_ico(&[]).is_none());
        assert!(parse_ico(&[0, 0, 1, 0]).is_none()); // header truncated
                                                     // Declares one entry but the directory is cut short.
        assert!(parse_ico(&[0, 0, 1, 0, 1, 0, 1, 2, 3]).is_none());
    }

    #[test]
    fn build_group_icon_emits_header_and_entry() {
        let frames = parse_ico(&tiny_ico()).unwrap();
        let grp = build_group_icon(&frames, 5000);
        // 6-byte GRPICONDIR header + one 14-byte GRPICONDIRENTRY.
        assert_eq!(grp.len(), 20);
        assert_eq!(u16::from_le_bytes([grp[0], grp[1]]), 0); // reserved
        assert_eq!(u16::from_le_bytes([grp[2], grp[3]]), 1); // type = icon
        assert_eq!(u16::from_le_bytes([grp[4], grp[5]]), 1); // count
                                                             // The entry's trailing 2 bytes are the assigned RT_ICON resource ID.
        assert_eq!(u16::from_le_bytes([grp[18], grp[19]]), 5000);
    }

    // ── PAK patching tests ────────────────────────────────────────────────────

    /// Builds a minimal valid version-5 PAK from `(id, data)` pairs.
    fn make_pak_v5(resources: &[(u16, &[u8])]) -> Vec<u8> {
        let rc = resources.len();
        let data_start = 12 + rc * 6 + 6; // header + entries + sentinel + end_offset (no aliases)
        let mut offsets: Vec<usize> = Vec::new();
        let mut cursor = data_start;
        for (_, d) in resources {
            offsets.push(cursor);
            cursor += d.len();
        }
        let end_off = cursor;
        let mut out = Vec::new();
        out.extend_from_slice(&5u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // encoding = utf-8
        out.extend_from_slice(&u16::try_from(rc).unwrap().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // alias_count = 0
        for (i, &(id, _)) in resources.iter().enumerate() {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&u32::try_from(offsets[i]).unwrap().to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes()); // sentinel
        out.extend_from_slice(&u32::try_from(end_off).unwrap().to_le_bytes());
        for (_, d) in resources {
            out.extend_from_slice(d);
        }
        out
    }

    /// Parse all (id, data) entries from a rebuilt PAK for assertions.
    fn parse_pak_resources(pak: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let rc = usize::from(u16::from_le_bytes([pak[8], pak[9]]));
        let ac = usize::from(u16::from_le_bytes([pak[10], pak[11]]));
        let end_off_pos = 12 + rc * 6 + 2;
        let end_off = u32::from_le_bytes([
            pak[end_off_pos],
            pak[end_off_pos + 1],
            pak[end_off_pos + 2],
            pak[end_off_pos + 3],
        ]) as usize;
        let mut entries = Vec::new();
        for i in 0..rc {
            let p = 12 + i * 6;
            let id = u16::from_le_bytes([pak[p], pak[p + 1]]);
            let off = u32::from_le_bytes([pak[p + 2], pak[p + 3], pak[p + 4], pak[p + 5]]) as usize;
            entries.push((id, off));
        }
        // alias table is ac * 4 bytes after end_off_pos + 4
        let data_base = end_off_pos + 4 + ac * 4;
        let _ = data_base; // offsets are absolute
        let mut result = Vec::new();
        for i in 0..entries.len() {
            let (id, off) = entries[i];
            let next = if i + 1 < entries.len() {
                entries[i + 1].1
            } else {
                end_off
            };
            result.push((id, pak[off..next].to_vec()));
        }
        result
    }

    #[test]
    fn pak_patch_replaces_target_resource() {
        let original = make_pak_v5(&[(100, b"hello"), (200, b"world"), (300, b"unchanged")]);
        let replacement = b"NEW_DATA";
        let (patched, complete) =
            rebuild_pak(&original, &[(200, replacement)]).expect("rebuild must succeed");
        assert!(complete);
        let resources = parse_pak_resources(&patched);
        assert_eq!(resources[0], (100, b"hello".to_vec()));
        assert_eq!(resources[1], (200, replacement.to_vec()));
        assert_eq!(resources[2], (300, b"unchanged".to_vec()));
    }

    #[test]
    fn pak_patch_updates_offsets_consistently() {
        let original = make_pak_v5(&[(10, b"aa"), (20, b"bbb"), (30, b"cccc")]);
        // Replace id=20 with something larger.
        let (patched, complete) =
            rebuild_pak(&original, &[(20, b"XXXXXXXXXX")]).expect("rebuild must succeed");
        assert!(complete);
        // All offsets in the rebuilt PAK must be self-consistent.
        let rc = usize::from(u16::from_le_bytes([patched[8], patched[9]]));
        let end_off_pos = 12 + rc * 6 + 2;
        let end_off = u32::from_le_bytes([
            patched[end_off_pos],
            patched[end_off_pos + 1],
            patched[end_off_pos + 2],
            patched[end_off_pos + 3],
        ]) as usize;
        assert_eq!(end_off, patched.len(), "end_offset must equal file length");
        let resources = parse_pak_resources(&patched);
        assert_eq!(resources[1].1, b"XXXXXXXXXX".to_vec());
        assert_eq!(resources[2].1, b"cccc".to_vec());
    }

    #[test]
    fn pak_patch_reports_unknown_id_as_incomplete() {
        let original = make_pak_v5(&[(10, b"data")]);
        // Patch targets an ID that doesn't exist — should be a no-op.
        let (patched, complete) =
            rebuild_pak(&original, &[(99, b"never")]).expect("rebuild must parse");
        assert!(
            !complete,
            "a missing resource must prevent the success marker"
        );
        let resources = parse_pak_resources(&patched);
        assert_eq!(resources[0], (10, b"data".to_vec()));
    }

    #[test]
    fn pak_patch_rejects_wrong_version() {
        let mut pak = make_pak_v5(&[(1, b"x")]);
        // Overwrite version to 4.
        pak[0] = 4;
        let err = rebuild_pak(&pak, &[]).expect_err("wrong version must fail");
        assert!(matches!(err, PakError::UnsupportedVersion(4)));
    }

    #[test]
    fn content_matching_survives_renumbering_and_png_reencoding() {
        let patch = &super::CHROMIUM.pak_patches[0];
        let pixels = super::logo_pixels(patch.expected_png_bytes).unwrap();
        let mut reencoded = Vec::new();
        let image = ico::IconImage::from_rgba_data(32, 32, pixels);
        image.write_png(&mut reencoded).unwrap();
        let original = make_pak_v5(&[(7, &reencoded), (14321, patch.png_bytes)]);
        // Even the historical ID cannot disambiguate two matching images.
        let (_, complete) = super::rebuild_pak_with(&original, |resources| {
            super::apply_logo_patches(resources, &[patch])
        })
        .unwrap();
        assert!(!complete);

        let original = make_pak_v5(&[(7, &reencoded), (14321, b"unrelated resource")]);
        let (patched, complete) = super::rebuild_pak_with(&original, |resources| {
            super::apply_logo_patches(resources, &[patch])
        })
        .unwrap();
        assert!(complete);
        let resources = parse_pak_resources(&patched);
        assert_eq!(resources[0].1, patch.png_bytes);
        assert_eq!(resources[1].1, b"unrelated resource");
        let (again, complete) = super::rebuild_pak_with(&patched, |resources| {
            super::apply_logo_patches(resources, &[patch])
        })
        .unwrap();
        assert!(complete);
        assert_eq!(again, patched, "branding must remain idempotent");
    }

    #[test]
    fn all_embedded_logos_decode_and_match_their_replacement_dimensions() {
        for patch in super::CHROMIUM.pak_patches {
            assert!(super::logo_pixels(patch.expected_png_bytes).is_some());
            assert!(super::logo_pixels(patch.png_bytes).is_some());
            assert!(super::png_dims_match(
                patch.expected_png_bytes,
                patch.png_bytes
            ));
        }
    }

    #[test]
    fn content_matching_rejects_wrong_image_at_the_right_id_without_partial_changes() {
        let patches: Vec<_> = super::CHROMIUM
            .pak_patches
            .iter()
            .filter(|p| p.pak_file == "chrome_100_percent.pak")
            .collect();
        let mut wrong_png = Vec::new();
        ico::IconImage::from_rgba_data(16, 16, vec![255; 16 * 16 * 4])
            .write_png(&mut wrong_png)
            .unwrap();
        let original = make_pak_v5(&[(14321, patches[0].expected_png_bytes), (14323, &wrong_png)]);
        let (unchanged, complete) = super::rebuild_pak_with(&original, |resources| {
            super::apply_logo_patches(resources, &patches)
        })
        .unwrap();
        assert!(!complete);
        assert_eq!(unchanged, original);
    }

    #[test]
    fn content_matching_rejects_missing_and_malformed_logos() {
        let patch = &super::CHROMIUM.pak_patches[0];
        for bytes in [b"not a PNG".as_slice(), &patch.expected_png_bytes[..24]] {
            let original = make_pak_v5(&[(14321, bytes)]);
            let (_, complete) = super::rebuild_pak_with(&original, |resources| {
                super::apply_logo_patches(resources, &[patch])
            })
            .unwrap();
            assert!(!complete);
        }
    }

    #[test]
    fn pak_parser_rejects_duplicate_ids_and_offsets_into_the_table() {
        let duplicate = make_pak_v5(&[(1, b"one"), (1, b"two")]);
        assert!(rebuild_pak(&duplicate, &[]).is_err());
        let mut invalid_offset = make_pak_v5(&[(1, b"one")]);
        invalid_offset[14..18].copy_from_slice(&0u32.to_le_bytes());
        assert!(rebuild_pak(&invalid_offset, &[]).is_err());
    }

    #[test]
    fn content_patch_preserves_aliases_and_rejects_invalid_alias_indexes() {
        let patch = &super::CHROMIUM.pak_patches[0];
        let mut pak = make_pak_v5(&[(7, patch.expected_png_bytes)]);
        pak[10..12].copy_from_slice(&1u16.to_le_bytes());
        for offset in [14, 20] {
            let old = u32::from_le_bytes(pak[offset..offset + 4].try_into().unwrap());
            pak[offset..offset + 4].copy_from_slice(&(old + 4).to_le_bytes());
        }
        pak.splice(24..24, [8, 0, 0, 0]); // id 8 aliases canonical entry index 0
        let (patched, complete) = super::rebuild_pak_with(&pak, |resources| {
            super::apply_logo_patches(resources, &[patch])
        })
        .unwrap();
        assert!(complete);
        assert_eq!(&patched[24..28], &[8, 0, 0, 0]);
        assert_eq!(parse_pak_resources(&patched)[0].1, patch.png_bytes);
        pak[26] = 1; // only index 0 exists
        assert!(rebuild_pak(&pak, &[]).is_err());
    }

    #[test]
    fn chromium_layout_failure_never_creates_a_success_marker() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".branding-patched"),
            b"untrusted archive marker",
        )
        .unwrap();
        let error = super::validate_chromium_stage(dir.path()).unwrap_err();
        assert!(matches!(
            error,
            crate::browsers::BrowserError::Compatibility(_)
        ));
        assert!(!dir.path().join(".branding-patched").exists());
        assert!(!dir.path().join(".nomad-version").exists());
    }

    #[cfg(windows)]
    #[test]
    fn pe_overlay_readback_detects_missing_and_changed_icons_without_execution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.exe");
        std::fs::write(&path, include_bytes!("../payloads/7zip/7z.exe")).unwrap();
        assert!(super::read_pe_resource(
            &path,
            super::RT_GROUP_ICON,
            &super::ResName::Id(65530),
            true
        )
        .is_err());
        super::patch_pe_icons(&path, super::CHROMIUM.icons).unwrap();
        super::verify_pe_icons(&path, super::CHROMIUM.icons).unwrap();
        let wrong = BrandingIcon {
            group: BrandingGroup::Id(100),
            ico: super::CHROMIUM.icons[3].ico,
        };
        assert!(super::verify_pe_icons(&path, &[wrong]).is_err());
    }

    /// Builds the bytes `png_dimensions` inspects: the 8-byte signature + an
    /// IHDR carrying `w`×`h`, plus a `tag` so instances are distinguishable.
    /// Not a renderable PNG — just enough for the dimension guard.
    fn fake_png(w: u32, h: u32, tag: &[u8]) -> Vec<u8> {
        let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&13u32.to_be_bytes()); // IHDR length
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(tag);
        v
    }

    #[test]
    fn pak_patch_guards_against_renumbered_logo_ids() {
        // id=100 holds the 16×16 logo we expect; id=200 holds a 48×48 image,
        // simulating a renumbered ID that now points at a different resource.
        let logo = fake_png(16, 16, b"OLD");
        let other = fake_png(48, 48, b"OTHER");
        let original = make_pak_v5(&[(100, logo.as_slice()), (200, other.as_slice())]);

        // Patch both IDs with our 16×16 logo. id=100 matches dimensions → replaced;
        // id=200 mismatches → skipped by the guard, leaving the resource intact.
        let new_logo = fake_png(16, 16, b"NEWLOGO");
        let (patched, complete) = rebuild_pak(
            &original,
            &[(100, new_logo.as_slice()), (200, new_logo.as_slice())],
        )
        .expect("rebuild must succeed");
        assert!(!complete, "a mismatch must prevent the success marker");
        let res = parse_pak_resources(&patched);
        assert_eq!(
            &res.iter().find(|(id, _)| *id == 100).unwrap().1,
            &new_logo,
            "matching-dimension logo must be replaced"
        );
        assert_eq!(
            &res.iter().find(|(id, _)| *id == 200).unwrap().1,
            &other,
            "mismatched-dimension target must be skipped, not clobbered"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive_to_icon_changes() {
        let dir = std::path::Path::new("branding-fingerprint-test-dir");
        let a = Branding {
            targets: &[],
            icons: &[BrandingIcon {
                group: BrandingGroup::Id(100),
                ico: b"AAAA",
            }],
            pak_patches: &[],
        };
        let b = Branding {
            targets: &[],
            icons: &[BrandingIcon {
                group: BrandingGroup::Id(100),
                ico: b"BBBB",
            }],
            pak_patches: &[],
        };
        // Deterministic for identical input.
        assert_eq!(branding_fingerprint(dir, &a), branding_fingerprint(dir, &a));
        // Sensitive to a change in the embedded icon bytes.
        assert_ne!(branding_fingerprint(dir, &a), branding_fingerprint(dir, &b));
    }

    #[test]
    fn build_group_icon_numbers_frames_sequentially() {
        // Two frames → IDs first_id and first_id + 1.
        let one = tiny_ico();
        let frames = parse_ico(&one).unwrap();
        let mut two = frames;
        two.push(parse_ico(&one).unwrap().pop().unwrap());
        let grp = build_group_icon(&two, 5100);
        assert_eq!(grp.len(), 6 + 2 * 14);
        assert_eq!(u16::from_le_bytes([grp[18], grp[19]]), 5100);
        assert_eq!(u16::from_le_bytes([grp[32], grp[33]]), 5101);
    }

    #[cfg(windows)]
    #[test]
    fn missing_required_target_never_creates_success_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let branding = Branding {
            targets: &["missing.exe"],
            icons: &[],
            pak_patches: &[],
        };

        assert!(!super::ensure_branding(dir.path(), &branding));
        assert!(
            !dir.path().join(super::MARKER).exists(),
            "an incomplete overlay must remain retryable"
        );
    }
}
