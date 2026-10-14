//! Bounded Shell Link metadata corroboration for owned Recent shortcuts.
//! Unknown targets, flags, namespace providers and malformed records are kept.

use std::path::{Component, Path, PathBuf};

const MAX_LINK_BYTES: usize = 65_536;
const CLSID: &[u8] = &[1, 20, 2, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70];

struct FolderAnchor {
    guid: [u8; 16],
    offset: usize,
}

struct ParsedLink<'a> {
    paths: Vec<PathBuf>,
    relative: Option<String>,
    id_list: Option<&'a [u8]>,
    native_required: bool,
    anchor: Option<FolderAnchor>,
}

pub(crate) fn owned_target(bytes: &[u8], link_path: &Path, root: &Path) -> Option<PathBuf> {
    let parsed = parse(bytes)?;
    let mut target = None;
    // Reject any explicit foreign target before invoking the native decoder.
    // IDList-only links have no textual target until that decoder returns.
    corroborate_paths(&parsed.paths, root, &mut target)?;
    if parsed.native_required {
        let paths = native::stored_paths(bytes, parsed.id_list, parsed.anchor.as_ref())?;
        corroborate_paths(&paths, root, &mut target)?;
    }
    let target = target?;
    if let Some(relative) = parsed.relative {
        let relative = Path::new(&relative);
        if relative
            .components()
            .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        {
            return None;
        }
        if existing_owned_path(&link_path.parent()?.join(relative), root)? != target {
            return None;
        }
    }
    Some(target)
}

fn corroborate_paths(paths: &[PathBuf], root: &Path, target: &mut Option<PathBuf>) -> Option<()> {
    for path in paths {
        let current = existing_owned_path(path, root)?;
        if let Some(expected) = target.as_ref() {
            if current != *expected {
                return None;
            }
        } else {
            *target = Some(current);
        }
    }
    Some(())
}

/// Normalize only lexical dot components, not aliases. On Windows, accept
/// drive-absolute paths only: UNC/device/drive-relative names never get a lookup.
fn lexical_path(path: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut parts = path.components();
        if !matches!(parts.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
            || !matches!(parts.next(), Some(Component::RootDir))
        {
            return None;
        }
    }
    if !path.is_absolute() {
        return None;
    }
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            _ => result.push(part.as_os_str()),
        }
    }
    Some(result)
}

fn existing_owned_path(path: &Path, root: &Path) -> Option<PathBuf> {
    // canonicalize produces a verbatim drive prefix on Windows. Convert only
    // that trusted root to ordinary drive syntax for the lexical boundary check.
    #[cfg(windows)]
    let ordinary_root = PathBuf::from(
        root.to_str()?
            .strip_prefix(r"\\?\")
            .unwrap_or(root.to_str()?),
    );
    #[cfg(not(windows))]
    let ordinary_root = root.to_owned();
    let path = lexical_path(path)?;
    let path_parts: Vec<_> = path.components().collect();
    let root_parts: Vec<_> = ordinary_root.components().collect();
    if path_parts.len() <= root_parts.len()
        || !path_parts.iter().zip(&root_parts).all(|(a, b)| {
            #[cfg(windows)]
            {
                a.as_os_str()
                    .to_str()
                    .zip(b.as_os_str().to_str())
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            }
            #[cfg(not(windows))]
            {
                a == b
            }
        })
    {
        return None;
    }
    // Reject reparse points before canonicalize can follow one, including
    // target aliases. These metadata checks do not stop a hostile path writer.
    let mut current = PathBuf::new();
    for part in &path_parts {
        current.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current).ok()?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return None;
            }
        }
        #[cfg(not(windows))]
        if metadata.file_type().is_symlink() {
            return None;
        }
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    (canonical != root && canonical.starts_with(root)).then_some(canonical)
}

fn u16_at(bytes: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(pos..pos.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(bytes: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(pos..pos.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn offset(bytes: &[u8], pos: usize, header: usize) -> Option<usize> {
    let value = usize::try_from(u32_at(bytes, pos)?).ok()?;
    (value >= header && value < bytes.len()).then_some(value)
}
fn ansi_string(bytes: &[u8], pos: usize) -> Option<String> {
    let tail = bytes.get(pos..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    native::decode_ansi(&tail[..end])
}
fn unicode_string(bytes: &[u8], pos: usize) -> Option<String> {
    let mut chars = Vec::new();
    let mut cursor = pos;
    loop {
        let value = u16_at(bytes, cursor)?;
        if value == 0 {
            return String::from_utf16(&chars).ok();
        }
        chars.push(value);
        cursor = cursor.checked_add(2)?;
    }
}
fn counted_string(bytes: &[u8], cursor: &mut usize, unicode: bool) -> Option<String> {
    let count = usize::from(u16_at(bytes, *cursor)?);
    *cursor = cursor.checked_add(2)?;
    let end = cursor.checked_add(count.checked_mul(if unicode { 2 } else { 1 })?)?;
    let data = bytes.get(*cursor..end)?;
    *cursor = end;
    let text = if unicode {
        let chars: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&chars).ok()?
    } else {
        native::decode_ansi(data)?
    };
    (!text.contains('\0')).then_some(text)
}

/// Bound `ItemID` extents and termination, and restrict namespace types before
/// handing a copy to Windows. Unknown namespace providers are not consulted.
fn local_id_list(bytes: &[u8]) -> Option<()> {
    const COMPUTER: &[u8] = &[
        0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 8, 0, 0x2b, 0x30, 0x30, 0x9d,
    ];
    const USER_FILES: &[u8] = &[
        0x47, 0x1a, 3, 0x59, 0x72, 0x3f, 0xa7, 0x44, 0x89, 0xc5, 0x55, 0x95, 0xfe, 0x6b, 0x30, 0xee,
    ];
    let mut cursor: usize = 0;
    let mut count = 0;
    loop {
        let size = usize::from(u16_at(bytes, cursor)?);
        if size == 0 {
            return (count >= 2 && cursor.checked_add(2)? == bytes.len()).then_some(());
        }
        if size < 3 || count >= 256 {
            return None;
        }
        let end = cursor.checked_add(size)?;
        let item = bytes.get(cursor..end)?;
        if count == 0 {
            if item.get(2) != Some(&0x1f)
                || !matches!(item.get(4..20), Some(id) if id == COMPUTER || id == USER_FILES)
            {
                return None;
            }
        } else {
            match item[2] {
                0x2f if count == 1 => {
                    if !item.get(3)?.is_ascii_alphabetic()
                        || item.get(4..7) != Some(&[b':', b'\\', 0])
                    {
                        return None;
                    }
                }
                0x31 | 0x32 | 0x35 | 0x36 if size >= 16 => {}
                // Current Windows filesystem child of the UsersFiles namespace.
                0x74 if count == 1 && item.get(6..10) == Some(b"CFSF") => {}
                _ => return None,
            }
        }
        cursor = end;
        count += 1;
    }
}

/// Only ordinary built-in folder IDs are accepted; custom namespace mappings
/// and unsupported legacy-only translation records remain untouched.
fn known_folder_legacy(guid: &[u8]) -> Option<u32> {
    match guid {
        [0x85, 0x27, 0xb3, 0xf1, 0xba, 0x6f, 0xcf, 0x4f, 0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91] => {
            Some(28)
        } // LocalAppData
        [0xdb, 0x85, 0xb6, 0x3e, 0xf9, 0x65, 0xf6, 0x4c, 0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d] => {
            Some(26)
        } // RoamingAppData
        [0x8f, 0x85, 0x6c, 0x5e, 0x22, 0x0e, 0x60, 0x47, 0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73] => {
            Some(40)
        } // Profile
        [0x3a, 0xcc, 0xbf, 0xb4, 0x2c, 0xdb, 0x4c, 0x42, 0xb0, 0x29, 0x7f, 0xe9, 0x9a, 0x87, 0xc6, 0x41] => {
            Some(0)
        } // Desktop
        [0xd0, 0x9a, 0xd3, 0xfd, 0x8f, 0x23, 0xaf, 0x46, 0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7] => {
            Some(5)
        } // Documents
        // UsersFiles and Downloads have no legacy CSIDL equivalent.
        [0x7c, 0x0f, 0xce, 0xf3, 0x01, 0x49, 0xcc, 0x4a, 0x86, 0x48, 0xd5, 0xd4, 0x4b, 0x04, 0xef, 0x8f]
        | [0x90, 0xe2, 0x4d, 0x37, 0x3f, 0x12, 0x65, 0x45, 0x91, 0x64, 0x39, 0xc4, 0x92, 0x5e, 0x46, 0x7b] => {
            Some(u32::MAX)
        }
        _ => None,
    }
}

fn item_boundary(list: &[u8], offset: usize) -> bool {
    let mut cursor = 0;
    while cursor < offset {
        let Some(size) = u16_at(list, cursor) else {
            return false;
        };
        if size < 3 {
            return false;
        }
        let Some(end) = cursor.checked_add(usize::from(size)) else {
            return false;
        };
        if end > list.len().saturating_sub(2) {
            return false;
        }
        cursor = end;
    }
    offset > 0 && cursor == offset && offset <= list.len().saturating_sub(2)
}

fn local_info_paths(info: &[u8]) -> Option<Vec<PathBuf>> {
    let header = usize::try_from(u32_at(info, 4)?).ok()?;
    if !matches!(header, 28 | 36)
        || info.len() < header
        || u32_at(info, 8)? != 1
        || u32_at(info, 20)? != 0
    {
        return None;
    }
    let volume = offset(info, 12, header)?;
    let volume_size = usize::try_from(u32_at(info, volume)?).ok()?;
    if volume_size < 17 || volume.checked_add(volume_size)? > info.len() {
        return None;
    }
    let base = offset(info, 16, header)?;
    let suffix = offset(info, 24, header)?;
    if base < volume + volume_size || !ansi_string(info, suffix)?.is_empty() {
        return None;
    }
    let mut paths = vec![PathBuf::from(ansi_string(info, base)?)];
    if header == 36 {
        let unicode_base = offset(info, 28, header)?;
        let unicode_suffix = offset(info, 32, header)?;
        if unicode_base < volume + volume_size || !unicode_string(info, unicode_suffix)?.is_empty()
        {
            return None;
        }
        paths.push(PathBuf::from(unicode_string(info, unicode_base)?));
    }
    Some(paths)
}

fn parse(bytes: &[u8]) -> Option<ParsedLink<'_>> {
    if bytes.len() > MAX_LINK_BYTES || u32_at(bytes, 0)? != 76 || bytes.get(4..20) != Some(CLSID) {
        return None;
    }
    let flags = u32_at(bytes, 20)?;
    // StringData/IDList plus EnableTargetMetadata. Refuse target-changing flags.
    if (flags & 1 == 0 && flags & 2 == 0) || flags & !0x0008_00ff != 0 {
        return None;
    }
    let mut cursor: usize = 76;
    let id_list = if flags & 1 != 0 {
        let size = usize::from(u16_at(bytes, cursor)?);
        cursor += 2;
        let end = cursor.checked_add(size)?;
        let data = bytes.get(cursor..end)?;
        local_id_list(data)?;
        cursor = end;
        Some(data)
    } else {
        None
    };
    let paths = if flags & 2 != 0 {
        let end = cursor.checked_add(usize::try_from(u32_at(bytes, cursor)?).ok()?)?;
        let info = bytes.get(cursor..end)?;
        let paths = local_info_paths(info)?;
        cursor = end;
        paths
    } else {
        Vec::new()
    };
    let mut relative = None;
    for bit in [4, 8, 16, 32, 64] {
        if flags & bit != 0 {
            let text = counted_string(bytes, &mut cursor, flags & 128 != 0)?;
            if bit == 8 {
                if text.is_empty() {
                    return None;
                }
                relative = Some(text);
            }
        }
    }
    let mut signatures = Vec::new();
    let mut special_folder = None;
    let mut anchor = None;
    let mut terminated = false;
    while cursor < bytes.len() {
        let size = usize::try_from(u32_at(bytes, cursor)?).ok()?;
        if size == 0 {
            if cursor.checked_add(4)? != bytes.len() {
                return None;
            }
            terminated = true;
            break;
        }
        let end = cursor.checked_add(size)?;
        let block = bytes.get(cursor..end)?;
        let signature = u32_at(block, 4)?;
        if signatures.contains(&signature) {
            return None;
        }
        match signature {
            0xa000_0003 if size == 96 && u32_at(block, 8)? == 88 && u32_at(block, 12)? == 0 => {}
            0xa000_0005 if size == 16 => {
                let offset = usize::try_from(u32_at(block, 12)?).ok()?;
                if !item_boundary(id_list?, offset) {
                    return None;
                }
                special_folder = Some((u32_at(block, 8)?, offset));
            }
            0xa000_000b if size == 28 => {
                let guid: [u8; 16] = block.get(8..24)?.try_into().ok()?;
                known_folder_legacy(&guid)?;
                let offset = usize::try_from(u32_at(block, 24)?).ok()?;
                if !item_boundary(id_list?, offset) {
                    return None;
                }
                anchor = Some(FolderAnchor { guid, offset });
            }
            0xa000_0009 if size >= 12 => {}
            _ => return None,
        }
        signatures.push(signature);
        cursor = end;
    }
    if let Some((legacy, offset)) = special_folder {
        let known = anchor.as_ref()?;
        if offset != known.offset || Some(legacy) != known_folder_legacy(&known.guid) {
            return None;
        }
    }
    if !signatures.is_empty() && !terminated {
        return None;
    }
    Some(ParsedLink {
        paths,
        relative,
        id_list,
        native_required: id_list.is_some() || !signatures.is_empty(),
        anchor,
    })
}

#[cfg(not(windows))]
mod native {
    use super::{FolderAnchor, PathBuf};
    pub(super) fn decode_ansi(bytes: &[u8]) -> Option<String> {
        String::from_utf8(bytes.to_vec()).ok()
    }
    pub(super) fn stored_paths(
        _: &[u8],
        _: Option<&[u8]>,
        _: Option<&FolderAnchor>,
    ) -> Option<Vec<PathBuf>> {
        None
    }
}

#[cfg(windows)]
mod native {
    use super::{FolderAnchor, PathBuf};
    use std::ffi::c_void;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_ACP, MB_ERR_INVALID_CHARS};
    use windows_sys::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::UI::Shell::{
        Common::ITEMIDLIST, SHCreateMemStream, SHGetKnownFolderIDList, SHGetPathFromIDListEx,
        ShellLink, GPFIDL_DEFAULT, SLGP_RAWPATH,
    };
    #[repr(C)]
    struct Unknown {
        query: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
    }
    #[repr(C)]
    struct LinkVtable {
        unknown: Unknown,
        get_path: unsafe extern "system" fn(
            *mut c_void,
            *mut u16,
            i32,
            *mut WIN32_FIND_DATAW,
            i32,
        ) -> i32,
    }
    #[repr(C)]
    struct PersistVtable {
        unknown: Unknown,
        get_class_id: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
        is_dirty: unsafe extern "system" fn(*mut c_void) -> i32,
        load: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
    }
    struct ComObject(*mut c_void);
    impl ComObject {
        fn vtable<T>(&self) -> &T {
            // SAFETY: callers use the ABI prefix of the interface acquired for
            // this live COM object. Its vtable remains valid until Release.
            unsafe { &**self.0.cast::<*const T>() }
        }
    }
    impl Drop for ComObject {
        fn drop(&mut self) {
            // SAFETY: owns one successful creation/query reference.
            unsafe {
                (self.vtable::<Unknown>().release)(self.0);
            }
        }
    }
    struct Apartment(bool);
    impl Drop for Apartment {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances successful CoInitializeEx on this thread.
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }
    fn wide_path(buffer: &[u16]) -> Option<PathBuf> {
        let end = buffer.iter().position(|&c| c == 0)?;
        if end == 0 {
            return None;
        }
        String::from_utf16(&buffer[..end]).ok().map(PathBuf::from)
    }
    pub(super) fn decode_ansi(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return Some(String::new());
        }
        let count = i32::try_from(bytes.len()).ok()?;
        let mut output = vec![0u16; bytes.len()];
        // SAFETY: bounded buffers/lengths remain live through conversion.
        let written = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                count,
                output.as_mut_ptr(),
                count,
            )
        };
        if written <= 0 {
            return None;
        }
        String::from_utf16(&output[..usize::try_from(written).ok()?]).ok()
    }
    struct FolderList(*mut ITEMIDLIST);
    impl Drop for FolderList {
        fn drop(&mut self) {
            // SAFETY: Windows allocated this returned IDList with the COM allocator.
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    fn copied_idlist_path(list: &[u8]) -> Option<PathBuf> {
        let aligned: Vec<u16> = list
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        let mut output = vec![0u16; 32_768];
        // SAFETY: caller supplies a validated complete or boundary-truncated
        // IDList with a terminal ID; aligned storage and output remain live.
        if unsafe {
            SHGetPathFromIDListEx(
                aligned.as_ptr().cast::<ITEMIDLIST>(),
                output.as_mut_ptr(),
                32_768,
                GPFIDL_DEFAULT,
            )
        } == 0
        {
            return None;
        }
        wide_path(&output)
    }
    fn corroborate_folder_anchor(list: &[u8], anchor: &FolderAnchor) -> Option<()> {
        let mut prefix = list.get(..anchor.offset)?.to_vec();
        prefix.extend_from_slice(&[0, 0]);
        let prefix_path = copied_idlist_path(&prefix)?;
        let guid = GUID {
            data1: u32::from_le_bytes(anchor.guid[..4].try_into().ok()?),
            data2: u16::from_le_bytes(anchor.guid[4..6].try_into().ok()?),
            data3: u16::from_le_bytes(anchor.guid[6..8].try_into().ok()?),
            data4: anchor.guid[8..].try_into().ok()?,
        };
        let mut pointer = std::ptr::null_mut();
        // SAFETY: valid allowlisted built-in folder GUID/out pointer. DONT_VERIFY
        // requests the mapping without verifying/creating the folder. Returned
        // memory is owned by FolderList and freed with CoTaskMemFree.
        if unsafe {
            SHGetKnownFolderIDList(
                &raw const guid,
                0x4000,
                std::ptr::null_mut(),
                &raw mut pointer,
            )
        } < 0
            || pointer.is_null()
        {
            return None;
        }
        let folder = FolderList(pointer);
        let mut output = vec![0u16; 32_768];
        // SAFETY: Windows returned a live complete IDList; buffer is sized to cchPath.
        if unsafe { SHGetPathFromIDListEx(folder.0, output.as_mut_ptr(), 32_768, GPFIDL_DEFAULT) }
            == 0
        {
            return None;
        }
        let known_path = wide_path(&output)?;
        let prefix = super::lexical_path(&prefix_path)?;
        let known = super::lexical_path(&known_path)?;
        // No filesystem lookup of a foreign folder: compare lexical mappings
        // before the full target can pass the separate owned-path boundary.
        prefix
            .to_str()?
            .eq_ignore_ascii_case(known.to_str()?)
            .then_some(())
    }
    pub(super) fn stored_paths(
        bytes: &[u8],
        id_list: Option<&[u8]>,
        anchor: Option<&FolderAnchor>,
    ) -> Option<Vec<PathBuf>> {
        // SAFETY: initialize this thread's COM apartment. Changed-mode means an
        // existing apartment can be used; it must not be uninitialized by us.
        let init = unsafe {
            CoInitializeEx(
                std::ptr::null(),
                u32::try_from(COINIT_APARTMENTTHREADED).ok()?,
            )
        };
        if init < 0 && init != -2_147_417_850 {
            return None;
        }
        let _apartment = Apartment(init >= 0);
        if let Some(anchor) = anchor {
            corroborate_folder_anchor(id_list?, anchor)?;
        }
        let mut paths = Vec::new();
        if let Some(list) = id_list {
            paths.push(copied_idlist_path(list)?);
        }
        let link_iid = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
        let persist_iid = GUID::from_u128(0x00000109_0000_0000_c000_000000000046);
        let mut pointer = std::ptr::null_mut();
        // SAFETY: valid GUIDs/out pointer; acquire stock in-process IShellLinkW.
        if unsafe {
            CoCreateInstance(
                &ShellLink,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &raw const link_iid,
                &raw mut pointer,
            )
        } < 0
            || pointer.is_null()
        {
            return None;
        }
        let link = ComObject(pointer);
        let mut persist_pointer = std::ptr::null_mut();
        // SAFETY: query the live object for IPersistStream; output owns a ref.
        if unsafe {
            (link.vtable::<Unknown>().query)(
                link.0,
                &raw const persist_iid,
                &raw mut persist_pointer,
            )
        } < 0
            || persist_pointer.is_null()
        {
            return None;
        }
        let persist = ComObject(persist_pointer);
        // SAFETY: bounded bytes stay live during memory-stream creation. This
        // passes no filename and does not open or execute a shortcut target.
        let stream_pointer =
            unsafe { SHCreateMemStream(bytes.as_ptr(), u32::try_from(bytes.len()).ok()?) };
        if stream_pointer.is_null() {
            return None;
        }
        let stream = ComObject(stream_pointer);
        // SAFETY: correct IPersistStream ABI and live IStream reference. Load
        // reads bounded in-memory metadata into the object; we never call Save.
        if unsafe { (persist.vtable::<PersistVtable>().load)(persist.0, stream.0) } < 0 {
            return None;
        }
        let mut output = vec![0u16; 32_768];
        // SAFETY: correct IShellLinkW ABI and output length; null find-data
        // avoids requesting attributes. Request only RAWPATH, never Resolve,
        // target execution, ShellExecute, tracking/search or installer actions.
        if unsafe {
            (link.vtable::<LinkVtable>().get_path)(
                link.0,
                output.as_mut_ptr(),
                32_768,
                std::ptr::null_mut(),
                SLGP_RAWPATH,
            )
        } != 0
        {
            return None;
        }
        paths.push(wide_path(&output)?);
        Some(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Vec<u8>) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("portable");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("target.txt");
        std::fs::write(&file, b"inert fixture").unwrap();
        let link = temp.path().join("host/Recent/fixture.lnk");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let bytes = crate::tests::make_lnk(file.to_str().unwrap());
        (temp, std::fs::canonicalize(root).unwrap(), link, bytes)
    }
    fn push_unicode(bytes: &mut Vec<u8>, value: &str) {
        let words: Vec<u16> = value.encode_utf16().collect();
        bytes.extend_from_slice(&u16::try_from(words.len()).unwrap().to_le_bytes());
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    #[test]
    fn safe_metadata_and_agreeing_relative_path_do_not_hide_owned_target() {
        let (_temp, root, link, mut bytes) = fixture();
        bytes[20..24].copy_from_slice(&0x9eu32.to_le_bytes());
        push_unicode(&mut bytes, "Unicode description \u{03c0}");
        #[cfg(windows)]
        push_unicode(&mut bytes, r"..\..\portable\target.txt");
        #[cfg(not(windows))]
        push_unicode(&mut bytes, "../../portable/target.txt");
        push_unicode(&mut bytes, "unrelated working directory metadata");
        let expected = std::fs::canonicalize(root.join("target.txt")).unwrap();
        assert_eq!(owned_target(&bytes, &link, &root), Some(expected));
    }
    #[test]
    fn malformed_strings_offsets_and_truncations_are_preserved_without_native_loading() {
        let (_temp, _root, _link, bytes) = fixture();
        for length in 0..bytes.len() {
            assert!(parse(&bytes[..length]).is_none());
        }
        for pos in [76usize, 80, 88, 92, 96, 100] {
            let mut bad = bytes.clone();
            bad[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(parse(&bad).is_none());
        }
        let mut bad = bytes.clone();
        bad[20..24].copy_from_slice(&0x86u32.to_le_bytes());
        bad.extend_from_slice(&1u16.to_le_bytes());
        bad.extend_from_slice(&0xd800u16.to_le_bytes());
        assert!(parse(&bad).is_none());
        let oversized = vec![0u8; MAX_LINK_BYTES + 1];
        assert!(parse(&oversized).is_none());
    }
    #[test]
    fn unknown_flags_and_extra_data_are_not_passed_to_windows() {
        let (_temp, _root, _link, bytes) = fixture();
        for flag in [0x100u32, 0x200, 0x1000, 0x8000, 0x0200_0000] {
            let mut bad = bytes.clone();
            bad[20..24].copy_from_slice(&(2 | flag).to_le_bytes());
            assert!(parse(&bad).is_none());
        }
        let mut bad = bytes.clone();
        bad.extend_from_slice(&8u32.to_le_bytes());
        bad.extend_from_slice(&0xa000_000cu32.to_le_bytes());
        bad.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse(&bad).is_none());
    }
    #[test]
    fn stored_unicode_and_ansi_paths_must_identify_the_same_owned_target() {
        let (temp, root, link, bytes) = fixture();
        let foreign = temp.path().join("foreign.txt");
        std::fs::write(&foreign, b"foreign fixture").unwrap();
        let old_info = &bytes[76..];
        let mut info = vec![0u8; 36];
        info.extend_from_slice(&old_info[28..]);
        let unicode_base = info.len();
        for word in foreign
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(std::iter::once(0))
        {
            info.extend_from_slice(&word.to_le_bytes());
        }
        let unicode_suffix = info.len();
        info.extend_from_slice(&0u16.to_le_bytes());
        for (pos, value) in [
            (0, info.len()),
            (4, 36),
            (8, 1),
            (12, 36),
            (16, u32_at(old_info, 16).unwrap() as usize + 8),
            (20, 0),
            (24, u32_at(old_info, 24).unwrap() as usize + 8),
            (28, unicode_base),
            (32, unicode_suffix),
        ] {
            info[pos..pos + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
        }
        let mut conflict = bytes[..76].to_vec();
        conflict.extend_from_slice(&info);
        assert!(
            parse(&conflict).is_some(),
            "fixture must be structurally valid"
        );
        assert_eq!(owned_target(&conflict, &link, &root), None);
    }
    #[test]
    fn relative_targets_cannot_be_rooted_or_escape_the_owner() {
        let (_temp, root, link, bytes) = fixture();
        for relative in ["../../foreign.txt", "/foreign.txt", r"C:\foreign.txt"] {
            let mut bad = bytes.clone();
            bad[20..24].copy_from_slice(&0x8au32.to_le_bytes());
            push_unicode(&mut bad, relative);
            assert_eq!(owned_target(&bad, &link, &root), None);
        }
    }
    #[test]
    fn alias_targets_are_preserved_instead_of_followed() {
        let (temp, root, link, _bytes) = fixture();
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("target.txt"), b"outside owned folder").unwrap();
        let alias = temp.path().join("portable/alias");
        crate::tests::owned_directory_link(&temp, &alias, &elsewhere);
        let bytes = crate::tests::make_lnk(alias.join("target.txt").to_str().unwrap());
        assert_eq!(owned_target(&bytes, &link, &root), None);
    }
}
