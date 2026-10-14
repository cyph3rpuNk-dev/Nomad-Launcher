//! Conservative local browser quiescence proof for automatic deletion.
use std::path::Path;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    Idle,
    Running,
    Unknown,
}

pub(crate) fn probe(root: &Path, image: &Path) -> Presence {
    #[cfg(windows)]
    {
        native::probe(root, image).unwrap_or(Presence::Unknown)
    }
    #[cfg(not(windows))]
    {
        let _ = (root, image);
        Presence::Unknown
    }
}

#[cfg(windows)]
mod native {
    use super::{Path, Presence};
    use std::{
        io,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Globalization::{CompareStringOrdinal, CSTR_EQUAL},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: this guard owns a checked non-null native handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn normalized(path: &Path) -> Vec<u16> {
        let mut wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .map(|c| if c == 47 { 92 } else { c })
            .collect();
        if wide.starts_with(&[92, 92, 63, 92]) {
            wide.drain(..4);
        }
        wide
    }
    fn equal(left: &[u16], right: &[u16]) -> bool {
        let (Ok(a), Ok(b)) = (i32::try_from(left.len()), i32::try_from(right.len())) else {
            return false;
        };
        // SAFETY: both buffers live for the call and lengths describe their initialized units.
        unsafe { CompareStringOrdinal(left.as_ptr(), a, right.as_ptr(), b, 1) == CSTR_EQUAL }
    }
    fn image_path(pid: u32) -> io::Result<Option<Vec<u16>>> {
        // SAFETY: no privileges are requested; the checked handle is owned until drop.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok() {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let handle = Handle(raw);
        let mut buffer = vec![0; 32768];
        let mut len = 32768;
        // SAFETY: the initialized output buffer has the declared capacity; handle remains live.
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &raw mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(usize::try_from(len).map_err(io::Error::other)?);
        if buffer.is_empty() {
            return Err(io::Error::other("empty process image"));
        }
        Ok(Some(normalized(Path::new(&std::ffi::OsString::from_wide(
            &buffer,
        )))))
    }
    fn classify_image(path: &[u16], root_prefix: &[u16]) -> Presence {
        if path.len() > root_prefix.len() && equal(&path[..root_prefix.len()], root_prefix) {
            Presence::Running
        } else {
            // Do not resolve foreign/short/mapped aliases. Same-name candidates
            // outside this lexical prefix cannot establish a complete idle proof.
            Presence::Unknown
        }
    }

    pub(super) fn probe(root: &Path, image: &Path) -> io::Result<Presence> {
        let name = image
            .file_name()
            .ok_or_else(|| io::Error::other("missing browser basename"))?;
        let name: Vec<u16> = name.encode_wide().collect();
        let mut prefix = normalized(root);
        if prefix.last() != Some(&92) {
            prefix.push(92);
        }
        // SAFETY: process snapshot has no output pointer and is released by its guard.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let snapshot = Handle(raw);
        // SAFETY: zero initialization is valid and dwSize is required by Toolhelp.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize =
            u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).map_err(io::Error::other)?;
        // SAFETY: initialized structure of the correct size and live snapshot handle.
        let mut available = unsafe { Process32FirstW(snapshot.0, &raw mut entry) };
        loop {
            if available == 0 {
                // SAFETY: inspected immediately after the failed enumeration call.
                return if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                    Ok(Presence::Idle)
                } else {
                    Err(io::Error::last_os_error())
                };
            }
            let len = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            if equal(&entry.szExeFile[..len], &name) {
                if let Some(path) = image_path(entry.th32ProcessID)? {
                    return Ok(classify_image(&path, &prefix));
                }
            }
            // SAFETY: enumeration structure and snapshot are still live.
            available = unsafe { Process32NextW(snapshot.0, &raw mut entry) };
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn lexical_process_boundary_accepts_case_but_rejects_sibling_and_short_alias() {
            let prefix = normalized(Path::new(r"C:\Portable\Helium\"));
            assert_eq!(
                classify_image(
                    &normalized(Path::new(r"c:\portable\helium\Browser\chrome.exe")),
                    &prefix
                ),
                Presence::Running
            );
            for path in [
                r"C:\Portable\Helium-other\Browser\chrome.exe",
                r"C:\PORTAB~1\Helium\Browser\chrome.exe",
                r"C:\Installed\chrome.exe",
            ] {
                assert_eq!(
                    classify_image(&normalized(Path::new(path)), &prefix),
                    Presence::Unknown
                );
            }
        }
        #[test]
        fn verbatim_and_slash_normalization_do_not_require_filesystem_lookup() {
            let prefix = normalized(Path::new(r"\\?\C:\Portable\Helium\"));
            assert_eq!(
                classify_image(
                    &normalized(Path::new("C:/Portable/Helium/Browser/chrome.exe")),
                    &prefix
                ),
                Presence::Running
            );
        }
    }
}
