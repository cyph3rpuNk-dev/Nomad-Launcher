# Recent shortcut cleanup safety

## Scope and ownership

Automatic post-exit cleanup examines individual `.lnk` files in
`%APPDATA%\Microsoft\Windows\Recent`. It first requires a valid matching
`Nomad/instance.toml` and an existing browser image inside the owned portable
folder. A drive letter, executable basename or browser brand is never sufficient
attribution. The source directory and each shortcut must be ordinary paths;
metadata reads are limited to 64 KiB.

The old exact `HasLinkInfo`-only flag check preserved ordinary Windows-created
links with additional records. `core/src/shell_link.rs` now validates those
records and corroborates their stored targets before `cleanup.rs` can delete the
individual shortcut. It does not delete the target file.

## Accepted metadata and conservative refusal

The parser checks the Shell Link header size, CLSID and allowed flags, then
bounds record extents, strings, ItemIDs and ExtraData blocks. Local LinkInfo paths, ANSI and Unicode
representations, filesystem IDLists and any relative target must all identify
one existing target strictly below the canonical owned folder. PropertyStore
contents are corroborated through Windows' loaded RAWPATH, not independently
interpreted as arbitrary property keys. Relative paths
are interpreted from the actual shortcut directory. Candidates must pass the
lexical owned-folder boundary before filesystem metadata checks; symlinks,
junctions and other reparse points are refused before canonicalization.

`DisableKnownFolderTracking` is accepted for ordinary stored targets, as emitted
by the Windows Shell Recent API. A link combining that bit with KnownFolder or
SpecialFolder translation records is preserved because Windows ignores those
records; Nomad does not use an ignored anchor as ownership evidence. All other
target representations must still agree.

Supported IDLists begin with the built-in Computer or UsersFiles namespace and
recognized local drive/filesystem item types. Supported ExtraData comprises
bounded Tracker, PropertyStore, KnownFolder and paired SpecialFolder records.
Known-folder IDs are limited to UsersFiles, Profile, LocalAppData,
RoamingAppData, Desktop, Documents and Downloads. Their offsets must match an
ItemID boundary, the legacy ID must agree when present, and the stored prefix
must match the current built-in folder mapping. A supported ID with a
conflicting mapping also preserves the shortcut.

Environment/installer/Darwin target overrides, network/device paths, unsupported
flags or namespace records, duplicate/unknown ExtraData, malformed strings or
sizes, nonempty LinkInfo suffixes, disagreeing representations, and missing
or inaccessible targets are preserved. Some valid but unsupported links and
long or unrepresentable paths will therefore remain as host traces. This is
intentional; the implementation is not a general Shell Link resolver.

## Windows decoder boundary

On Windows, validated IDLists are converted with `SHGetPathFromIDListEx`. A
stock in-process Shell Link COM object loads the bounded bytes through an
in-memory `IPersistStream`; `IShellLinkW::GetPath` requests `SLGP_RAWPATH` with
no file-attribute output. Known-folder corroboration uses
`SHGetKnownFolderIDList` with `KF_FLAG_DONT_VERIFY`, without requesting folder
creation. Native paths must agree with all separately parsed target records.

Nomad never calls `IShellLink::Resolve`, `Save`, `ShellExecute`, target execution
or a moved-target search in this cleanup path. These API choices avoid
requesting link tracking, installer repair or a resolution dialog. They are
code-level controls, not a complete measurement of Windows internals or proof
of zero native decoder side effects. Windows remains trusted to decode the
allowlisted metadata safely; a malicious host can alter COM registrations,
folder mappings or files. Repeated metadata checks do not eliminate concurrent
path replacement races. Cleanup is best effort, not forensic erasure or a
security boundary against the host.

Non-Windows tooling conservatively preserves links that need the Windows
decoder; it is not a substitute for Windows validation.

## Regression coverage and limits

`core/tests/fixtures/create-shell-link.ps1` uses Windows' `WScript.Shell` to save
real links to inert files inside an explicitly marked temporary fixture. It
never opens or executes a target. Cleanup tests supply fake AppData/ProgramData
roots under that fixture; they do not clean the real host Recent directory,
launch a browser or alter persistent user/system settings.

Tests cover ordinary Windows IDList/LinkInfo/StringData/ExtraData, non-ASCII
targets, unrelated same-drive and sibling targets, missing targets, malformed
and unsupported records, disagreeing IDLists/relative paths, and altered folder
IDs/offsets. A derived IDList-only variant removes optional LinkInfo from a
Windows-created fixture; disagreement tests deliberately mutate metadata. Pure
parser tests additionally exercise bounded truncation, ANSI/Unicode conflicts,
relative escapes and target junctions.

The recorded local native run used Windows 11 build 26200. Windows 10 and actual
Explorer-generated Recent links from browsing sessions have not been tested for
this patch. For release qualification, collect inert examples on both Windows
10 and 11, preserve their original bytes, and replay them under the same owned
fake-host fixture with unrelated-target sentinels. Do not run cleanup against
real user directories as a test. [WER fixture coverage](WER-CLEANUP-SAFETY.md)
is separate; [missed-cleanup recovery](MISSED-CLEANUP-RECOVERY.md) now has
inert regression coverage, while native crash/power-loss validation remains pending.

## Upstream contract references

- [MS-SHLLINK structures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/747629b3-b5be-452a-8101-b9a2ec49978c)
  and [LinkFlags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af)
  define the independent target records and metadata flags.
- [SHGetPathFromIDListEx](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetpathfromidlistex)
  converts a filesystem IDList to a path.
- [IShellLink GetPath](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinka-getpath)
  documents RAWPATH; [Resolve](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinka-resolve)
  documents the search/tracking behavior this cleanup does not request.
- [Known-folder flags](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-known_folder_flag)
  and [known-folder IDs](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)
  document the bounded anchor mappings and no-verification flag.

## Windows Shell Recent capture follow-up (2026-10-15)

**Tested:** an offline Windows 11 Sandbox produced actual `SHAddToRecentDocs`
links with flags `0x0020009B`. The baseline parser refused their
`DisableKnownFolderTracking` bit and left the owned Recent copy behind. A narrow
bit allowlist correction, with ignored folder-block combinations still refused,
passed a same-byte replay; unrelated links/reports and original captures were
preserved. The final refactored build also passed, alongside the 551-test gate
(17 ignored) and Rust 1.92 checking. The change is local/uncommitted.

[Commands, exact evidence and limits](WINDOWS-METADATA-QUALIFICATION.md) distinguish
Shell API serialization from an actual Explorer/browser navigation session.
Windows 10 and those navigation-generated variants remain unqualified.
