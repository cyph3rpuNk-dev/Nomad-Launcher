#!/usr/bin/env python3
"""Verify a Chromium PAK (version 5) still carries Nomad's pinned logo resources.

Usage:
    verify_pak_logos.py <pak-file> <id>:<w>x<h> [<id>:<w>x<h> ...]

For each grit resource ID, checks the resource exists and is a PNG of the given
dimensions. Exit 0 if every target matches; exit 1 on any drift (missing target,
non-PNG, or wrong dimensions); exit 2 on usage/parse error.

Why this exists: grit can renumber resource IDs between Chromium versions,
silently moving the product logo that `launchers/ungoogled-chromium/src/main.rs`
patches by ID. `core/src/branding.rs` guards this at *runtime* (skips + warns on
a dimension mismatch); this script is the *bump-time* complement, run by
.github/workflows/hardening-sync.yml against a fresh ungoogled-chromium release
so maintainers re-derive the IDs before shipping.

No dependencies beyond the standard library.
"""

import struct
import sys


def parse_pak_v5(data: bytes) -> dict[int, bytes]:
    """Returns {resource_id: bytes} for a version-5 PAK. Raises on bad format.

    Layout (little-endian): [u32 version=5][u32 encoding][u16 resource_count]
    [u16 alias_count][resource_count x (u16 id, u32 offset)][u16 0][u32 end].
    """
    if len(data) < 12:
        raise ValueError("file too short to be a PAK")
    version = struct.unpack_from("<I", data, 0)[0]
    if version != 5:
        raise ValueError(f"unsupported PAK version {version} (only v5)")
    resource_count = struct.unpack_from("<H", data, 8)[0]
    entries_end = 12 + resource_count * 6
    if len(data) < entries_end + 6:
        raise ValueError("truncated PAK entry table")
    end_offset = struct.unpack_from("<I", data, entries_end + 2)[0]
    entries = [
        struct.unpack_from("<HI", data, 12 + i * 6) for i in range(resource_count)
    ]
    resources: dict[int, bytes] = {}
    for i, (rid, off) in enumerate(entries):
        nxt = entries[i + 1][1] if i + 1 < len(entries) else end_offset
        if off > len(data) or nxt > len(data) or off > nxt:
            raise ValueError(f"resource id={rid} has an out-of-bounds offset")
        resources[rid] = data[off:nxt]
    return resources


def png_dimensions(b: bytes):
    """(width, height) from a PNG's IHDR, or None if `b` is not a PNG."""
    if len(b) < 24 or b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
        return None
    return struct.unpack_from(">II", b, 16)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    pak_path = argv[1]
    try:
        targets = []
        for spec in argv[2:]:
            rid_s, dims_s = spec.split(":")
            w_s, h_s = dims_s.lower().split("x")
            targets.append((int(rid_s), int(w_s), int(h_s)))
    except ValueError:
        print(f"bad target spec; expected <id>:<w>x<h>, got: {argv[2:]}")
        return 2

    try:
        resources = parse_pak_v5(open(pak_path, "rb").read())
    except (OSError, ValueError) as e:
        print(f"  ERROR  cannot read {pak_path}: {e}")
        return 2

    print(f"Verifying {pak_path} ({len(resources)} resources):")
    drift = False
    for rid, w, h in targets:
        data = resources.get(rid)
        if data is None:
            print(f"  DRIFT  id={rid}: resource not found")
            drift = True
        elif (dims := png_dimensions(data)) is None:
            print(f"  DRIFT  id={rid}: resource is not a PNG")
            drift = True
        elif dims != (w, h):
            print(f"  DRIFT  id={rid}: expected {w}x{h}, got {dims[0]}x{dims[1]}")
            drift = True
        else:
            print(f"  ok     id={rid}: {w}x{h} PNG")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
