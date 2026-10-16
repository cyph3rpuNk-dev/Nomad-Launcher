"""Regenerate public inert ZIP fixtures with Python standard-library zipfile.
No download, browser, executable, profile, or private data is used.
"""
from pathlib import Path
import hashlib
import io
import zipfile


class StreamingBuffer(io.BytesIO):
    def seek(self, *args):
        raise io.UnsupportedOperation("streaming fixture")


entries = [
    ("browser.exe", b"INERT browser marker; never executed\n", zipfile.ZIP_STORED),
    ("resources/app.pak", b"PUBLIC ZIP compatibility payload\n" * 16, zipfile.ZIP_DEFLATED),
    ("manifest.json", b'{"manifest_version":2,"name":"Inert ZIP fixture","version":"1.0.0"}\n', zipfile.ZIP_DEFLATED),
    ("META-INF/test.sf", b"INERT layout marker; not a signature\n", zipfile.ZIP_STORED),
    ("assets/caf\u00e9.txt", b"utf8 path\n", zipfile.ZIP_DEFLATED),
    ("bzip2.txt", b"bzip2 payload\n", zipfile.ZIP_BZIP2),
    ("lzma.txt", b"lzma payload\n", zipfile.ZIP_LZMA),
    ("empty/", b"", zipfile.ZIP_STORED),
    ("zip64.txt", b"small forced ZIP64 payload\n", zipfile.ZIP_STORED),
]
root = Path(__file__).resolve().parent
for filename, prefix, streaming in [("flat.zip", "", False), ("wrapped-stream.zip", "bundle/", True)]:
    buffer = StreamingBuffer() if streaming else io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data, method in entries:
            info = zipfile.ZipInfo(prefix + name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = method
            info.create_system = 3
            info.external_attr = (0o40755 if name.endswith("/") else 0o100644) << 16
            with archive.open(info, "w", force_zip64=name == "zip64.txt") as target:
                target.write(data)
    content = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.testzip() is None
        assert len(archive.infolist()) == len(entries)
    (root / filename).write_bytes(content)
    print(filename, len(content), hashlib.sha256(content).hexdigest())

# Corrupt only the stored payload, retaining the original CRC/header sizes.
flat = (root / "flat.zip").read_bytes()
corrupt = bytearray(flat)
position = corrupt.index(entries[0][1])
corrupt[position] ^= 1
(root / "corrupt-crc.zip").write_bytes(corrupt)
(root / "truncated.zip").write_bytes(flat[:len(flat) // 2])
