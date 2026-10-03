# Code Walkthrough: tests/test_fingerprint.py

- **Purpose**: Unit tests for file hashing and PE magic-byte validation.
- **Inputs**: Known byte sequences and temporary files.
- **Outputs**: Test pass/fail.
- **Dependencies**: `os`, `struct`, `tempfile`, `unittest`, fingerprint module.
- **Callers**: `python -m unittest discover tests/`.
- **Callees**: `_compute_hashes()`, `_validate_pe_magic()`, `fingerprint_file()`.

---

## Lines 1-8: Module docstring

## Lines 10-15: Imports

```python
import os
import struct
import tempfile
import unittest

from analyzer.fingerprint import fingerprint_file, _compute_hashes, _validate_pe_magic
```

Imports both public and private functions for testing.

## Lines 18-37: TestComputeHashes

```python
    def test_known_hash(self):
        sha256, md5 = _compute_hashes(b"")
        self.assertEqual(sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(md5, "d41d8cd98f00b204e9800998ecf8427e")
```
Verifies SHA-256 and MD5 of the empty string against known reference values.

```python
    def test_nonempty(self):
        sha1, md1 = _compute_hashes(b"hello")
        sha2, md2 = _compute_hashes(b"world")
        self.assertNotEqual(sha1, sha2)
        self.assertNotEqual(md1, md2)
```
Verifies different inputs produce different hashes (collision resistance check).

## Lines 40-81: TestValidatePEMagic

```python
    def _build_minimal_pe(self) -> bytes:
        header = bytearray(0x44)
        header[0:2] = b'MZ'
        struct.pack_into('<I', header, 0x3C, 0x40)
        header[0x40:0x44] = b'PE\x00\x00'
        return bytes(header)
```
Helper that builds the smallest valid PE header (68 bytes). The comment at lines 46-56 documents the exact layout.

Four test methods cover: valid PE (line 58), missing MZ (line 63), file too small (line 69), MZ present but wrong PE signature (line 74).

## Lines 84-105: TestFingerprintFile

```python
    def test_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            fingerprint_file("/nonexistent/path/to/file.exe")
```
Verifies the function raises `FileNotFoundError` for missing files.

```python
    def test_non_pe_file(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"This is not a PE file at all.")
            ...
        try:
            fp = fingerprint_file(path)
            self.assertFalse(fp.is_pe)
            self.assertGreater(fp.file_size, 0)
            self.assertEqual(len(fp.sha256), 64)
            self.assertEqual(len(fp.md5), 32)
        finally:
            os.unlink(path)
```
Creates a temporary file with a `.exe` extension but non-PE contents. Verifies `is_pe` is False, size is positive, and hash lengths are correct. Uses try/finally to clean up the temp file.

## Lines 108-109: Entry point
