"""
tests/test_fingerprint.py — Unit tests for the fingerprint module.

Tests cover:
  - SHA-256 / MD5 hash computation on known data.
  - PE magic-byte validation (MZ + PE\\0\\0 check).
  - Rejection of non-PE files.
"""

import os
import struct
import tempfile
import unittest

from analyzer.fingerprint import fingerprint_file, _compute_hashes, _validate_pe_magic


class TestComputeHashes(unittest.TestCase):
    """Test the _compute_hashes helper."""

    def test_known_hash(self):
        """SHA-256 and MD5 of an empty byte string should match known values."""
        sha256, md5 = _compute_hashes(b"")
        # SHA-256 of empty string:
        self.assertEqual(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        # MD5 of empty string:
        self.assertEqual(md5, "d41d8cd98f00b204e9800998ecf8427e")

    def test_nonempty(self):
        """Hashes should change for different inputs."""
        sha1, md1 = _compute_hashes(b"hello")
        sha2, md2 = _compute_hashes(b"world")
        self.assertNotEqual(sha1, sha2)
        self.assertNotEqual(md1, md2)


class TestValidatePEMagic(unittest.TestCase):
    """Test the _validate_pe_magic helper."""

    def _build_minimal_pe(self) -> bytes:
        """Build the smallest byte sequence that passes PE validation.

        Layout:
          - Bytes 0-1: 'MZ' (DOS magic)
          - Bytes 2-0x3B: zeros (padding)
          - Bytes 0x3C-0x3F: e_lfanew pointing to offset 0x40
          - Bytes 0x40-0x43: 'PE\\0\\0' (PE signature)
        """
        header = bytearray(0x44)          # 68 bytes of zeros
        header[0:2] = b'MZ'              # DOS magic
        struct.pack_into('<I', header, 0x3C, 0x40)  # e_lfanew = 0x40
        header[0x40:0x44] = b'PE\x00\x00'  # PE signature
        return bytes(header)

    def test_valid_pe(self):
        is_pe, detail = _validate_pe_magic(self._build_minimal_pe())
        self.assertTrue(is_pe)
        self.assertIn("Valid PE", detail)

    def test_no_mz(self):
        data = b'\x00\x00' + b'\x00' * 100
        is_pe, detail = _validate_pe_magic(data)
        self.assertFalse(is_pe)
        self.assertIn("Missing DOS header", detail)

    def test_too_small(self):
        is_pe, detail = _validate_pe_magic(b'M')
        self.assertFalse(is_pe)
        self.assertIn("too small", detail)

    def test_mz_but_no_pe_sig(self):
        header = bytearray(0x44)
        header[0:2] = b'MZ'
        struct.pack_into('<I', header, 0x3C, 0x40)
        header[0x40:0x44] = b'XX\x00\x00'  # Wrong signature
        is_pe, detail = _validate_pe_magic(bytes(header))
        self.assertFalse(is_pe)
        self.assertIn("invalid", detail)


class TestFingerprintFile(unittest.TestCase):
    """Test the full fingerprint_file function."""

    def test_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            fingerprint_file("/nonexistent/path/to/file.exe")

    def test_non_pe_file(self):
        """A plain text file should fingerprint successfully but is_pe=False."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"This is not a PE file at all.")
            f.flush()
            path = f.name

        try:
            fp = fingerprint_file(path)
            self.assertFalse(fp.is_pe)
            self.assertGreater(fp.file_size, 0)
            self.assertEqual(len(fp.sha256), 64)  # SHA-256 hex is 64 chars
            self.assertEqual(len(fp.md5), 32)      # MD5 hex is 32 chars
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
