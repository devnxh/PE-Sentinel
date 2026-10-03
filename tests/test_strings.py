"""
tests/test_strings.py — Unit tests for the strings extraction module.

Tests cover:
  - ASCII string extraction.
  - UTF-16LE string extraction.
  - Pattern matching (IPs, URLs, registry paths, shell invocations).
  - Benign IP filtering.
"""

import os
import tempfile
import unittest

from analyzer.static.strings import (
    _extract_ascii_strings,
    _extract_utf16le_strings,
    analyze_strings,
)


class TestASCIIExtraction(unittest.TestCase):
    """Test _extract_ascii_strings."""

    def test_basic_extraction(self):
        data = b"\x00\x00Hello World\x00\x00more text here\x00"
        strings = _extract_ascii_strings(data, min_len=5)
        self.assertIn("Hello World", strings)
        self.assertIn("more text here", strings)

    def test_min_length_filter(self):
        data = b"Hi\x00Hello World\x00"
        strings = _extract_ascii_strings(data, min_len=5)
        # "Hi" is too short.
        self.assertTrue(all(len(s) >= 5 for s in strings))

    def test_no_strings(self):
        data = bytes(range(0, 0x20)) * 10  # Non-printable bytes
        strings = _extract_ascii_strings(data, min_len=5)
        self.assertEqual(len(strings), 0)


class TestUTF16Extraction(unittest.TestCase):
    """Test _extract_utf16le_strings."""

    def test_basic_utf16(self):
        # "Hello" in UTF-16LE: H\x00e\x00l\x00l\x00o\x00
        data = b"\x00" + "Hello".encode('utf-16-le') + b"\x00\x00"
        strings = _extract_utf16le_strings(data, min_len=5)
        self.assertIn("Hello", strings)


class TestPatternMatching(unittest.TestCase):
    """Test that suspicious patterns are detected in extracted strings."""

    def _write_temp(self, content: bytes) -> str:
        """Write content to a temp file and return its path."""
        f = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        f.write(content)
        f.flush()
        f.close()
        return f.name

    def test_ip_detection(self):
        data = b"\x00\x00\x00Connect to 192.168.1.100 for callback\x00\x00"
        path = self._write_temp(data)
        try:
            result = analyze_strings(path)
            ip_matches = [m for m in result.matches if m.pattern_name == "IPv4 Address"]
            matched_ips = [m.matched_text for m in ip_matches]
            self.assertIn("192.168.1.100", matched_ips)
        finally:
            os.unlink(path)

    def test_benign_ip_filtered(self):
        data = b"\x00\x00\x00Localhost is 127.0.0.1 always\x00\x00"
        path = self._write_temp(data)
        try:
            result = analyze_strings(path)
            ip_matches = [m for m in result.matches if m.pattern_name == "IPv4 Address"]
            matched_ips = [m.matched_text for m in ip_matches]
            self.assertNotIn("127.0.0.1", matched_ips)
        finally:
            os.unlink(path)

    def test_url_detection(self):
        data = b"\x00\x00https://evil.com/payload.exe download\x00\x00"
        path = self._write_temp(data)
        try:
            result = analyze_strings(path)
            url_matches = [m for m in result.matches if m.pattern_name == "URL"]
            self.assertGreater(len(url_matches), 0)
        finally:
            os.unlink(path)

    def test_registry_detection(self):
        data = b"\x00\x00HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        path = self._write_temp(data)
        try:
            result = analyze_strings(path)
            reg_matches = [m for m in result.matches if m.pattern_name == "Registry Path"]
            self.assertGreater(len(reg_matches), 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
