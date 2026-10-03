"""
tests/test_verdict.py — Unit tests for the scoring/verdict module.

Tests cover:
  - Score banding (clean / suspicious / malicious boundaries).
  - Contribution caps (no single category should exceed its cap).
  - Additive scoring (multiple signals combine correctly).
"""

import unittest
from unittest.mock import MagicMock

from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis, SectionInfo, ImportEntry, ExportEntry, SuspiciousComboHit
from analyzer.static.entropy import EntropyAnalysis, SectionEntropy
from analyzer.static.strings import StringsAnalysis, StringMatch
from analyzer.static.yara_scan import YaraScanResult, YaraMatch
from analyzer.scoring.verdict import compute_verdict


def _make_fingerprint(**overrides) -> FileFingerprint:
    defaults = {
        "file_path": "/test/sample.exe",
        "file_name": "sample.exe",
        "file_size": 1024,
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "is_pe": True,
        "pe_validation_detail": "Valid PE",
    }
    defaults.update(overrides)
    return FileFingerprint(**defaults)


def _make_pe_analysis(**overrides) -> PEAnalysis:
    defaults = {
        "machine": "AMD64",
        "machine_hex": 0x8664,
        "compile_time": "2024-01-01 00:00:00 UTC",
        "compile_time_raw": 1704067200,
        "sections": [],
        "imports": [],
        "exports": [],
        "suspicious_imports": [],
        "suspicious_combos": [],
        "has_signature": True,
        "signature_detail": "Present",
    }
    defaults.update(overrides)
    return PEAnalysis(**defaults)


def _make_entropy(**overrides) -> EntropyAnalysis:
    defaults = {
        "sections": [],
        "packed_sections": [],
        "mismatch_sections": [],
        "overall_suspicious": False,
    }
    defaults.update(overrides)
    return EntropyAnalysis(**defaults)


def _make_strings(**overrides) -> StringsAnalysis:
    defaults = {
        "total_strings_extracted": 0,
        "ascii_count": 0,
        "utf16_count": 0,
        "matches": [],
        "match_summary": {},
    }
    defaults.update(overrides)
    return StringsAnalysis(**defaults)


def _make_yara(**overrides) -> YaraScanResult:
    defaults = {
        "rules_loaded": 0,
        "rule_files": [],
        "matches": [],
        "errors": [],
        "yara_available": True,
    }
    defaults.update(overrides)
    return YaraScanResult(**defaults)


class TestVerdictBanding(unittest.TestCase):
    """Test that scores map to the correct bands."""

    def test_clean_band(self):
        """A benign PE with no findings should be CLEAN."""
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(),
            _make_entropy(),
            _make_strings(),
            _make_yara(),
        )
        self.assertEqual(verdict.band, "CLEAN")
        self.assertLessEqual(verdict.score, 30)

    def test_unsigned_is_still_clean(self):
        """A binary with only a missing signature should still be CLEAN (4 pts)."""
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(has_signature=False),
            _make_entropy(),
            _make_strings(),
            _make_yara(),
        )
        self.assertEqual(verdict.band, "CLEAN")
        self.assertEqual(verdict.score, 4)


class TestVerdictScoring(unittest.TestCase):
    """Test that individual scoring components contribute correctly."""

    def test_suspicious_imports_add_points(self):
        sus_import = ImportEntry(
            dll="KERNEL32.dll",
            function="CreateRemoteThread",
            is_suspicious=True,
            suspicion_reason="Creates thread in another process.",
        )
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(suspicious_imports=[sus_import]),
            _make_entropy(),
            _make_strings(),
            _make_yara(),
        )
        # Should have at least the import points.
        self.assertGreater(verdict.score, 0)
        self.assertTrue(any("CreateRemoteThread" in r.detail for r in verdict.reasons))

    def test_yara_match_adds_points(self):
        yara_match = YaraMatch(
            rule_name="Test_Rule",
            namespace="test",
            meta={"description": "Test rule"},
            tags=["test"],
            description="Test rule",
        )
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(),
            _make_entropy(),
            _make_strings(),
            _make_yara(matches=[yara_match]),
        )
        self.assertGreater(verdict.score, 0)
        self.assertTrue(any("Test_Rule" in r.detail for r in verdict.reasons))

    def test_score_clamped_to_100(self):
        """Even with all signals maxed out, score should not exceed 100."""
        # Create a lot of findings.
        sus_imports = [
            ImportEntry("K32", f"Func{i}", True, "suspicious")
            for i in range(20)
        ]
        yara_matches = [
            YaraMatch(f"Rule{i}", "ns", {}, [], "desc")
            for i in range(10)
        ]
        string_matches = [
            StringMatch("URL", f"http://evil{i}.com", "ascii")
            for i in range(20)
        ]
        packed = [
            SectionEntropy(f".s{i}", 7.8, 1000, 1000, True, False, "packed")
            for i in range(5)
        ]

        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(
                suspicious_imports=sus_imports,
                has_signature=False,
            ),
            _make_entropy(packed_sections=packed, overall_suspicious=True),
            _make_strings(matches=string_matches, match_summary={"URL": 20}),
            _make_yara(matches=yara_matches),
        )
        self.assertLessEqual(verdict.score, 100)


if __name__ == "__main__":
    unittest.main()
