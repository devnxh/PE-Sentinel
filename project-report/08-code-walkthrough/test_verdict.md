# Code Walkthrough: tests/test_verdict.py

- **Purpose**: Unit tests for the scoring engine and verdict banding.
- **Inputs**: Mock analysis dataclasses constructed via factory functions.
- **Outputs**: Test pass/fail.
- **Dependencies**: `unittest`, all analysis dataclass types, `compute_verdict`.
- **Callers**: `python -m unittest discover tests/`.
- **Callees**: `compute_verdict()`.

---

## Lines 1-8: Module docstring

Documents coverage: banding, caps, additive scoring.

## Lines 10-18: Imports

```python
import unittest
from unittest.mock import MagicMock

from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis, SectionInfo, ImportEntry, ExportEntry, SuspiciousComboHit
from analyzer.static.entropy import EntropyAnalysis, SectionEntropy
from analyzer.static.strings import StringsAnalysis, StringMatch
from analyzer.static.yara_scan import YaraScanResult, YaraMatch
from analyzer.scoring.verdict import compute_verdict
```

`MagicMock` is imported but unused. All dataclass types are imported to construct test fixtures.

## Lines 21-85: Factory functions

Five factory functions (`_make_fingerprint`, `_make_pe_analysis`, `_make_entropy`, `_make_strings`, `_make_yara`) create default "clean" instances of each dataclass. They accept `**overrides` to customize specific fields. This pattern avoids repeating all default values in every test.

```python
def _make_fingerprint(**overrides) -> FileFingerprint:
    defaults = {
        "file_path": "/test/sample.exe",
        "file_name": "sample.exe",
        ...
    }
    defaults.update(overrides)
    return FileFingerprint(**defaults)
```

The defaults represent a benign, signed PE file with no findings. Tests override only the fields they need.

## Lines 88-113: TestVerdictBanding

```python
    def test_clean_band(self):
        verdict = compute_verdict(
            _make_fingerprint(), _make_pe_analysis(),
            _make_entropy(), _make_strings(), _make_yara(),
        )
        self.assertEqual(verdict.band, "CLEAN")
        self.assertLessEqual(verdict.score, 30)
```
A fully clean PE should score in the CLEAN band (0-30).

```python
    def test_unsigned_is_still_clean(self):
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(has_signature=False),
            _make_entropy(), _make_strings(), _make_yara(),
        )
        self.assertEqual(verdict.band, "CLEAN")
        self.assertEqual(verdict.score, 4)
```
A PE with only a missing signature should score exactly 4 (the weight for missing signature) and remain in the CLEAN band. This verifies the exact weight value from `verdict.py:83`.

## Lines 116-185: TestVerdictScoring

```python
    def test_suspicious_imports_add_points(self):
        sus_import = ImportEntry(
            dll="KERNEL32.dll", function="CreateRemoteThread",
            is_suspicious=True, suspicion_reason="...",
        )
        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(suspicious_imports=[sus_import]),
            _make_entropy(), _make_strings(), _make_yara(),
        )
        self.assertGreater(verdict.score, 0)
        self.assertTrue(any("CreateRemoteThread" in r.detail for r in verdict.reasons))
```
Verifies one suspicious import adds points and appears in the reasons list.

```python
    def test_yara_match_adds_points(self):
        yara_match = YaraMatch(
            rule_name="Test_Rule", namespace="test",
            meta={"description": "Test rule"}, tags=["test"],
            description="Test rule",
        )
        verdict = compute_verdict(
            _make_fingerprint(), _make_pe_analysis(),
            _make_entropy(), _make_strings(),
            _make_yara(matches=[yara_match]),
        )
        self.assertGreater(verdict.score, 0)
        self.assertTrue(any("Test_Rule" in r.detail for r in verdict.reasons))
```
Verifies one YARA match adds points and appears in reasons.

```python
    def test_score_clamped_to_100(self):
        sus_imports = [ImportEntry("K32", f"Func{i}", True, "suspicious") for i in range(20)]
        yara_matches = [YaraMatch(f"Rule{i}", "ns", {}, [], "desc") for i in range(10)]
        string_matches = [StringMatch("URL", f"http://evil{i}.com", "ascii") for i in range(20)]
        packed = [SectionEntropy(f".s{i}", 7.8, 1000, 1000, True, False, "packed") for i in range(5)]

        verdict = compute_verdict(
            _make_fingerprint(),
            _make_pe_analysis(suspicious_imports=sus_imports, has_signature=False),
            _make_entropy(packed_sections=packed, overall_suspicious=True),
            _make_strings(matches=string_matches, match_summary={"URL": 20}),
            _make_yara(matches=yara_matches),
        )
        self.assertLessEqual(verdict.score, 100)
```
Stress test: creates 20 suspicious imports, 10 YARA matches, 20 string matches, and 5 packed sections. The theoretical uncapped total exceeds 100, but the test verifies the score is clamped at 100.

## Lines 188-189: Entry point
