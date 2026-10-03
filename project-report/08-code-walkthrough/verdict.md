# Code Walkthrough: analyzer/scoring/verdict.py

- **Purpose**: Combines all analysis signals into a weighted 0-100 score and assigns a verdict band (CLEAN/SUSPICIOUS/MALICIOUS).
- **Inputs**: `FileFingerprint`, `PEAnalysis`, `EntropyAnalysis`, `StringsAnalysis`, `YaraScanResult`.
- **Outputs**: `Verdict` dataclass.
- **Dependencies**: `dataclasses`, `typing`, all analysis module dataclasses.
- **Callers**: `main.py:69`.
- **Callees**: None (pure computation).

---

## Lines 1-29: Module docstring

Extensive documentation of the scoring philosophy: no single signal dominates, combinations > individuals, packing is suspicious not damning, strings are noisy. Documents the three score bands.

## Lines 31-38: Imports

```python
from dataclasses import dataclass, field
from typing import Optional

from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis
from analyzer.static.entropy import EntropyAnalysis
from analyzer.static.strings import StringsAnalysis
from analyzer.static.yara_scan import YaraScanResult
```

Imports all analysis dataclass types for type annotations. `field` and `Optional` are unused.

## Lines 46-93: Weight constants

```python
WEIGHT_SUSPICIOUS_IMPORT: float = 2.0
CAP_SUSPICIOUS_IMPORTS: float = 16.0

WEIGHT_IMPORT_COMBO: float = 8.0
CAP_IMPORT_COMBOS: float = 20.0

WEIGHT_PACKED_SECTION: float = 6.0
WEIGHT_SIZE_MISMATCH: float = 4.0
CAP_PACKING: float = 18.0

WEIGHT_YARA_HIT: float = 10.0
CAP_YARA: float = 30.0

WEIGHT_STRING_MATCH: float = 1.5
CAP_STRINGS: float = 12.0

WEIGHT_NO_SIGNATURE: float = 4.0
WEIGHT_TIMESTAMP_ANOMALY: float = 3.0
WEIGHT_EXE_WITH_EXPORTS: float = 3.0
```

Every weight and cap is a named constant with a comment explaining the rationale. The theoretical maximum score (if all caps are hit plus uncapped signals) is: 16 + 20 + 18 + 30 + 12 + 4 + 3 + 3 = 106, which is clamped to 100.

## Lines 100-102: Band thresholds

```python
BAND_CLEAN_MAX      = 30
BAND_SUSPICIOUS_MAX = 60
```

Score 0-30 = CLEAN, 31-60 = SUSPICIOUS, 61-100 = MALICIOUS.

## Lines 109-123: Data classes

```python
@dataclass
class ScoringReason:
    category: str
    detail: str
    points: float

@dataclass
class Verdict:
    score: int
    band: str
    reasons: list[ScoringReason]
    breakdown: dict[str, float]
```

`ScoringReason` records one finding with its point contribution. `Verdict` contains the final score, band, all reasons, and a per-category breakdown summary.

## Lines 130-312: `compute_verdict()`

The main scoring function. Pure computation — no I/O, no side effects.

```python
    reasons: list[ScoringReason] = []
    raw_score: float = 0.0
    breakdown: dict[str, float] = {}
```

Initializes the accumulator, reason list, and breakdown dictionary.

### Section 1: Suspicious imports (lines 161-173)

```python
    import_points = 0.0
    for imp in pe_analysis.suspicious_imports:
        pts = min(WEIGHT_SUSPICIOUS_IMPORT, CAP_SUSPICIOUS_IMPORTS - import_points)
        if pts <= 0:
            break
        import_points += pts
        reasons.append(ScoringReason(
            category="Suspicious Import",
            detail=f"Imports {imp.function} ({imp.suspicion_reason})",
            points=pts,
        ))
    raw_score += import_points
    breakdown["Suspicious Imports"] = import_points
```

Each suspicious import adds 2.0 points. The `min()` expression ensures the cap is respected: if the remaining room under the cap is less than 2.0, only the remaining amount is added. The `break` stops iteration once the cap is reached.

### Section 2: Import combinations (lines 176-189)

Same pattern: 8.0 points each, cap at 20.0.

### Section 3: Packing indicators (lines 192-218)

```python
    packing_points = 0.0
    for sec in entropy.packed_sections:
        pts = min(WEIGHT_PACKED_SECTION, CAP_PACKING - packing_points)
        if pts <= 0:
            break
        packing_points += pts
        ...

    for sec in entropy.mismatch_sections:
        pts = min(WEIGHT_SIZE_MISMATCH, CAP_PACKING - packing_points)
        if pts <= 0:
            break
        packing_points += pts
        ...
```

Packed sections (6.0 each) and size-mismatch sections (4.0 each) share a single cap of 18.0. This means a binary with three packed sections would use 18/18 of the cap, leaving no room for size-mismatch points.

### Section 4: YARA matches (lines 221-234)

10.0 points each, cap at 30.0. Three matches would max out the YARA contribution.

### Section 5: Suspicious strings (lines 237-253)

1.5 points each, cap at 12.0. Eight matches would max out the string contribution.

```python
        text = match.matched_text
        if len(text) > 80:
            text = text[:77] + "..."
```

Long matched text is truncated to 80 characters for readability in the reason list.

### Section 6: Missing signature (lines 256-265)

```python
    if not pe_analysis.has_signature:
        raw_score += WEIGHT_NO_SIGNATURE
        reasons.append(ScoringReason(
            category="Signature",
            detail="No Authenticode digital signature present.",
            points=WEIGHT_NO_SIGNATURE,
        ))
        breakdown["Missing Signature"] = WEIGHT_NO_SIGNATURE
    else:
        breakdown["Missing Signature"] = 0.0
```

Binary check: 4.0 points if unsigned, 0 if signed. Always sets the breakdown key so the printer can display it consistently.

### Section 7: Timestamp anomaly (lines 268-280)

```python
    ts = pe_analysis.compile_time_raw
    if ts == 0 or ts > 1893456000:
        raw_score += WEIGHT_TIMESTAMP_ANOMALY
```

Flags timestamp = 0 (epoch, deliberately zeroed) or > 2030-01-01 (far future, suggesting deliberate tampering or deterministic builds). The magic number `1893456000` is the Unix timestamp for 2030-01-01 00:00:00 UTC.

### Section 8: EXE with exports (lines 282-294)

```python
    is_exe = fingerprint.file_name.lower().endswith('.exe')
    if is_exe and pe_analysis.exports:
        raw_score += WEIGHT_EXE_WITH_EXPORTS
```

Checks the file extension (not the PE characteristics) to determine if the file is an executable. DLLs normally export symbols; executables usually do not. An .exe with exports may indicate DLL masquerading.

### Final scoring (lines 296-312)

```python
    final_score = max(0, min(100, int(round(raw_score))))

    if final_score <= BAND_CLEAN_MAX:
        band = "CLEAN"
    elif final_score <= BAND_SUSPICIOUS_MAX:
        band = "SUSPICIOUS"
    else:
        band = "MALICIOUS"

    return Verdict(
        score=final_score, band=band,
        reasons=reasons, breakdown=breakdown,
    )
```

Clamps the float score to 0-100 as an integer. Assigns the band based on thresholds. Returns the complete verdict.
