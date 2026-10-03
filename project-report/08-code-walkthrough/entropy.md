# Code Walkthrough: analyzer/static/entropy.py

- **Purpose**: Shannon entropy analysis per PE section. Detects packed/encrypted sections and virtual/raw size mismatches.
- **Inputs**: File path (string) and section metadata from pe_parser.
- **Outputs**: `EntropyAnalysis` dataclass.
- **Dependencies**: `math`, `dataclasses`, `typing`, `pefile` (external, imported at function scope).
- **Callers**: `main.py:60`.
- **Callees**: `pefile.PE()`.

---

## Lines 1-16: Module docstring

```python
"""
static/entropy.py — Shannon entropy analysis per PE section.
...
"""
```

Explains that normal code is 4.5-6.5 entropy, packed data is 7.0-7.9, and the module flags both high entropy and size mismatches.

## Lines 18-20: Imports

```python
import math
from dataclasses import dataclass
from typing import Optional
```

`math.log2` is used in the Shannon formula. `Optional` is imported but unused — dead import.

## Lines 27-41: Tunable constants

```python
ENTROPY_PACKED_THRESHOLD: float = 7.2
SIZE_MISMATCH_RATIO: float = 3.0
MIN_RAW_SIZE: int = 512
```

Three module-level constants that control detection sensitivity:
- `ENTROPY_PACKED_THRESHOLD` (7.2): conservative cutoff. The docstring (lines 29-30) explains the choice.
- `SIZE_MISMATCH_RATIO` (3.0): virtual/raw ratio threshold. Sections expanding 3x or more are flagged.
- `MIN_RAW_SIZE` (512): sections smaller than this are skipped for entropy calculation, as BSS/uninitialized sections produce meaningless values.

These are deliberately exposed as module-level constants for easy adjustment.

## Lines 44-53: SectionEntropy dataclass

```python
@dataclass
class SectionEntropy:
    name: str
    entropy: float
    raw_size: int
    virtual_size: int
    is_packed: bool
    has_size_mismatch: bool
    detail: str
```

Per-section result. Contains both the raw entropy value and boolean flags for the two detection criteria.

## Lines 56-62: EntropyAnalysis dataclass

```python
@dataclass
class EntropyAnalysis:
    sections: list[SectionEntropy]
    packed_sections: list[SectionEntropy]
    mismatch_sections: list[SectionEntropy]
    overall_suspicious: bool
```

Aggregate result. `packed_sections` and `mismatch_sections` are convenience subsets of `sections`. `overall_suspicious` is true if any section is flagged.

## Lines 65-92: `_shannon_entropy()`

```python
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
```

Implements the Shannon entropy formula: H = -SUM(p(x) * log2(p(x))). Returns a value on a 0-8 scale (8 bits per byte). Uses a 256-element count array for byte frequencies. The `count == 0` guard avoids `log2(0)` which would be negative infinity. Performance note: iterating byte-by-byte in Python is slower than using `collections.Counter`, but the function is called only once per section and PE sections are typically under 1 MB.

## Lines 95-191: `analyze_entropy()`

```python
def analyze_entropy(file_path: str, sections_info: list[dict]) -> EntropyAnalysis:
```

Accepts the file path and section metadata dictionaries (with keys `name`, `virtual_size`, `raw_size`).

```python
    with open(file_path, 'rb') as fh:
        raw = fh.read()

    import pefile
    pe = pefile.PE(file_path)
```

Reads the entire file and creates a second pefile instance. This is the file's third full read in the pipeline (fingerprint read it once, pe_parser read it once via pefile). The import of pefile at function scope (line 119) is unusual — the module docstring does not explain this choice. [Inferred: likely done to keep the module-level imports pefile-free, but the practical effect is the same since this function is always called.]

```python
    results: list[SectionEntropy] = []

    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        v_size = section.Misc_VirtualSize
        r_size = section.SizeOfRawData

        offset = section.PointerToRawData
        section_data = raw[offset : offset + r_size]
```

Iterates pefile's section objects and slices the raw bytes for each section using `PointerToRawData` and `SizeOfRawData`.

```python
        if r_size >= MIN_RAW_SIZE:
            entropy = _shannon_entropy(section_data)
        else:
            entropy = 0.0
```

Only computes entropy for sections with sufficient data. Tiny sections (BSS, padding) get 0.0.

```python
        is_packed = entropy > ENTROPY_PACKED_THRESHOLD and r_size >= MIN_RAW_SIZE

        has_mismatch = False
        if r_size > 0 and v_size > 0:
            ratio = v_size / r_size
            has_mismatch = ratio >= SIZE_MISMATCH_RATIO
```

Two independent checks: high entropy and size mismatch. The size mismatch check guards against division by zero.

```python
        detail_parts = []
        if r_size < MIN_RAW_SIZE:
            detail_parts.append(
                f"Raw size ({r_size}B) below minimum threshold "
                f"({MIN_RAW_SIZE}B) — entropy not meaningful."
            )
        else:
            detail_parts.append(f"Entropy: {entropy:.4f} / 8.0")
            if is_packed:
                detail_parts.append(
                    f"  → ABOVE packed threshold ({ENTROPY_PACKED_THRESHOLD}) — "
                    f"section likely contains compressed or encrypted data."
                )

        if has_mismatch:
            ratio = v_size / r_size
            detail_parts.append(
                f"  → Size mismatch: virtual ({v_size}B) is {ratio:.1f}× "
                f"raw ({r_size}B) — packing indicator."
            )
```

Builds a human-readable detail string. Note: `ratio` is computed twice (line 146 and line 165) when `has_mismatch` is true. This is harmless but could be DRYer.

```python
        results.append(SectionEntropy(
            name=name, entropy=round(entropy, 4),
            raw_size=r_size, virtual_size=v_size,
            is_packed=is_packed, has_size_mismatch=has_mismatch,
            detail="\n".join(detail_parts),
        ))

    pe.close()

    packed = [s for s in results if s.is_packed]
    mismatched = [s for s in results if s.has_size_mismatch]

    return EntropyAnalysis(
        sections=results, packed_sections=packed,
        mismatch_sections=mismatched,
        overall_suspicious=bool(packed or mismatched),
    )
```

Rounds entropy to 4 decimal places for display consistency. Closes the pefile instance. Builds the filtered lists and returns the aggregate result.

Note: the `sections_info` parameter is accepted but not used. The function gets section data directly from pefile. This parameter exists because `main.py:56-60` constructs it from the PE parser's output, but the function ignores it and re-parses with pefile. This is a design inconsistency — the parameter could be removed, or the function could use it instead of creating a second pefile instance.
