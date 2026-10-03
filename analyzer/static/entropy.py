"""
static/entropy.py — Shannon entropy analysis per PE section.

Shannon entropy measures the randomness/information density of data.
Normal compiled code typically has entropy in the 4.5–6.5 range.
Compressed or encrypted data (i.e. packed executables) pushes entropy
toward the theoretical maximum of 8.0 (for byte-level measurement).

This module:
  1. Computes per-section entropy using the standard Shannon formula.
  2. Flags sections above a configurable threshold (default 7.2) as
     likely-packed or encrypted.
  3. Flags large mismatches between virtual size and raw size, which is
     another classic packing indicator (the packer stores compressed data
     on disk and inflates it to a much larger region in memory).
"""

import math
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Tunables — these are deliberately exposed as module-level constants so
# a reader can see exactly what thresholds we use and adjust them.
# ---------------------------------------------------------------------------

# Entropy above this value (on a 0–8 scale) flags the section as "packed."
# 7.2 is a conservative choice: truly random data is ~8.0, and most packers
# (UPX, ASPack, Themida) produce output in the 7.0–7.9 range.
ENTROPY_PACKED_THRESHOLD: float = 7.2

# If virtual_size / raw_size exceeds this ratio, the section is flagged
# for a size mismatch.  A ratio of 3× means the section expands to at
# least three times its on-disk size when loaded — a strong packing hint.
SIZE_MISMATCH_RATIO: float = 3.0

# Minimum raw size to consider for entropy / size-mismatch checks.
# Sections with zero or tiny raw size are usually BSS (uninitialized data)
# and produce meaningless entropy values.
MIN_RAW_SIZE: int = 512


@dataclass
class SectionEntropy:
    """Entropy analysis result for one PE section."""
    name: str
    entropy: float             # Shannon entropy, 0.0 – 8.0
    raw_size: int
    virtual_size: int
    is_packed: bool            # True if entropy > threshold
    has_size_mismatch: bool    # True if vsize/rsize ratio is extreme
    detail: str                # Human-readable explanation


@dataclass
class EntropyAnalysis:
    """Complete entropy analysis across all sections of a PE."""
    sections: list[SectionEntropy]
    packed_sections: list[SectionEntropy]    # Subset flagged as packed
    mismatch_sections: list[SectionEntropy]  # Subset flagged for size mismatch
    overall_suspicious: bool                 # True if *any* section is flagged


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence on a 0–8 scale.

    The formula:  H = -Σ p(x) · log₂(p(x))  for each distinct byte value x.

    An entropy of 0 means perfectly uniform (all bytes identical).
    An entropy of 8 means perfectly random (every byte value equally likely).
    """
    if not data:
        return 0.0

    length = len(data)

    # Count occurrences of each byte value (0–255).
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        # p(x) = count / length
        probability = count / length
        # Shannon formula: subtract p * log2(p)
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_entropy(file_path: str, sections_info: list[dict]) -> EntropyAnalysis:
    """Compute entropy for each PE section.

    Parameters
    ----------
    file_path : str
        Path to the PE file on disk.
    sections_info : list[dict]
        Section metadata from pe_parser, each dict must have keys:
        'name', 'virtual_size', 'raw_size'.  We use this to know
        where each section lives in the file, but we read raw bytes
        ourselves for the entropy computation.

    Returns
    -------
    EntropyAnalysis with per-section results and aggregate flags.
    """
    # Read the entire file once.
    with open(file_path, 'rb') as fh:
        raw = fh.read()

    # We'll use pefile briefly just to get accurate section offsets.
    # (We could calculate them manually from section headers, but pefile
    #  already did the hard work during pe_parser.analyze_pe.)
    import pefile
    pe = pefile.PE(file_path)

    results: list[SectionEntropy] = []

    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        v_size = section.Misc_VirtualSize
        r_size = section.SizeOfRawData

        # Extract the raw bytes for this section from the file.
        offset = section.PointerToRawData
        section_data = raw[offset : offset + r_size]

        # Compute entropy, but only if the section has meaningful data.
        if r_size >= MIN_RAW_SIZE:
            entropy = _shannon_entropy(section_data)
        else:
            entropy = 0.0

        # --- Packed check ---
        is_packed = entropy > ENTROPY_PACKED_THRESHOLD and r_size >= MIN_RAW_SIZE

        # --- Size mismatch check ---
        # Only meaningful when raw_size is nonzero (avoid division by zero).
        has_mismatch = False
        if r_size > 0 and v_size > 0:
            ratio = v_size / r_size
            has_mismatch = ratio >= SIZE_MISMATCH_RATIO

        # Build a human-readable detail string.
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

        results.append(SectionEntropy(
            name=name,
            entropy=round(entropy, 4),
            raw_size=r_size,
            virtual_size=v_size,
            is_packed=is_packed,
            has_size_mismatch=has_mismatch,
            detail="\n".join(detail_parts),
        ))

    pe.close()

    packed = [s for s in results if s.is_packed]
    mismatched = [s for s in results if s.has_size_mismatch]

    return EntropyAnalysis(
        sections=results,
        packed_sections=packed,
        mismatch_sections=mismatched,
        overall_suspicious=bool(packed or mismatched),
    )
