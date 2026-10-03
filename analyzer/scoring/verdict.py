"""
scoring/verdict.py — Threat-score computation and verdict assignment.

Combines signals from all analysis modules into a single 0–100 score
using a transparent, explicitly-documented weighting scheme.

SCORING PHILOSOPHY
==================
The weights below were chosen to approximate how a human analyst triages
a PE binary.  The key principles:

  1. **No single signal should dominate.**  Even a binary that trips every
     YARA rule can't score above ~40 from YARA alone — other modules must
     corroborate.
  2. **Combinations matter more than individual hits.**  A binary that imports
     both WriteProcessMemory and CreateRemoteThread is far more suspicious
     than one that imports either alone.  Combo bonuses reflect this.
  3. **Packing is suspicious but not damning.**  Many legitimate installers
     use UPX.  Packing raises the score, but clean code + UPX should still
     land in the "suspicious" band, not "malicious."
  4. **Strings are noisy.**  A single IP address in a binary is common.
     We award small per-hit points but cap the total contribution.

SCORE BANDS
===========
   0–30   →  CLEAN        (normal, no significant indicators)
  31–60   →  SUSPICIOUS   (some indicators warrant further review)
  61–100  →  MALICIOUS    (strong indicators of malicious intent)
"""

from dataclasses import dataclass, field
from typing import Optional

from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis
from analyzer.static.entropy import EntropyAnalysis
from analyzer.static.strings import StringsAnalysis
from analyzer.static.yara_scan import YaraScanResult


# ---------------------------------------------------------------------------
# Weight constants — every number is documented so a reader can audit or
# adjust the scoring without reading the logic below.
# ---------------------------------------------------------------------------

# -- Suspicious imports --
# Each individual suspicious import adds this many points.
WEIGHT_SUSPICIOUS_IMPORT: float = 2.0
# Cap on total points from individual suspicious imports, so a binary
# that links 20 suspicious APIs doesn't automatically hit 40.
CAP_SUSPICIOUS_IMPORTS: float = 16.0

# -- Suspicious import combinations --
# Each matched combo (e.g. VirtualAllocEx + WriteProcessMemory +
# CreateRemoteThread) adds this many points ON TOP of individual import
# points.  Combos are the strongest import signal.
WEIGHT_IMPORT_COMBO: float = 8.0
CAP_IMPORT_COMBOS: float = 20.0

# -- Entropy / packing --
# Each section flagged as packed (entropy > 7.2) adds this.
WEIGHT_PACKED_SECTION: float = 6.0
# Each section with a virtual/raw size mismatch adds this.
WEIGHT_SIZE_MISMATCH: float = 4.0
# Combined cap for all packing indicators.
CAP_PACKING: float = 18.0

# -- YARA rule matches --
# Each YARA rule hit adds this.
WEIGHT_YARA_HIT: float = 10.0
# Cap so YARA alone can't push past "suspicious" into "malicious."
CAP_YARA: float = 30.0

# -- Suspicious strings --
# Each unique suspicious-string match (URL, IP, registry key, etc.)
WEIGHT_STRING_MATCH: float = 1.5
# Cap on total string-match contribution.
CAP_STRINGS: float = 12.0

# -- Authenticode signature --
# A missing signature is mildly suspicious (most legitimate software is
# signed).  This is a *bonus* added when there is NO signature.
WEIGHT_NO_SIGNATURE: float = 4.0

# -- Compile timestamp anomaly --
# A zeroed-out timestamp (epoch 0) or a timestamp in the far future
# suggests deliberate tampering.
WEIGHT_TIMESTAMP_ANOMALY: float = 3.0

# -- Exports in an .exe --
# DLLs normally export symbols; .exe files usually don't.  An .exe with
# exports can indicate a dual-purpose binary or DLL masquerading.
WEIGHT_EXE_WITH_EXPORTS: float = 3.0


# ---------------------------------------------------------------------------
# Band thresholds
# ---------------------------------------------------------------------------

BAND_CLEAN_MAX      = 30
BAND_SUSPICIOUS_MAX = 60
# Anything above 60 is MALICIOUS.


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScoringReason:
    """One specific reason that contributed to the score."""
    category: str      # e.g. "Suspicious Import", "Packing", "YARA"
    detail: str        # Human-readable finding, e.g. "Imports CreateRemoteThread"
    points: float      # How many points this reason contributed


@dataclass
class Verdict:
    """Final verdict for a PE file."""
    score: int                     # 0–100 (clamped)
    band: str                      # "CLEAN", "SUSPICIOUS", or "MALICIOUS"
    reasons: list[ScoringReason]   # Every finding that contributed points
    breakdown: dict[str, float]    # Category → total points (for summary)


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def compute_verdict(
    fingerprint: FileFingerprint,
    pe_analysis: PEAnalysis,
    entropy: EntropyAnalysis,
    strings: StringsAnalysis,
    yara_result: YaraScanResult,
) -> Verdict:
    """Combine all analysis signals into a scored verdict.

    Parameters
    ----------
    fingerprint : FileFingerprint
        File identity info (we use the filename to check for .exe exports).
    pe_analysis : PEAnalysis
        Import/export/section data.
    entropy : EntropyAnalysis
        Per-section entropy results.
    strings : StringsAnalysis
        Suspicious-string matches.
    yara_result : YaraScanResult
        YARA rule matches.

    Returns
    -------
    Verdict with score, band, and itemized reasons.
    """
    reasons: list[ScoringReason] = []
    raw_score: float = 0.0
    breakdown: dict[str, float] = {}

    # ── 1. Suspicious imports (individual) ──────────────────────────────
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

    # ── 2. Suspicious import combinations ───────────────────────────────
    combo_points = 0.0
    for combo in pe_analysis.suspicious_combos:
        pts = min(WEIGHT_IMPORT_COMBO, CAP_IMPORT_COMBOS - combo_points)
        if pts <= 0:
            break
        combo_points += pts
        funcs_str = " + ".join(combo.functions)
        reasons.append(ScoringReason(
            category="Import Combination",
            detail=f"{funcs_str} — {combo.description}",
            points=pts,
        ))
    raw_score += combo_points
    breakdown["Import Combinations"] = combo_points

    # ── 3. Packing indicators (entropy + size mismatch) ─────────────────
    packing_points = 0.0
    for sec in entropy.packed_sections:
        pts = min(WEIGHT_PACKED_SECTION, CAP_PACKING - packing_points)
        if pts <= 0:
            break
        packing_points += pts
        reasons.append(ScoringReason(
            category="Packing",
            detail=f"Section '{sec.name}' has high entropy ({sec.entropy:.2f}/8.0) "
                   f"— likely packed or encrypted.",
            points=pts,
        ))

    for sec in entropy.mismatch_sections:
        pts = min(WEIGHT_SIZE_MISMATCH, CAP_PACKING - packing_points)
        if pts <= 0:
            break
        packing_points += pts
        ratio = sec.virtual_size / sec.raw_size if sec.raw_size > 0 else 0
        reasons.append(ScoringReason(
            category="Packing",
            detail=f"Section '{sec.name}' virtual size ({sec.virtual_size}B) is "
                   f"{ratio:.1f}× raw size ({sec.raw_size}B) — packing indicator.",
            points=pts,
        ))
    raw_score += packing_points
    breakdown["Packing Indicators"] = packing_points

    # ── 4. YARA rule matches ────────────────────────────────────────────
    yara_points = 0.0
    for match in yara_result.matches:
        pts = min(WEIGHT_YARA_HIT, CAP_YARA - yara_points)
        if pts <= 0:
            break
        yara_points += pts
        desc = match.description or "(no description)"
        reasons.append(ScoringReason(
            category="YARA Rule",
            detail=f"Matched rule '{match.rule_name}': {desc}",
            points=pts,
        ))
    raw_score += yara_points
    breakdown["YARA Rules"] = yara_points

    # ── 5. Suspicious strings ───────────────────────────────────────────
    string_points = 0.0
    for match in strings.matches:
        pts = min(WEIGHT_STRING_MATCH, CAP_STRINGS - string_points)
        if pts <= 0:
            break
        string_points += pts
        # Truncate very long matched text for readability.
        text = match.matched_text
        if len(text) > 80:
            text = text[:77] + "..."
        reasons.append(ScoringReason(
            category="Suspicious String",
            detail=f"{match.pattern_name}: \"{text}\"",
            points=pts,
        ))
    raw_score += string_points
    breakdown["Suspicious Strings"] = string_points

    # ── 6. Missing Authenticode signature ───────────────────────────────
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

    # ── 7. Compile-timestamp anomaly ────────────────────────────────────
    # Timestamp = 0 (epoch) or > year 2030 is suspicious.
    ts = pe_analysis.compile_time_raw
    if ts == 0 or ts > 1893456000:  # 1893456000 = 2030-01-01 UTC
        raw_score += WEIGHT_TIMESTAMP_ANOMALY
        reasons.append(ScoringReason(
            category="Timestamp",
            detail=f"Compile timestamp is anomalous (raw=0x{ts:08X}): "
                   f"{'zeroed out' if ts == 0 else 'set to far future'}.",
            points=WEIGHT_TIMESTAMP_ANOMALY,
        ))
        breakdown["Timestamp Anomaly"] = WEIGHT_TIMESTAMP_ANOMALY
    else:
        breakdown["Timestamp Anomaly"] = 0.0

    # ── 8. Exports in an .exe file ──────────────────────────────────────
    is_exe = fingerprint.file_name.lower().endswith('.exe')
    if is_exe and pe_analysis.exports:
        raw_score += WEIGHT_EXE_WITH_EXPORTS
        reasons.append(ScoringReason(
            category="Exports",
            detail=f"EXE file exports {len(pe_analysis.exports)} symbol(s) — "
                   f"unusual for an executable.",
            points=WEIGHT_EXE_WITH_EXPORTS,
        ))
        breakdown["EXE Exports"] = WEIGHT_EXE_WITH_EXPORTS
    else:
        breakdown["EXE Exports"] = 0.0

    # ── Clamp to 0–100 ──────────────────────────────────────────────────
    final_score = max(0, min(100, int(round(raw_score))))

    # ── Assign band ─────────────────────────────────────────────────────
    if final_score <= BAND_CLEAN_MAX:
        band = "CLEAN"
    elif final_score <= BAND_SUSPICIOUS_MAX:
        band = "SUSPICIOUS"
    else:
        band = "MALICIOUS"

    return Verdict(
        score=final_score,
        band=band,
        reasons=reasons,
        breakdown=breakdown,
    )
