"""
output/printer.py — Terminal output formatting for analysis results.

This module is the ONLY place that calls `print()`.  Every analyzer
function returns plain data (dataclasses / dicts); this module formats
that data into readable terminal output.

Two output modes:
  1. `print_full_analysis()` — Detailed breakdown for the `analyze`
     subcommand: file info → PE summary → findings → verdict.
  2. `print_batch_line()` — Single summary line for the `batch`
     subcommand: filename, verdict band, score.

No external formatting libraries (rich, colorama) — just plain text with
simple indentation and separator lines.
"""

from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis
from analyzer.static.entropy import EntropyAnalysis
from analyzer.static.strings import StringsAnalysis
from analyzer.static.yara_scan import YaraScanResult
from analyzer.scoring.verdict import Verdict


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

# Width of the separator lines.
LINE_WIDTH = 72


def _separator(char: str = "=") -> str:
    """Return a full-width separator line."""
    return char * LINE_WIDTH


def _header(title: str) -> str:
    """Return a section header with surrounding separators."""
    return f"\n{_separator('-')}\n  {title}\n{_separator('-')}"


def _indent(text: str, level: int = 1) -> str:
    """Indent every line of `text` by `level` × 4 spaces."""
    prefix = "    " * level
    return "\n".join(prefix + line for line in text.split("\n"))


def _format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string.

    Examples: 1234 → '1,234 bytes (1.2 KB)'
    """
    if size_bytes < 1024:
        return f"{size_bytes:,} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
    else:
        return f"{size_bytes:,} bytes ({size_bytes / (1024*1024):.1f} MB)"


# ---------------------------------------------------------------------------
# Full analysis output (for the 'analyze' subcommand)
# ---------------------------------------------------------------------------

def print_full_analysis(
    fingerprint: FileFingerprint,
    pe_analysis: PEAnalysis,
    entropy: EntropyAnalysis,
    strings: StringsAnalysis,
    yara_result: YaraScanResult,
    verdict: Verdict,
    verbose: bool = False,
) -> None:
    """Print the complete analysis report to the terminal.

    Output order (per spec):
      1. File info (name, size, hashes, confirmed type)
      2. PE summary (architecture, timestamp, section table with entropy)
      3. Findings (suspicious imports, packing flags, strings, YARA)
      4. Verdict LAST (score, band, reasons)
    """
    print(f"\n{_separator('=')}")
    print(f"  PE-Sentinel — Static PE Analysis Report")
    print(_separator("="))

    # ── 1. File Information ─────────────────────────────────────────────
    print(_header("FILE INFORMATION"))
    print(f"    File Name : {fingerprint.file_name}")
    print(f"    File Path : {fingerprint.file_path}")
    print(f"    File Size : {_format_size(fingerprint.file_size)}")
    print(f"    SHA-256   : {fingerprint.sha256}")
    print(f"    MD5       : {fingerprint.md5}")
    print(f"    PE Valid  : {'Yes' if fingerprint.is_pe else 'No'}")
    print(f"    Detail    : {fingerprint.pe_validation_detail}")

    # ── 2. PE Summary ───────────────────────────────────────────────────
    print(_header("PE SUMMARY"))
    print(f"    Architecture    : {pe_analysis.machine} (0x{pe_analysis.machine_hex:04X})")
    print(f"    Compile Time    : {pe_analysis.compile_time}")
    print(f"    Digital Sig     : {'Present' if pe_analysis.has_signature else 'Not present'}")
    print(f"    Signature Note  : {pe_analysis.signature_detail}")
    print(f"    Total Imports   : {len(pe_analysis.imports)}")
    print(f"    Total Exports   : {len(pe_analysis.exports)}")

    # Section table.
    print(f"\n    {'Section':<12} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8}  Flags")
    print(f"    {'-'*12} {'-'*10} {'-'*10} {'-'*8}  {'-'*24}")
    for sec_entropy in entropy.sections:
        # Find the matching section in pe_analysis for the flags string.
        flags = ""
        for pe_sec in pe_analysis.sections:
            if pe_sec.name == sec_entropy.name:
                flags = pe_sec.characteristics_str
                break

        packed_marker = " [PACKED!]" if sec_entropy.is_packed else ""
        mismatch_marker = " [SIZE-MISMATCH]" if sec_entropy.has_size_mismatch else ""

        print(
            f"    {sec_entropy.name:<12} "
            f"{sec_entropy.virtual_size:>10,} "
            f"{sec_entropy.raw_size:>10,} "
            f"{sec_entropy.entropy:>8.4f}"
            f"  {flags}{packed_marker}{mismatch_marker}"
        )

    # ── 3. Findings ─────────────────────────────────────────────────────

    # --- 3a. Suspicious imports ---
    print(_header("SUSPICIOUS IMPORTS"))
    if pe_analysis.suspicious_imports:
        print(f"    Found {len(pe_analysis.suspicious_imports)} suspicious API import(s):\n")
        for imp in pe_analysis.suspicious_imports:
            print(f"    [!] {imp.dll} :: {imp.function}")
            print(f"        Reason: {imp.suspicion_reason}")
    else:
        print("    No suspicious API imports detected.")

    # --- 3b. Suspicious import combinations ---
    if pe_analysis.suspicious_combos:
        print(f"\n    Suspicious API combinations detected:\n")
        for combo in pe_analysis.suspicious_combos:
            funcs = " + ".join(combo.functions)
            print(f"    [!!] {funcs}")
            print(f"         {combo.description}")

    # --- 3c. Packing indicators ---
    print(_header("PACKING INDICATORS"))
    if entropy.overall_suspicious:
        if entropy.packed_sections:
            print(f"    {len(entropy.packed_sections)} section(s) with high entropy (likely packed):\n")
            for sec in entropy.packed_sections:
                print(f"    [!] '{sec.name}' — entropy {sec.entropy:.4f} "
                      f"(threshold: 7.2)")
        if entropy.mismatch_sections:
            print(f"\n    {len(entropy.mismatch_sections)} section(s) with "
                  f"virtual/raw size mismatch:\n")
            for sec in entropy.mismatch_sections:
                ratio = sec.virtual_size / sec.raw_size if sec.raw_size > 0 else 0
                print(f"    [!] '{sec.name}' — virtual {sec.virtual_size:,}B vs "
                      f"raw {sec.raw_size:,}B ({ratio:.1f}×)")
    else:
        print("    No packing indicators detected.")

    # --- 3d. Suspicious strings ---
    print(_header("SUSPICIOUS STRINGS"))
    print(f"    Total strings extracted: {strings.total_strings_extracted:,} "
          f"(ASCII: {strings.ascii_count:,}, UTF-16: {strings.utf16_count:,})")

    if strings.matches:
        print(f"    Suspicious pattern matches: {len(strings.matches)}\n")

        # Group by pattern type.
        for pattern_name, count in sorted(strings.match_summary.items()):
            print(f"    [{pattern_name}] — {count} match(es):")
            # Show up to 5 examples per category, or all in verbose mode.
            category_matches = [m for m in strings.matches
                                if m.pattern_name == pattern_name]
            limit = len(category_matches) if verbose else 5
            for m in category_matches[:limit]:
                text = m.matched_text
                if len(text) > 100:
                    text = text[:97] + "..."
                print(f"        \"{text}\"  ({m.encoding})")
            if len(category_matches) > limit:
                print(f"        ... and {len(category_matches) - limit} more "
                      f"(use --verbose to see all)")
            print()
    else:
        print("    No suspicious string patterns detected.")

    # --- 3e. YARA matches ---
    print(_header("YARA SCAN RESULTS"))
    if not yara_result.yara_available:
        print("    [WARN] yara-python is not installed — YARA scanning skipped.")
    elif yara_result.errors:
        for err in yara_result.errors:
            print(f"    [ERROR] {err}")
    else:
        print(f"    Rules loaded  : {yara_result.rules_loaded}")
        print(f"    Rule files    : {len(yara_result.rule_files)}")

        if yara_result.matches:
            print(f"    Matches found : {len(yara_result.matches)}\n")
            for m in yara_result.matches:
                print(f"    [!] Rule: {m.rule_name}")
                if m.description:
                    print(f"        Description: {m.description}")
                if m.tags:
                    print(f"        Tags: {', '.join(m.tags)}")
                if verbose and m.meta:
                    for key, val in m.meta.items():
                        if key not in ("description", "desc"):
                            print(f"        {key}: {val}")
        else:
            print("    No YARA rules matched.")

    # ── 4. Verdict (LAST — so it's the final thing visible) ─────────────
    print(f"\n{_separator('=')}")
    print(f"  VERDICT")
    print(_separator("="))
    print(f"    Score : {verdict.score} / 100")
    print(f"    Band  : {verdict.band}")
    print()

    # Score breakdown by category.
    print("    Score Breakdown:")
    for category, points in sorted(verdict.breakdown.items()):
        if points > 0:
            bar = "#" * int(points)
            print(f"        {category:<24} {points:>5.1f}  {bar}")

    # Itemized reasons.
    print(f"\n    Reasons ({len(verdict.reasons)} finding(s)):")
    for reason in verdict.reasons:
        print(f"        [{reason.category}] (+{reason.points:.1f}) {reason.detail}")

    print(f"\n{_separator('=')}\n")


# ---------------------------------------------------------------------------
# Batch output (for the 'batch' subcommand)
# ---------------------------------------------------------------------------

def print_batch_header() -> None:
    """Print the column header for batch output."""
    print(f"\n{'File':<50} {'Verdict':<12} {'Score':>5}")
    print(f"{'-'*50} {'-'*12} {'-'*5}")


def print_batch_line(file_name: str, band: str, score: int) -> None:
    """Print a single summary line for one file in batch mode."""
    # Truncate long filenames to fit the column.
    display_name = file_name if len(file_name) <= 48 else file_name[:45] + "..."
    print(f"{display_name:<50} {band:<12} {score:>5}")


def print_batch_footer(total: int, clean: int, suspicious: int, malicious: int) -> None:
    """Print the summary footer for batch output."""
    print(f"{'-'*69}")
    print(f"Total: {total}  |  Clean: {clean}  |  "
          f"Suspicious: {suspicious}  |  Malicious: {malicious}")
    print()


def print_error(file_path: str, error_msg: str) -> None:
    """Print an error line for a file that couldn't be analyzed."""
    print(f"[ERROR] {file_path}: {error_msg}")
