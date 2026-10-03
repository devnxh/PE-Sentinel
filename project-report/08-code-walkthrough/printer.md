# Code Walkthrough: analyzer/output/printer.py

- **Purpose**: Terminal output formatting. The only module that calls `print()`. Formats analysis results for both `analyze` and `batch` subcommands.
- **Inputs**: All analysis dataclasses plus verbose flag.
- **Outputs**: Formatted text to stdout.
- **Dependencies**: All analysis dataclass types (for type annotations).
- **Callers**: `main.py:97, 125, 135, 142, 148`.
- **Callees**: None (calls only `print()`).

---

## Lines 1-16: Module docstring

Explicitly states this is "the ONLY place that calls print()" and documents the two output modes.

## Lines 18-23: Imports

```python
from analyzer.fingerprint import FileFingerprint
from analyzer.static.pe_parser import PEAnalysis
from analyzer.static.entropy import EntropyAnalysis
from analyzer.static.strings import StringsAnalysis
from analyzer.static.yara_scan import YaraScanResult
from analyzer.scoring.verdict import Verdict
```

Imports all six dataclass types for type annotations in function signatures.

## Lines 31-60: Formatting helpers

```python
LINE_WIDTH = 72

def _separator(char: str = "=") -> str:
    return char * LINE_WIDTH

def _header(title: str) -> str:
    return f"\n{_separator('-')}\n  {title}\n{_separator('-')}"

def _indent(text: str, level: int = 1) -> str:
    prefix = "    " * level
    return "\n".join(prefix + line for line in text.split("\n"))

def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes:,} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
    else:
        return f"{size_bytes:,} bytes ({size_bytes / (1024*1024):.1f} MB)"
```

`LINE_WIDTH` of 72 matches traditional terminal width conventions. `_separator` generates full-width lines. `_header` creates section headers with dashes. `_indent` adds 4-space indentation per level. `_format_size` provides human-readable byte counts with appropriate units (bytes, KB, MB).

## Lines 67-240: `print_full_analysis()`

The main output function. Prints five sections in order: file info, PE summary, findings, YARA results, verdict.

### Section 1: File Information (lines 84-96)

```python
    print(f"\n{_separator('=')}")
    print(f"  PE-Sentinel — Static PE Analysis Report")
    print(_separator("="))

    print(_header("FILE INFORMATION"))
    print(f"    File Name : {fingerprint.file_name}")
    print(f"    File Path : {fingerprint.file_path}")
    print(f"    File Size : {_format_size(fingerprint.file_size)}")
    print(f"    SHA-256   : {fingerprint.sha256}")
    print(f"    MD5       : {fingerprint.md5}")
    print(f"    PE Valid  : {'Yes' if fingerprint.is_pe else 'No'}")
    print(f"    Detail    : {fingerprint.pe_validation_detail}")
```

Displays all FileFingerprint fields in a fixed-width aligned format.

### Section 2: PE Summary with section table (lines 98-127)

```python
    print(f"\n    {'Section':<12} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8}  Flags")
    print(f"    {'-'*12} {'-'*10} {'-'*10} {'-'*8}  {'-'*24}")
    for sec_entropy in entropy.sections:
        flags = ""
        for pe_sec in pe_analysis.sections:
            if pe_sec.name == sec_entropy.name:
                flags = pe_sec.characteristics_str
                break
```

Prints a formatted section table. Joins entropy data with PE parser section data by matching on section name. The inner loop (lines 113-116) is O(n*m) but both lists are small (typically 5-10 sections).

### Section 3: Findings — imports, combos, packing, strings (lines 129-192)

Each finding category follows the same pattern: print header, check if findings exist, print details or "no findings" message. In verbose mode, all string matches are shown; in normal mode, up to 5 per category with a "use --verbose" hint.

### Section 4: YARA results (lines 194-218)

```python
    if not yara_result.yara_available:
        print("    [WARN] yara-python is not installed — YARA scanning skipped.")
    elif yara_result.errors:
        for err in yara_result.errors:
            print(f"    [ERROR] {err}")
    else:
        ...
```

Three-way branch: yara unavailable, yara errors, or normal results. In verbose mode, YARA rule metadata is shown (lines 213-216).

### Section 5: Verdict (lines 220-240)

```python
    print(f"    Score : {verdict.score} / 100")
    print(f"    Band  : {verdict.band}")

    print("    Score Breakdown:")
    for category, points in sorted(verdict.breakdown.items()):
        if points > 0:
            bar = "#" * int(points)
            print(f"        {category:<24} {points:>5.1f}  {bar}")

    print(f"\n    Reasons ({len(verdict.reasons)} finding(s)):")
    for reason in verdict.reasons:
        print(f"        [{reason.category}] (+{reason.points:.1f}) {reason.detail}")
```

The verdict section appears last so it is the final thing visible in the terminal. The breakdown uses a simple bar chart (hash characters). Each reason is printed with its category and point contribution.

## Lines 247-270: Batch output functions

```python
def print_batch_header() -> None:
    print(f"\n{'File':<50} {'Verdict':<12} {'Score':>5}")
    print(f"{'-'*50} {'-'*12} {'-'*5}")

def print_batch_line(file_name: str, band: str, score: int) -> None:
    display_name = file_name if len(file_name) <= 48 else file_name[:45] + "..."
    print(f"{display_name:<50} {band:<12} {score:>5}")

def print_batch_footer(total: int, clean: int, suspicious: int, malicious: int) -> None:
    print(f"{'-'*69}")
    print(f"Total: {total}  |  Clean: {clean}  |  "
          f"Suspicious: {suspicious}  |  Malicious: {malicious}")
    print()

def print_error(file_path: str, error_msg: str) -> None:
    print(f"[ERROR] {file_path}: {error_msg}")
```

Fixed-width columns for batch output. Long filenames are truncated to 45 chars with "..." suffix.
