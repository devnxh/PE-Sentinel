"""
static/strings.py — Suspicious string extraction and pattern matching.

Scans a PE file's raw bytes for printable strings and then applies regex
patterns to identify indicators of compromise (IOCs) and suspicious
behaviours:

  - IP addresses (IPv4)
  - URLs (http/https/ftp)
  - Windows registry paths (HKEY_...)
  - Command-shell invocation patterns (cmd.exe, powershell, etc.)
  - Long Base64-looking blobs (potential encoded payloads)

The module extracts both ASCII and UTF-16LE strings, since Windows
binaries commonly use both encodings.
"""

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum string length to extract.  Short strings produce too many
# false positives — 5 characters is a practical lower bound.
MIN_STRING_LENGTH: int = 5

# Maximum number of raw strings to return (to avoid flooding output
# on binaries with tens of thousands of strings).
MAX_STRINGS_RETURNED: int = 5000


# ---------------------------------------------------------------------------
# Regex patterns for suspicious content
#
# Each pattern has a human-readable label used in findings output.
# We compile them once at module load time for performance.
# ---------------------------------------------------------------------------

SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "IPv4 Address",
        # Matches dotted-quad IPv4 addresses like 192.168.1.1.
        # Uses word boundaries to avoid matching version numbers inside
        # longer tokens.  Excludes common benign addresses (0.0.0.0,
        # 127.0.0.1) in the filtering step, not the regex itself.
        re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
    ),
    (
        "URL",
        # Matches http://, https://, and ftp:// URLs.
        re.compile(
            r'https?://[^\s\x00"\'<>]{4,}|ftp://[^\s\x00"\'<>]{4,}',
            re.IGNORECASE,
        ),
    ),
    (
        "Registry Path",
        # Matches Windows registry hive paths.  These appear when malware
        # reads or writes persistence keys (e.g. Run, RunOnce).
        re.compile(
            r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|'
            r'CURRENT_CONFIG)\\[^\s\x00"\']{2,}',
            re.IGNORECASE,
        ),
    ),
    (
        "Shell Invocation",
        # Matches references to cmd.exe, powershell.exe, or common
        # PowerShell cmdlets / flags that suggest scripted execution.
        re.compile(
            r'(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)'
            r'(?:\s+[/\-][^\s\x00]{1,})*',
            re.IGNORECASE,
        ),
    ),
    (
        "PowerShell Keyword",
        # Catches specific PowerShell patterns like -EncodedCommand,
        # Invoke-Expression, IEX, DownloadString — high-confidence IOCs.
        re.compile(
            r'(?:-(?:enc(?:odedcommand)?|nop(?:rofile)?|w(?:indowstyle)?\s+hidden))|'
            r'(?:Invoke-(?:Expression|WebRequest|Command))|'
            r'(?:IEX\s*\()|'
            r'(?:DownloadString|DownloadFile|Net\.WebClient)',
            re.IGNORECASE,
        ),
    ),
    (
        "Base64 Blob",
        # Matches long runs of Base64-legal characters (A-Z, a-z, 0-9, +, /)
        # ending with optional padding.  The minimum length of 40 avoids
        # false-positiving on short legitimate Base64 (e.g. GUIDs).
        re.compile(
            r'[A-Za-z0-9+/]{40,}={0,2}'
        ),
    ),
]

# Benign IP addresses that appear in almost every binary and should NOT
# be flagged as suspicious.
BENIGN_IPS: set[str] = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "1.0.0.0", "0.0.0.1",   # Common PE version-info artefacts
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class StringMatch:
    """A single pattern match found in the binary's strings."""
    pattern_name: str   # e.g. "IPv4 Address", "URL"
    matched_text: str   # The actual text that matched
    encoding: str       # 'ascii' or 'utf-16le'


@dataclass
class StringsAnalysis:
    """Complete strings-analysis result."""
    total_strings_extracted: int          # How many raw strings we found
    ascii_count: int                      # Strings from ASCII extraction
    utf16_count: int                      # Strings from UTF-16LE extraction
    matches: list[StringMatch]            # Suspicious pattern hits
    match_summary: dict[str, int]         # pattern_name → count


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_ascii_strings(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
    """Extract printable ASCII strings of at least `min_len` characters.

    A "printable ASCII string" is a contiguous run of bytes in the range
    0x20–0x7E (space through tilde).  This is the same heuristic used by
    the classic Unix `strings` utility.
    """
    # The regex matches runs of printable ASCII characters.
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    return [m.group().decode('ascii', errors='replace') for m in pattern.finditer(data)]


def _extract_utf16le_strings(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
    """Extract UTF-16LE strings (common in Windows binaries).

    Windows APIs use wide (UTF-16LE) strings extensively.  In a PE file,
    these appear as sequences of (printable byte, 0x00) pairs.  We look
    for runs of such pairs and decode them.
    """
    # Pattern: printable ASCII byte followed by a null byte, repeated.
    pattern = re.compile(
        rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'
    )
    results = []
    for m in pattern.finditer(data):
        try:
            decoded = m.group().decode('utf-16-le', errors='replace')
            results.append(decoded)
        except UnicodeDecodeError:
            continue
    return results


# ---------------------------------------------------------------------------
# Public analysis function
# ---------------------------------------------------------------------------

def analyze_strings(file_path: str) -> StringsAnalysis:
    """Extract strings from a PE file and scan for suspicious patterns.

    Parameters
    ----------
    file_path : str
        Path to the PE file.

    Returns
    -------
    StringsAnalysis with extracted string counts and pattern matches.
    """
    with open(file_path, 'rb') as fh:
        data = fh.read()

    # --- Step 1: Extract raw strings ---
    ascii_strings  = _extract_ascii_strings(data)
    utf16_strings  = _extract_utf16le_strings(data)

    # Cap the total to avoid memory issues with huge binaries.
    all_strings_ascii  = ascii_strings[:MAX_STRINGS_RETURNED]
    all_strings_utf16  = utf16_strings[:MAX_STRINGS_RETURNED]

    # --- Step 2: Scan for suspicious patterns ---
    matches: list[StringMatch] = []
    seen: set[tuple[str, str]] = set()  # Deduplicate (pattern_name, matched_text)

    def _scan(strings: list[str], encoding: str) -> None:
        for s in strings:
            for pattern_name, regex in SUSPICIOUS_PATTERNS:
                for m in regex.finditer(s):
                    text = m.group()

                    # Filter out benign IPs.
                    if pattern_name == "IPv4 Address" and text in BENIGN_IPS:
                        continue

                    key = (pattern_name, text)
                    if key not in seen:
                        seen.add(key)
                        matches.append(StringMatch(
                            pattern_name=pattern_name,
                            matched_text=text,
                            encoding=encoding,
                        ))

    _scan(all_strings_ascii, "ascii")
    _scan(all_strings_utf16, "utf-16le")

    # --- Step 3: Build summary ---
    summary: dict[str, int] = {}
    for match in matches:
        summary[match.pattern_name] = summary.get(match.pattern_name, 0) + 1

    return StringsAnalysis(
        total_strings_extracted=len(ascii_strings) + len(utf16_strings),
        ascii_count=len(ascii_strings),
        utf16_count=len(utf16_strings),
        matches=matches,
        match_summary=summary,
    )
