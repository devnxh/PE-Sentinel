# Code Walkthrough: analyzer/static/strings.py

- **Purpose**: Extracts printable strings (ASCII and UTF-16LE) from PE files and scans them for suspicious patterns (IPs, URLs, registry paths, shell invocations, PowerShell keywords, Base64 blobs).
- **Inputs**: File path (string).
- **Outputs**: `StringsAnalysis` dataclass.
- **Dependencies**: `re`, `dataclasses`.
- **Callers**: `main.py:63`.
- **Callees**: None (leaf module).

---

## Lines 1-16: Module docstring

Lists the five pattern categories and notes that both ASCII and UTF-16LE encodings are extracted.

## Lines 18-19: Imports

```python
import re
from dataclasses import dataclass, field
```

`re` for pattern matching. `field` is imported but unused.

## Lines 28-33: Configuration constants

```python
MIN_STRING_LENGTH: int = 5
MAX_STRINGS_RETURNED: int = 5000
```

`MIN_STRING_LENGTH` of 5 avoids false positives from random byte sequences (`README.md:379-380`). `MAX_STRINGS_RETURNED` of 5000 caps memory usage for large binaries.

## Lines 42-103: SUSPICIOUS_PATTERNS list

```python
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("IPv4 Address", re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}...\b')),
    ("URL", re.compile(r'https?://[^\s\x00"\'<>]{4,}|ftp://...', re.IGNORECASE)),
    ("Registry Path", re.compile(r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|...)\\...', re.IGNORECASE)),
    ("Shell Invocation", re.compile(r'(?:cmd(?:\.exe)?|powershell...)...', re.IGNORECASE)),
    ("PowerShell Keyword", re.compile(r'(?:-(?:enc(?:odedcommand)?|...))...', re.IGNORECASE)),
    ("Base64 Blob", re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')),
]
```

Six compiled regex patterns. Each is a tuple of (label, compiled pattern). Patterns are compiled once at module load time for performance. Key design decisions:
- IPv4 pattern uses word boundaries and proper octet validation (0-255).
- URL pattern matches http, https, and ftp schemes.
- Base64 minimum length of 40 chars avoids false positives on GUIDs and short identifiers.
- PowerShell detection is split into two patterns: one for executable references with flags, one for high-confidence keywords.

## Lines 107-110: BENIGN_IPS set

```python
BENIGN_IPS: set[str] = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "1.0.0.0", "0.0.0.1",
}
```

IPs that appear in almost every binary (loopback, broadcast, version-info artifacts) and should not be flagged. These are filtered during scanning, not in the regex itself.

## Lines 117-132: Data classes

```python
@dataclass
class StringMatch:
    pattern_name: str
    matched_text: str
    encoding: str

@dataclass
class StringsAnalysis:
    total_strings_extracted: int
    ascii_count: int
    utf16_count: int
    matches: list[StringMatch]
    match_summary: dict[str, int]
```

`StringMatch` holds one pattern hit. `StringsAnalysis` aggregates all results plus a summary count per pattern category.

## Lines 139-148: `_extract_ascii_strings()`

```python
def _extract_ascii_strings(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    return [m.group().decode('ascii', errors='replace') for m in pattern.finditer(data)]
```

Matches contiguous runs of printable ASCII bytes (0x20-0x7E). The regex is dynamically constructed with the minimum length parameter. Same heuristic as the Unix `strings` utility. `errors='replace'` is defensive — all matched bytes are already in the ASCII printable range.

## Lines 151-169: `_extract_utf16le_strings()`

```python
def _extract_utf16le_strings(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
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
```

Matches sequences of (printable byte, null byte) pairs, which is the UTF-16LE encoding of ASCII-range characters. Windows APIs use UTF-16LE extensively, so PE files contain many wide strings. The try/except is defensive against malformed encodings.

## Lines 176-236: `analyze_strings()`

```python
def analyze_strings(file_path: str) -> StringsAnalysis:
    with open(file_path, 'rb') as fh:
        data = fh.read()
```

Reads the entire file into memory.

```python
    ascii_strings  = _extract_ascii_strings(data)
    utf16_strings  = _extract_utf16le_strings(data)

    all_strings_ascii  = ascii_strings[:MAX_STRINGS_RETURNED]
    all_strings_utf16  = utf16_strings[:MAX_STRINGS_RETURNED]
```

Extracts both string types and caps each list at 5000 entries.

```python
    matches: list[StringMatch] = []
    seen: set[tuple[str, str]] = set()

    def _scan(strings: list[str], encoding: str) -> None:
        for s in strings:
            for pattern_name, regex in SUSPICIOUS_PATTERNS:
                for m in regex.finditer(s):
                    text = m.group()

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
```

Nested function `_scan` iterates all strings and applies all patterns. Deduplicates by `(pattern_name, matched_text)` tuple. Filters out benign IPs. The `seen` set prevents the same finding from appearing twice when the same text exists in both ASCII and UTF-16LE strings.

```python
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
```

Builds a summary count per pattern category. Note that `total_strings_extracted` uses the uncapped counts (from `ascii_strings` and `utf16_strings`), while the pattern scanning uses the capped lists. This means the extracted count is accurate even though only the first 5000 strings of each type are scanned for patterns.
