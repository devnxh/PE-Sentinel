# 07 — API and Interfaces

## CLI Interface

PE-Sentinel exposes two subcommands via `argparse` (`main.py:158-213`).

### `analyze` — Single File Analysis

```
python main.py analyze <file_path> [--verbose]
```

| Argument | Type | Required | Description | Source |
|----------|------|----------|-------------|--------|
| `file_path` | positional string | Yes | Path to the PE file (.exe/.dll) | `main.py:180-183` |
| `--verbose` / `-v` | flag | No (default: False) | Show extended details | `main.py:184-189` |

**Handler**: `cmd_analyze(args)` at `main.py:74-98`.

**Behavior**:
- Validates file exists (`main.py:81-83`). Prints error and returns 1 if not found.
- Runs full pipeline (`main.py:86-88`). On `ValueError` (not a PE): prints error, returns 1.
- On any other exception: prints error, returns 1.
- On success: prints full report to stdout, returns 0.

**Output**: Full analysis report to stdout. Sections: FILE INFORMATION, PE SUMMARY (with section table), SUSPICIOUS IMPORTS, PACKING INDICATORS, SUSPICIOUS STRINGS, YARA SCAN RESULTS, VERDICT (score, band, breakdown, itemized reasons).

**Exit codes**: 0 = success, 1 = error.

### `batch` — Directory Analysis

```
python main.py batch <folder_path>
```

| Argument | Type | Required | Description | Source |
|----------|------|----------|-------------|--------|
| `folder_path` | positional string | Yes | Path to directory containing PE files | `main.py:196-199` |

**Handler**: `cmd_batch(args)` at `main.py:101-155`.

**Behavior**:
- Validates directory exists (`main.py:109-111`). Prints error and returns 1 if not found.
- Lists all files in directory, sorted alphabetically, non-recursive (`main.py:113-119`).
- For each file: runs full pipeline. On success: prints one summary line. On `ValueError`: silently skips. On other exception: prints error line.
- Prints footer with totals.

**Output**: Table format — one line per PE file with filename (max 48 chars), verdict band, score. Footer with counts.

**Exit codes**: 0 = all files succeeded, 1 = any errors occurred.

### No subcommand

If no subcommand is provided, prints help text and returns 1 (`main.py:203-205`).

## Public Python Functions

### `fingerprint_file(file_path: str) -> FileFingerprint`

- **Location**: `analyzer/fingerprint.py:100-124`
- **Purpose**: Read a file from disk and produce identity/validation data.
- **Input**: `file_path` — path to any file.
- **Output**: `FileFingerprint` dataclass.
- **Raises**: `FileNotFoundError` if file does not exist. `PermissionError` if file is not readable.
- **Side effects**: Reads entire file into memory.
- **Callers**: `main.py:43` via `_analyze_single_file()`.

### `analyze_pe(file_path: str) -> PEAnalysis`

- **Location**: `analyzer/static/pe_parser.py:214-344`
- **Purpose**: Parse PE headers, imports, exports, and flag suspicious APIs.
- **Input**: `file_path` — path to a validated PE file.
- **Output**: `PEAnalysis` dataclass.
- **Raises**: `pefile.PEFormatError` if pefile cannot parse the file.
- **Side effects**: Opens and reads the file via pefile. Calls `pe.close()` at line 330.
- **Callers**: `main.py:51`.

### `analyze_entropy(file_path: str, sections_info: list[dict]) -> EntropyAnalysis`

- **Location**: `analyzer/static/entropy.py:95-191`
- **Purpose**: Compute per-section Shannon entropy and flag packing indicators.
- **Input**: `file_path` — path to PE file. `sections_info` — list of dicts with keys `name`, `virtual_size`, `raw_size`.
- **Output**: `EntropyAnalysis` dataclass.
- **Side effects**: Reads entire file into memory. Creates a second `pefile.PE` instance (`entropy.py:120`).
- **Callers**: `main.py:60`.

### `analyze_strings(file_path: str) -> StringsAnalysis`

- **Location**: `analyzer/static/strings.py:176-236`
- **Purpose**: Extract printable strings and scan for suspicious patterns.
- **Input**: `file_path` — path to PE file.
- **Output**: `StringsAnalysis` dataclass.
- **Side effects**: Reads entire file into memory.
- **Callers**: `main.py:63`.

### `scan_with_yara(file_path: str, rules_dir: str) -> YaraScanResult`

- **Location**: `analyzer/static/yara_scan.py:80-185`
- **Purpose**: Discover YARA rules, compile them, and scan the file.
- **Input**: `file_path` — path to PE file. `rules_dir` — path to directory with `.yar`/`.yara` files.
- **Output**: `YaraScanResult` dataclass.
- **Side effects**: Reads rule files. If yara-python is unavailable, returns empty result with error message.
- **Error handling**: Catches `yara.SyntaxError` (`yara_scan.py:133`) and generic exceptions (`yara_scan.py:143`, `yara_scan.py:155`).
- **Callers**: `main.py:66`.

### `compute_verdict(fingerprint, pe_analysis, entropy, strings, yara_result) -> Verdict`

- **Location**: `analyzer/scoring/verdict.py:130-312`
- **Purpose**: Combine all analysis signals into a scored verdict.
- **Input**: `FileFingerprint`, `PEAnalysis`, `EntropyAnalysis`, `StringsAnalysis`, `YaraScanResult`.
- **Output**: `Verdict` dataclass.
- **Side effects**: None (pure computation).
- **Callers**: `main.py:69`.

### `print_full_analysis(fingerprint, pe_analysis, entropy, strings, yara_result, verdict, verbose=False) -> None`

- **Location**: `analyzer/output/printer.py:67-240`
- **Purpose**: Print the complete analysis report to stdout.
- **Input**: All analysis dataclasses plus `verbose` flag.
- **Output**: Formatted text to stdout.
- **Side effects**: Calls `print()` multiple times.
- **Callers**: `main.py:97`.

### `print_batch_header() -> None`

- **Location**: `analyzer/output/printer.py:247-250`
- **Purpose**: Print column headers for batch mode.
- **Callers**: `main.py:125`.

### `print_batch_line(file_name: str, band: str, score: int) -> None`

- **Location**: `analyzer/output/printer.py:253-257`
- **Purpose**: Print one summary line in batch mode.
- **Callers**: `main.py:135`.

### `print_batch_footer(total: int, clean: int, suspicious: int, malicious: int) -> None`

- **Location**: `analyzer/output/printer.py:260-265`
- **Purpose**: Print summary footer for batch mode.
- **Callers**: `main.py:148-153`.

### `print_error(file_path: str, error_msg: str) -> None`

- **Location**: `analyzer/output/printer.py:268-270`
- **Purpose**: Print an error line for a failed file.
- **Callers**: `main.py:142`.

## Internal Functions

| Function | Location | Visibility | Purpose |
|----------|----------|------------|---------|
| `_compute_hashes(raw: bytes)` | `fingerprint.py:38-47` | Private | Compute SHA-256 and MD5 from byte blob |
| `_validate_pe_magic(raw: bytes)` | `fingerprint.py:50-97` | Private | Check MZ and PE\0\0 signatures |
| `_characteristics_to_str(chars: int)` | `pe_parser.py:190-193` | Private | Convert section flags bitfield to string |
| `_shannon_entropy(data: bytes)` | `entropy.py:65-92` | Private | Compute Shannon entropy (0-8 scale) |
| `_extract_ascii_strings(data, min_len)` | `strings.py:139-148` | Private | Extract printable ASCII strings |
| `_extract_utf16le_strings(data, min_len)` | `strings.py:151-169` | Private | Extract UTF-16LE strings |
| `_find_rule_files(rules_dir: str)` | `yara_scan.py:59-73` | Private | Discover .yar/.yara files recursively |
| `_analyze_single_file(file_path, verbose)` | `main.py:36-71` | Private | Run full pipeline on one file |
| `_separator(char)` | `printer.py:34-36` | Private | Generate separator line |
| `_header(title)` | `printer.py:39-41` | Private | Generate section header |
| `_indent(text, level)` | `printer.py:44-47` | Private | Indent text block |
| `_format_size(size_bytes)` | `printer.py:50-60` | Private | Format byte count as human-readable |
