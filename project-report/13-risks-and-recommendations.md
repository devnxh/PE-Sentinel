# 13 — Risks and Recommendations

## High Priority

### RISK-01: No tests for the PE parser module

**Evidence**: `tests/` contains no `test_pe_parser.py`. The module
(`pe_parser.py`, 345 lines) is the most complex and handles the most critical
analysis: suspicious import detection, combo matching, A/W suffix handling,
Authenticode checking.

**Impact**: Bugs in import matching (e.g., false negatives on dangerous APIs)
could cause malicious binaries to be scored as CLEAN.

**Recommendation**: Add unit tests using either (a) small crafted PE binaries
generated with `struct`, or (b) mocked `pefile.PE` objects.

### RISK-02: Redundant file reads and pefile parsing

**Evidence**: The target file is read into memory 3-4 times per analysis
(`fingerprint.py:110`, `pe_parser.py:221`, `entropy.py:113`, `strings.py:188`).
The pefile library parses it twice (`pe_parser.py:221`, `entropy.py:120`).

**Impact**: Doubles memory usage for large PE files and introduces a TOCTOU
race condition (SEC-02).

**Recommendation**: Read the file once in `_analyze_single_file()` and pass the
byte buffer to all modules. Reuse the pefile instance from pe_parser in entropy.

### RISK-03: No file size guard

**Evidence**: All file-reading functions call `fh.read()` without checking
file size first (see SEC-01).

**Impact**: A multi-gigabyte file could crash the tool with an out-of-memory
error.

**Recommendation**: Add a `MAX_FILE_SIZE` constant (e.g., 500 MB) and check
`os.path.getsize()` before reading.

## Medium Priority

### RISK-04: `entropy.py` ignores its `sections_info` parameter

**Evidence**: `entropy.py:95` accepts `sections_info` but uses
`pefile.PE(file_path)` at line 120 to get section data instead.

**Impact**: The parameter is misleading. The section data constructed in
`main.py:56-60` is computed but never used. This wastes CPU and confuses
maintainers.

**Recommendation**: Either remove the parameter and have `entropy.py`
independently create its pefile instance (current behavior), or use the
parameter to avoid re-parsing.

### RISK-05: No dependency pinning

**Evidence**: `requirements.txt` uses `>=` constraints (`pefile>=2023.2.7`,
`yara-python>=4.3.0`). No lockfile exists.

**Impact**: Different installations may use different library versions, leading
to inconsistent behavior. A breaking change in pefile or yara-python could
silently break the tool.

**Recommendation**: Add a `requirements-lock.txt` or use `pip freeze` output
for reproducible installations. Keep the `>=` constraints in `requirements.txt`
for flexibility.

### RISK-06: `$generic_pushad at 0` likely does not fire

**Evidence**: `packer_entry_point.yar:77` constrains `$generic_pushad` to
offset 0. Offset 0 in a PE file is the MZ header, which starts with `4D 5A`,
not `60 E8` (the PUSHAD+CALL pattern). The intent was to limit false positives
by constraining to "near the entry point," but offset 0 is not the entry point.

**Impact**: The generic PUSHAD detection is effectively disabled. Only the
specific packer signatures (ASPack, PECompact, MPRESS, Themida) can fire.

**Recommendation**: Either remove the `at 0` constraint and accept more matches,
or document that generic PUSHAD detection is intentionally disabled.

### RISK-07: Deprecated `utcfromtimestamp()` (Python 3.12+)

**Evidence**: `pe_parser.py:232`.

**Impact**: Deprecation warnings on Python 3.12+. Will be removed in a future
Python version.

**Recommendation**: Replace with `datetime.datetime.fromtimestamp(raw_ts, tz=datetime.timezone.utc)`.

## Low Priority

### RISK-08: Dead imports across multiple files

**Evidence**: See Testing and Quality (11) for the full list of 10 unused
imports.

**Impact**: Minor code cleanliness issue. No runtime impact.

**Recommendation**: Remove unused imports. Consider adding a linter (flake8,
ruff) to catch this automatically.

### RISK-09: No CI/CD pipeline

**Evidence**: No `.github/workflows/`, `.gitlab-ci.yml`, or equivalent.

**Impact**: Tests are not automatically run on commit or pull request.

**Recommendation**: Add a GitHub Actions workflow that runs `python -m unittest
discover tests/` on push.

### RISK-10: No structured output format

**Evidence**: `printer.py` produces human-readable text only. No JSON, CSV,
or machine-readable output option.

**Impact**: Limits integration with other tools and automated pipelines. Users
cannot easily pipe results to other programs.

**Recommendation**: Add a `--format json` flag that outputs structured JSON
instead of formatted text.

### RISK-11: Benign IP list is incomplete

**Evidence**: `strings.py:107-110` filters only 5 IPs. Many other benign IPs
commonly appear in PE files: `192.168.0.0` (subnet), `10.0.0.0` (private),
`169.254.0.0` (link-local), `224.0.0.0` (multicast).

**Impact**: False positives on version-info IPs and private network addresses.

**Recommendation**: Expand the benign list or filter entire private/reserved
ranges (RFC 1918, RFC 5735).

## Summary

| ID | Severity | Category | Summary |
|----|----------|----------|---------|
| RISK-01 | High | Testing | No tests for pe_parser.py (345 lines) |
| RISK-02 | High | Performance/Security | File read 3-4 times per analysis (TOCTOU risk) |
| RISK-03 | High | Security | No file size limit (OOM risk) |
| RISK-04 | Medium | Code Quality | Unused parameter in analyze_entropy() |
| RISK-05 | Medium | Deployment | No dependency version pinning |
| RISK-06 | Medium | Correctness | Generic PUSHAD YARA rule likely never fires |
| RISK-07 | Medium | Compatibility | Deprecated utcfromtimestamp() |
| RISK-08 | Low | Code Quality | 10 dead imports |
| RISK-09 | Low | CI/CD | No automated testing pipeline |
| RISK-10 | Low | Feature | No machine-readable output format |
| RISK-11 | Low | Accuracy | Incomplete benign IP filter |
