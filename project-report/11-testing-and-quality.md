# 11 — Testing and Quality

## Test Suite Overview

The project has 26 unit tests across 4 test files, all using Python's built-in
`unittest` framework. Tests are run with:

```bash
python -m unittest discover tests/ -v
```

All 26 tests pass as documented in `README.md:330-363`.

## Test Inventory

| File | Tests | What is Tested | Module Under Test |
|------|------:|----------------|-------------------|
| `tests/test_entropy.py` | 5 | Shannon entropy on known distributions | `entropy._shannon_entropy()` |
| `tests/test_fingerprint.py` | 6 | Hashing, PE magic validation, full fingerprinting | `fingerprint._compute_hashes()`, `fingerprint._validate_pe_magic()`, `fingerprint.fingerprint_file()` |
| `tests/test_strings.py` | 7 | ASCII/UTF-16 extraction, pattern detection, benign IP filtering | `strings._extract_ascii_strings()`, `strings._extract_utf16le_strings()`, `strings.analyze_strings()` |
| `tests/test_verdict.py` | 8 | Score banding, individual signal scoring, cap enforcement | `verdict.compute_verdict()` |

## Coverage Analysis

### What is Covered

| Module | Test Coverage | Notes |
|--------|-------------|-------|
| `fingerprint.py` | Good | All three functions tested (hashing, magic validation, full fingerprint). Edge cases covered: empty file, non-PE, nonexistent file, MZ-only, too-small. |
| `entropy.py` | Partial | Only `_shannon_entropy()` is tested. `analyze_entropy()` is not tested — it requires a real PE file. |
| `strings.py` | Good | Both extraction functions and the full analysis function tested. Pattern detection for IPs, URLs, registry paths. Benign IP filtering verified. |
| `verdict.py` | Good | Clean band, unsigned-but-clean, import scoring, YARA scoring, and clamping to 100 all tested. |
| `pe_parser.py` | None | No tests. The most complex module (345 lines) has zero test coverage. |
| `yara_scan.py` | None | No tests. |
| `printer.py` | None | No tests. |
| `main.py` | None | No tests. Integration/CLI tests are absent. |

### Coverage Gaps

1. **`pe_parser.py` has no tests** — this is the most critical gap. The PE
   parsing logic, suspicious import detection, combo matching, and Authenticode
   checking are all untested. Testing would require mock PE files or pefile
   mocking.

2. **`yara_scan.py` has no tests** — rule discovery, compilation error handling,
   scan error handling, and graceful degradation when yara-python is unavailable
   are all untested.

3. **`printer.py` has no tests** — output formatting is untested. While
   functional testing via `README.md` examples provides some indirect coverage,
   there are no automated tests that verify output format.

4. **`main.py` has no tests** — no CLI integration tests. Argument parsing,
   error handling, and the batch loop are untested.

5. **`analyze_entropy()` is untested** — only the pure `_shannon_entropy()`
   helper is tested. The integration with pefile and the packing/mismatch
   detection logic are not covered.

6. **No tests for import combination matching** — the A/W suffix matching logic
   in `pe_parser.py:286-293` is not tested.

7. **No tests for the `--verbose` flag** — the verbose output path in
   `printer.py` is not tested.

## Code Quality Observations

### Dead Imports

| File | Unused Import | Evidence |
|------|--------------|----------|
| `fingerprint.py:18` | `field` | Not used in any dataclass |
| `fingerprint.py:19` | `Optional` | Not used in any type annotation |
| `entropy.py:20` | `Optional` | Not used |
| `strings.py:19` | `field` | Not used |
| `yara_scan.py:19` | `field` | Not used |
| `yara_scan.py:20` | `Optional` | Not used |
| `verdict.py:31` | `field` | Not used |
| `verdict.py:32` | `Optional` | Not used |
| `test_verdict.py:11` | `MagicMock` | Not used |
| `test_entropy.py:9` | `math` | Not used |

### Unused Parameter

`analyze_entropy()` accepts `sections_info` (`entropy.py:95`) but does not use
it. The function re-reads section data from pefile directly (`entropy.py:120-127`).

### Redundant File Reads

The target PE file is read 3-4 times during a single analysis. See SEC-02 in
the security review for details.

### Duplicate Ratio Computation

In `entropy.py`, the `ratio = v_size / r_size` computation appears twice:
once at line 146 (for the `has_mismatch` check) and again at line 165 (for
the detail string).

### Performance

For a typical PE file (1-10 MB), performance is not a concern. The dominant
cost is the pefile parsing, which happens twice (once in pe_parser, once in
entropy). For batch mode with many files, the repeated file reads and pefile
initializations could be optimized.

### Code Style

- Consistent 4-space indentation throughout.
- Comprehensive docstrings on every public function and module.
- Inline comments explain non-obvious decisions.
- Type annotations on all function signatures (Python 3.10+ syntax).
- Consistent naming: private functions prefixed with underscore.
- No use of global mutable state.
