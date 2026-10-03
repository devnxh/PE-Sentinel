# 02 — Repository Map

## Directory Tree

```
PE-Sentinel/
├── main.py                              # CLI entry point, argparse, pipeline orchestration
├── requirements.txt                     # Python dependency manifest (2 packages)
├── README.md                            # Project documentation (396 lines)
├── analyzer/                            # Core analysis package
│   ├── __init__.py                      # Package marker
│   ├── fingerprint.py                   # SHA-256/MD5 hashing, PE magic validation
│   ├── static/                          # Static analysis subpackage
│   │   ├── __init__.py                  # Package marker
│   │   ├── pe_parser.py                 # PE header, import/export table analysis
│   │   ├── entropy.py                   # Shannon entropy per section
│   │   ├── strings.py                   # String extraction + regex pattern scanning
│   │   └── yara_scan.py                 # YARA rule compilation and scanning
│   ├── scoring/                         # Scoring subpackage
│   │   ├── __init__.py                  # Package marker
│   │   └── verdict.py                   # Score computation and verdict assignment
│   └── output/                          # Output formatting subpackage
│       ├── __init__.py                  # Package marker
│       └── printer.py                   # Terminal output formatting
├── rules/                               # YARA rule definitions
│   ├── upx_packer.yar                   # Detects UPX-packed executables
│   ├── suspicious_powershell.yar        # Detects PowerShell download/execute patterns
│   └── packer_entry_point.yar           # Detects common packer entry-point signatures
├── samples/                             # Test PE files (user-supplied)
│   ├── README.md                        # Instructions for populating samples
│   ├── notepad.exe                      # [EXCLUDED: binary, 360,448 bytes]
│   └── certutil.exe                     # [EXCLUDED: binary, 1,601,536 bytes]
├── tests/                               # Unit test suite
│   ├── __init__.py                      # Package marker
│   ├── test_entropy.py                  # Tests for Shannon entropy computation
│   ├── test_fingerprint.py              # Tests for hashing and PE validation
│   ├── test_strings.py                  # Tests for string extraction and patterns
│   └── test_verdict.py                  # Tests for scoring and verdict logic
└── project-report/                      # This report (generated, not part of source)
```

## Excluded Items

| Path | Reason for Exclusion |
|------|---------------------|
| `analyzer/__pycache__/` | Python bytecode cache, auto-generated |
| `analyzer/static/__pycache__/` | Python bytecode cache, auto-generated |
| `analyzer/scoring/__pycache__/` | Python bytecode cache, auto-generated |
| `analyzer/output/__pycache__/` | Python bytecode cache, auto-generated |
| `tests/__pycache__/` | Python bytecode cache, auto-generated |
| `samples/notepad.exe` | Binary PE sample file (360 KB), not source code |
| `samples/certutil.exe` | Binary PE sample file (1.5 MB), not source code |

## File Inventory

| File | Language | Lines | Size (bytes) | Role |
|------|----------|------:|-------------:|------|
| `main.py` | Python | 218 | 6,790 | CLI entry point, argparse setup, pipeline orchestration |
| `requirements.txt` | Text | 3 | 36 | Dependency manifest (pefile, yara-python) |
| `README.md` | Markdown | 396 | 16,326 | Project documentation, usage, scoring design |
| `analyzer/__init__.py` | Python | 2 | 19 | Package marker for `analyzer` |
| `analyzer/fingerprint.py` | Python | 125 | 4,593 | File hashing (SHA-256, MD5) and PE magic validation |
| `analyzer/static/__init__.py` | Python | 2 | 26 | Package marker for `analyzer.static` |
| `analyzer/static/pe_parser.py` | Python | 345 | 14,731 | PE header parsing, import/export analysis, suspicious API catalog |
| `analyzer/static/entropy.py` | Python | 192 | 6,802 | Shannon entropy per section, packing detection |
| `analyzer/static/strings.py` | Python | 237 | 8,573 | String extraction (ASCII/UTF-16LE), regex pattern matching |
| `analyzer/static/yara_scan.py` | Python | 186 | 6,343 | YARA rule discovery, compilation, scanning |
| `analyzer/scoring/__init__.py` | Python | 2 | 27 | Package marker for `analyzer.scoring` |
| `analyzer/scoring/verdict.py` | Python | 313 | 12,431 | Weighted scoring engine, verdict assignment (0-100) |
| `analyzer/output/__init__.py` | Python | 2 | 26 | Package marker for `analyzer.output` |
| `analyzer/output/printer.py` | Python | 271 | 11,419 | Terminal output formatting for analyze and batch modes |
| `rules/upx_packer.yar` | YARA | 48 | 1,552 | Rule to detect UPX-packed executables |
| `rules/suspicious_powershell.yar` | YARA | 63 | 2,398 | Rule to detect embedded PowerShell patterns |
| `rules/packer_entry_point.yar` | YARA | 80 | 3,145 | Rule to detect packer entry-point signatures |
| `samples/README.md` | Markdown | 9 | 278 | Instructions for populating samples directory |
| `tests/__init__.py` | Python | 2 | 16 | Package marker for `tests` |
| `tests/test_entropy.py` | Python | 53 | 1,729 | Unit tests for Shannon entropy function |
| `tests/test_fingerprint.py` | Python | 110 | 3,644 | Unit tests for hashing and PE validation |
| `tests/test_strings.py` | Python | 109 | 3,673 | Unit tests for string extraction and pattern matching |
| `tests/test_verdict.py` | Python | 190 | 5,934 | Unit tests for scoring engine and verdict banding |

## Summary Statistics

| Metric | Count |
|--------|------:|
| First-party Python files | 16 |
| YARA rule files | 3 |
| Markdown files | 3 |
| Config files | 1 |
| Total first-party lines (Python) | 2,259 |
| Total first-party lines (YARA) | 191 |
| Total first-party lines (all) | 2,855 |
