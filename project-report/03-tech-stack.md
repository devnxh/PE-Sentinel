# 03 — Technology Stack

## Core Technologies

| Name | Version | Category | Where Used | What It Does Here | Why Chosen | Alternatives | Evidence |
|------|---------|----------|------------|-------------------|------------|-------------|----------|
| Python | >=3.10 | Language | All `.py` files | Primary implementation language | Type hint syntax (`tuple[str, str]`, `dict[str, str]`, `list[str]`) requires 3.10+. Cross-platform, strong library ecosystem for security tooling. | Go, Rust, C | Inferred from use of PEP 604/585 type hints (`README.md:36`) |
| pefile | >=2023.2.7 | Library (runtime) | `analyzer/static/pe_parser.py`, `analyzer/static/entropy.py` | Parses PE file structures: headers, section tables, import/export tables, data directories | De-facto standard Python library for PE parsing. Pure Python, cross-platform, mature. | LIEF, pepy, manual struct parsing | `requirements.txt:1` |
| yara-python | >=4.3.0 | Library (runtime) | `analyzer/static/yara_scan.py` | Compiles and runs YARA rules against PE files | Python binding for YARA, the industry-standard pattern matching engine for malware research | Custom regex engine, ClamAV signatures | `requirements.txt:2` |
| argparse | stdlib | Library (runtime) | `main.py:13` | CLI argument parsing with subcommands (`analyze`, `batch`) | Part of Python standard library, no external dependency needed for simple CLI tools | Click, Typer, Fire | Verified |
| hashlib | stdlib | Library (runtime) | `analyzer/fingerprint.py:15` | SHA-256 and MD5 hash computation | Standard library, hardware-accelerated on most platforms | PyCryptodome | Verified |
| struct | stdlib | Library (runtime) | `analyzer/fingerprint.py:17` | Binary data unpacking for PE header validation (e_lfanew pointer) | Standard library for binary format handling | Manual byte slicing | Verified |
| math | stdlib | Library (runtime) | `analyzer/static/entropy.py:18` | `log2()` for Shannon entropy calculation | Standard library, no external dependency needed | numpy | Verified |
| re | stdlib | Library (runtime) | `analyzer/static/strings.py:18` | Regex patterns for string extraction and suspicious pattern matching | Standard library, sufficient for the pattern complexity used | regex (third-party) | Verified |
| os | stdlib | Library (runtime) | `main.py:14`, multiple modules | File path operations, directory listing, file existence checks | Standard library | pathlib | Verified |
| datetime | stdlib | Library (runtime) | `analyzer/static/pe_parser.py:19` | Converts PE compile timestamp to human-readable format | Standard library | arrow, pendulum | Verified |
| dataclasses | stdlib | Library (runtime) | All data container modules | Defines structured data containers (`FileFingerprint`, `PEAnalysis`, etc.) | Built-in since Python 3.7, lightweight, no boilerplate | attrs, pydantic, NamedTuple | Verified |
| unittest | stdlib | Library (dev) | `tests/test_*.py` | Unit testing framework | Standard library, zero setup | pytest, nose2 | Verified |
| tempfile | stdlib | Library (dev) | `tests/test_fingerprint.py:12`, `tests/test_strings.py` | Creates temporary files for test fixtures | Standard library | pytest tmp_path fixture | Verified |
| YARA | (rule language) | Rule engine | `rules/*.yar` | Pattern matching rule definitions for malware detection | Industry standard for malware signature writing | Sigma, Snort rules | Verified |

## Dependency Analysis

### Runtime Dependencies (from `requirements.txt`)

| Package | Version Constraint | Used In | Purpose | Risk |
|---------|-------------------|---------|---------|------|
| pefile | `>=2023.2.7` | `pe_parser.py:23`, `entropy.py:119` | PE file parsing | Low. Mature, actively maintained, pure Python. No minimum version pinned to a specific patch means potential for breaking changes, though the pefile API has been stable for years. |
| yara-python | `>=4.3.0` | `yara_scan.py:23` | YARA rule compilation and scanning | Medium. Requires a C compiler on some platforms (noted in `README.md:50-54`). The import is wrapped in a try/except (`yara_scan.py:22-28`) so the tool degrades gracefully if yara-python is unavailable. |

### Dev Dependencies

None declared. The test suite uses only standard library modules (`unittest`, `tempfile`, `struct`).

### Dependency Risk Assessment

| Concern | Status |
|---------|--------|
| Unused dependencies | None found. Both pefile and yara-python are actively used. |
| Outdated dependencies | No pinned versions to become outdated. The `>=` constraint means the latest version is always acceptable. This avoids staleness but introduces reproducibility risk. |
| Supply-chain risk | Low. Both packages are well-known in the security community. pefile has 20M+ downloads. yara-python is maintained by VirusTotal. |
| Transitive dependencies | pefile is pure Python with no transitive dependencies. yara-python depends on the C libyara library. |
| License risk | pefile: MIT. yara-python: Apache-2.0. Both are permissive. |

## Platform Requirements

| Requirement | Detail | Evidence |
|-------------|--------|----------|
| Operating system | Cross-platform (Windows, Linux, macOS) | `README.md:388`: "uses pefile for PE parsing (works on Linux/macOS) and avoids all Windows-only APIs" |
| Python version | 3.10 or later | `README.md:36`: "Python 3.10 or later". Uses built-in generic type syntax (`list[str]`, `dict[str, str]`, `tuple[str, str]`) introduced in PEP 585/604. |
| C compiler | May be needed for yara-python installation | `README.md:50-54` |

## Technology Choice Rationale

**Why Python over compiled languages**: Python is the dominant language in the
malware analysis ecosystem. Both pefile and yara-python are Python-first
libraries. The performance overhead of Python is negligible for static analysis
of individual PE files, which are typically under 100 MB. [Inferred: no
explicit rationale documented]

**Why dataclasses over pydantic**: The project uses `dataclasses.dataclass` for
all data containers. Pydantic would add runtime validation and serialization,
but at the cost of an additional dependency. The project's data flows are
internal (module-to-module), so the simplicity of dataclasses is appropriate.
[Inferred: no explicit rationale documented]

**Why plain print over rich/colorama**: The output module (`printer.py:14-16`)
explicitly notes "No external formatting libraries (rich, colorama) — just plain
text with simple indentation and separator lines." This keeps the dependency
count minimal and ensures output works in any terminal. [Verified]
