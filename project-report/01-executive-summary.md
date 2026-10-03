# 01 — Executive Summary

## What PE-Sentinel Is

PE-Sentinel is a command-line tool for static malware analysis of Windows
Portable Executable (PE) files. It examines `.exe` and `.dll` binaries without
executing them and classifies each as CLEAN, SUSPICIOUS, or MALICIOUS based on
a transparent, weighted scoring system.

## Problem It Solves

Malware analysts and security teams need a fast, repeatable way to triage PE
binaries before committing to expensive dynamic analysis (sandboxing, debugging).
PE-Sentinel automates the initial triage step by examining structural indicators
that correlate with malicious intent: suspicious API imports, high-entropy
(packed/encrypted) sections, embedded strings matching IOC patterns, YARA rule
matches, and missing digital signatures.

## Intended Users

Security analysts, malware researchers, SOC teams, and students learning static
analysis techniques. The project README (`README.md:8`) states it is "Built as a
portfolio project demonstrating static malware analysis skills."

## Main Features

1. **File fingerprinting** — SHA-256 and MD5 hashes with PE header validation (`analyzer/fingerprint.py`).
2. **PE header parsing** — architecture, compile timestamp, section table, imports, exports, Authenticode presence (`analyzer/static/pe_parser.py`).
3. **Suspicious import detection** — curated list of approximately 40 Windows APIs commonly abused by malware, plus combination analysis (`analyzer/static/pe_parser.py:33-112`).
4. **Shannon entropy analysis** — per-section entropy to detect packed/encrypted sections with a threshold of 7.2/8.0 (`analyzer/static/entropy.py`).
5. **String extraction** — ASCII and UTF-16LE with regex scanning for IPs, URLs, registry paths, PowerShell patterns, Base64 blobs (`analyzer/static/strings.py`).
6. **YARA scanning** — three included rules for UPX packer, PowerShell invocation, and packer entry-point signatures (`rules/`).
7. **Transparent scoring** — 0-100 score with itemized reasons and per-category caps (`analyzer/scoring/verdict.py`).
8. **Batch mode** — scan all PE files in a directory with one-line-per-file summary (`main.py:101-155`).

## Maturity

This is a portfolio/educational project. It has:
- A complete analysis pipeline from file input to scored verdict.
- 26 passing unit tests covering the core analysis functions.
- Well-documented code with docstrings and inline comments.
- No CI/CD, no Docker, no package distribution, no database.
- Two runtime dependencies (pefile, yara-python).

The codebase is approximately 1,900 lines of Python across 12 first-party
modules, plus 3 YARA rule files (191 lines) and 4 test files (462 lines).

## Architecture Summary

PE-Sentinel follows a pipeline architecture with five sequential stages:
fingerprinting, PE header parsing, entropy analysis, string extraction, and
YARA scanning. Each stage is an independent module that reads the file, produces
a dataclass result, and passes it forward. The scoring engine (`verdict.py`)
combines all results into a weighted score. The printer module (`printer.py`)
formats the output for terminal display. The CLI entry point (`main.py`)
orchestrates the pipeline via `argparse` subcommands (`analyze` and `batch`).
There is no database, no network communication, and no persistent state.
