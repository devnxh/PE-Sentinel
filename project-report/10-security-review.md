# 10 — Security Review

## Overview

PE-Sentinel is a read-only analysis tool that processes untrusted PE files.
It does not execute the files, does not expose a network interface, and does
not persist data. The primary security concerns are: processing malformed input
files, and the inherent risks of handling malware samples.

## Findings

### SEC-01: No file size limit on input (Severity: Medium)

**Evidence**: `fingerprint.py:110-111` reads the entire file into memory with
`fh.read()`. `entropy.py:113-114`, `strings.py:188-189` do the same. There is
no check on file size before reading.

**Risk**: A maliciously large file (or a file that appears small but decompresses
to gigabytes) could exhaust available memory, causing an out-of-memory crash.

**Fix**: Add a maximum file-size check before reading. PE files larger than
~500 MB are extremely unusual and should be rejected.

### SEC-02: File read three to four times (Severity: Low)

**Evidence**: The same PE file is read into memory at least three times:
1. `fingerprint.py:110-111` (full read for hashing)
2. `pe_parser.py:221` (via pefile.PE())
3. `entropy.py:113-114` (full read) and `entropy.py:120` (via pefile.PE() again)
4. `strings.py:188-189` (full read)

**Risk**: TOCTOU (time-of-check-time-of-use) race condition if the file is
modified between reads. An attacker could swap a benign file for a malicious one
between the fingerprint check and analysis. This is primarily a concern in
automated pipelines where files could be replaced.

**Fix**: Read the file once in `_analyze_single_file()` and pass the byte buffer
to all analysis modules.

### SEC-03: MD5 used for file identification (Severity: Low)

**Evidence**: `fingerprint.py:46` computes MD5 alongside SHA-256.

**Risk**: MD5 is cryptographically broken (practical collision attacks exist).
However, it is used here only as a lookup key for malware databases, not for
integrity verification. SHA-256 is the primary hash.

**Fix**: None required. The dual-hash approach is standard practice in malware
analysis. Document that MD5 should not be used for integrity verification.

### SEC-04: Deprecated `utcfromtimestamp()` (Severity: Low)

**Evidence**: `pe_parser.py:232`.

**Risk**: `datetime.datetime.utcfromtimestamp()` is deprecated since Python 3.12
and returns a naive datetime. This is not a security vulnerability but will
produce deprecation warnings on Python 3.12+.

**Fix**: Replace with `datetime.datetime.fromtimestamp(raw_ts, tz=datetime.timezone.utc)`.

### SEC-05: No path traversal protection on YARA rules directory (Severity: Low)

**Evidence**: `yara_scan.py:68` uses `os.walk(rules_dir)` to discover rule files.
The `rules_dir` is hardcoded to `main.py:33` (relative to script location), so
user input does not directly control this path.

**Risk**: If the `RULES_DIR` constant were ever made configurable (e.g., via CLI
argument), a malicious user could point it to an arbitrary directory containing
crafted YARA rules. Those rules would be compiled and executed by the YARA engine.

**Fix**: If rules_dir becomes user-configurable, validate that it is a subdirectory
of the project root.

### SEC-06: No input validation on CLI arguments beyond file/dir existence (Severity: Low)

**Evidence**: `main.py:81` checks `os.path.isfile()` and `main.py:109` checks
`os.path.isdir()`. No other validation (symlink resolution, path canonicalization,
etc.).

**Risk**: On Unix-like systems, a symlink could point to a sensitive file outside
the intended scope. This is a minor concern for a local CLI tool.

**Fix**: Use `os.path.realpath()` to resolve symlinks before processing.

### SEC-07: YARA engine processes untrusted files (Severity: Informational)

**Evidence**: `yara_scan.py:154` calls `compiled_rules.match(file_path)`.

**Risk**: YARA itself has had vulnerabilities (buffer overflows, integer overflows)
in the past. Processing a crafted PE file could trigger a vulnerability in the
YARA engine's parsing code. This is an inherent risk of any malware analysis tool.

**Fix**: Keep yara-python updated. Consider running analysis in a sandboxed
environment (container, VM) for production use.

## Vulnerability Class Checklist

| Class | Applicable | Status |
|-------|-----------|--------|
| SQL Injection | No | No database |
| XSS | No | No web output |
| CSRF | No | No web interface |
| Command Injection | No | No shell commands executed |
| Path Traversal | Minimal | RULES_DIR is hardcoded; file paths are user-supplied but only read |
| SSRF | No | No network requests |
| Insecure Deserialization | No | No serialization/deserialization |
| Weak Cryptography | Informational | MD5 used alongside SHA-256 (see SEC-03) |
| Secrets Handling | No | No secrets, tokens, or credentials in the codebase |
| Authentication | No | No auth system |
| Authorization | No | No auth system |
| Input Validation | Medium | No file size limits (see SEC-01) |
| Output Encoding | No | Plain text output to stdout |

## Secrets Inventory

No secrets, API keys, tokens, passwords, or credentials were found anywhere
in the codebase. There are no `.env` files, no config files with sensitive
values, and no hardcoded credentials.
