# Code Walkthrough: analyzer/fingerprint.py

- **Purpose**: File identification and integrity fingerprinting. Computes cryptographic hashes and validates PE magic bytes before any deeper analysis.
- **Inputs**: File path (string).
- **Outputs**: `FileFingerprint` dataclass.
- **Dependencies**: `hashlib`, `os`, `struct`, `dataclasses`, `typing`.
- **Callers**: `main.py:43` (`_analyze_single_file`), `tests/test_fingerprint.py`.
- **Callees**: None (leaf module).

---

## Lines 1-13: Module docstring

```python
"""
fingerprint.py — File identification and integrity fingerprinting.

Responsible for:
  1. Computing cryptographic hashes (SHA-256, MD5) for file identification.
  2. Validating that a file is actually a PE (Portable Executable) by checking
     raw magic bytes — we never trust the file extension alone.
  3. Returning basic file metadata (size, hashes, confirmed type).

This module reads the file as raw bytes and performs manual header checks
*before* handing the file to the `pefile` library, so that we can give a
clear error if someone passes in a JPEG renamed to .exe.
"""
```

Explains the module's three responsibilities and the rationale for doing manual magic-byte checks before using pefile.

## Lines 15-19: Imports

```python
import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Optional
```

All standard library. `hashlib` for hashing, `struct` for binary unpacking of the e_lfanew field, `dataclass` for the result container. `field` and `Optional` are imported but not used in this file — `Optional` was likely planned for optional fields and `field` for default values, but the current `FileFingerprint` uses neither. This is dead import code.

## Lines 22-36: FileFingerprint dataclass

```python
@dataclass
class FileFingerprint:
    """Plain-data container returned by `fingerprint_file()`.

    Every field is a simple type so downstream code (scoring, printing) never
    needs to import pefile or touch the filesystem again.
    """
    file_path: str                # Original path the user supplied
    file_name: str                # Basename only (e.g. "malware.exe")
    file_size: int                # Size in bytes
    sha256: str                   # Hex-encoded SHA-256
    md5: str                      # Hex-encoded MD5
    is_pe: bool                   # True only if both MZ + PE\0\0 checks pass
    pe_validation_detail: str     # Human-readable explanation of the check
```

Seven fields, all primitive types. The docstring emphasizes the design decision: downstream modules should not need to re-read the file or import pefile. Every field is annotated with an inline comment explaining its content.

## Lines 38-47: `_compute_hashes()`

```python
def _compute_hashes(raw: bytes) -> tuple[str, str]:
    """Return (sha256_hex, md5_hex) for the given byte blob.

    We read the whole file into memory once and hash it in a single pass.
    For multi-gigabyte files you'd want chunked reads, but PE binaries are
    almost never that large, so simplicity wins here.
    """
    sha256_digest = hashlib.sha256(raw).hexdigest()
    md5_digest    = hashlib.md5(raw).hexdigest()
    return sha256_digest, md5_digest
```

Accepts raw bytes (already read into memory) and returns both hashes as hex strings. The docstring acknowledges the single-pass design is not suitable for very large files but justifies it for PE binaries. MD5 is included despite being cryptographically broken because it remains widely used as a file identifier in malware databases (VirusTotal, etc.). [Inferred: rationale for MD5 not documented]

## Lines 50-97: `_validate_pe_magic()`

```python
def _validate_pe_magic(raw: bytes) -> tuple[bool, str]:
    """Check that `raw` starts with 'MZ' and has a valid PE signature.

    PE validation involves two steps:
      1. Bytes 0-1 must be 'MZ' (the DOS header magic number, present in
         every PE file since the DOS era).
      2. At offset 0x3C in the DOS header there is a 4-byte little-endian
         pointer (`e_lfanew`) that tells us where the PE signature lives.
         The 4 bytes at that offset must be 'PE\\0\\0' (0x50 0x45 0x00 0x00).

    Returns (is_pe, detail_string).
    """
```

Thorough docstring explaining the two-step validation and the PE format structure.

```python
    if len(raw) < 2:
        return False, "File is too small to contain a DOS header."
```

Guard against files smaller than 2 bytes. Cannot even check for MZ.

```python
    if raw[0:2] != b'MZ':
        return False, (
            f"Missing DOS header magic: expected 'MZ' (0x4D5A), "
            f"got 0x{raw[0]:02X}{raw[1]:02X}."
        )
```

Checks the DOS header magic number. The error message includes the actual bytes found, which is helpful for debugging.

```python
    if len(raw) < 0x40:
        return False, "File has MZ magic but is too short for a complete DOS header."
```

The e_lfanew field is at offset 0x3C (60) and is 4 bytes long, so the file must be at least 0x40 (64) bytes.

```python
    e_lfanew = struct.unpack_from('<I', raw, 0x3C)[0]
```

Reads the e_lfanew pointer: a 4-byte little-endian unsigned integer at offset 0x3C. This pointer tells us where in the file the PE signature lives.

```python
    if e_lfanew + 4 > len(raw):
        return False, (
            f"e_lfanew (0x{e_lfanew:X}) points past end of file "
            f"(file is {len(raw)} bytes)."
        )
```

Validates the pointer is within bounds. Without this check, a crafted file could cause an out-of-bounds read.

```python
    pe_sig = raw[e_lfanew : e_lfanew + 4]
    if pe_sig != b'PE\x00\x00':
        return False, (
            f"PE signature at offset 0x{e_lfanew:X} is invalid: "
            f"expected 'PE\\0\\0', got {pe_sig!r}."
        )

    return True, "Valid PE: MZ header and PE signature confirmed."
```

Reads 4 bytes at the e_lfanew offset and compares to the PE signature. Returns a success tuple if both checks pass.

## Lines 100-124: `fingerprint_file()`

```python
def fingerprint_file(file_path: str) -> FileFingerprint:
    """Read a file from disk and produce a complete FileFingerprint.

    Raises FileNotFoundError / PermissionError naturally — we let those
    propagate so the caller can decide how to present the error.
    """
    abs_path = os.path.abspath(file_path)
```

Normalizes the path. This ensures the `file_path` field in the result is always absolute, regardless of how the user specified the path.

```python
    with open(abs_path, 'rb') as fh:
        raw = fh.read()
```

Reads the entire file into memory. Binary mode (`'rb'`) is essential for hash correctness and magic-byte checking. No explicit error handling — `FileNotFoundError` and `PermissionError` propagate naturally as documented.

```python
    sha256, md5 = _compute_hashes(raw)
    is_pe, detail = _validate_pe_magic(raw)

    return FileFingerprint(
        file_path=abs_path,
        file_name=os.path.basename(abs_path),
        file_size=len(raw),
        sha256=sha256,
        md5=md5,
        is_pe=is_pe,
        pe_validation_detail=detail,
    )
```

Calls both helper functions and constructs the result dataclass. `file_size` is derived from the in-memory buffer length rather than `os.path.getsize()` — this is correct and avoids a TOCTOU race where the file could change between the size check and the read.
