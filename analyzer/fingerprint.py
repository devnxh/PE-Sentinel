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

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Optional


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


def _compute_hashes(raw: bytes) -> tuple[str, str]:
    """Return (sha256_hex, md5_hex) for the given byte blob.

    We read the whole file into memory once and hash it in a single pass.
    For multi-gigabyte files you'd want chunked reads, but PE binaries are
    almost never that large, so simplicity wins here.
    """
    sha256_digest = hashlib.sha256(raw).hexdigest()
    md5_digest    = hashlib.md5(raw).hexdigest()
    return sha256_digest, md5_digest


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
    # --- Step 1: DOS header magic ---
    if len(raw) < 2:
        return False, "File is too small to contain a DOS header."

    # 'MZ' = 0x4D 0x5A — Mark Zbikowski's initials, a fun bit of history.
    if raw[0:2] != b'MZ':
        return False, (
            f"Missing DOS header magic: expected 'MZ' (0x4D5A), "
            f"got 0x{raw[0]:02X}{raw[1]:02X}."
        )

    # --- Step 2: Read e_lfanew and find the PE signature ---
    # e_lfanew is a 4-byte little-endian unsigned int at offset 0x3C.
    if len(raw) < 0x40:
        return False, "File has MZ magic but is too short for a complete DOS header."

    # struct.unpack_from('<I', ...) → little-endian unsigned 32-bit int.
    e_lfanew = struct.unpack_from('<I', raw, 0x3C)[0]

    # Sanity-check the pointer: it must point inside the file with room for
    # at least the 4-byte PE signature.
    if e_lfanew + 4 > len(raw):
        return False, (
            f"e_lfanew (0x{e_lfanew:X}) points past end of file "
            f"(file is {len(raw)} bytes)."
        )

    # 'PE\0\0' = 0x50 0x45 0x00 0x00
    pe_sig = raw[e_lfanew : e_lfanew + 4]
    if pe_sig != b'PE\x00\x00':
        return False, (
            f"PE signature at offset 0x{e_lfanew:X} is invalid: "
            f"expected 'PE\\0\\0', got {pe_sig!r}."
        )

    return True, "Valid PE: MZ header and PE signature confirmed."


def fingerprint_file(file_path: str) -> FileFingerprint:
    """Read a file from disk and produce a complete FileFingerprint.

    Raises FileNotFoundError / PermissionError naturally — we let those
    propagate so the caller can decide how to present the error.
    """
    # os.path.abspath normalises the path for display purposes.
    abs_path = os.path.abspath(file_path)

    # Read the entire file into memory once.
    with open(abs_path, 'rb') as fh:
        raw = fh.read()

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
