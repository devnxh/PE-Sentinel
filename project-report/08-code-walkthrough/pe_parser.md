# Code Walkthrough: analyzer/static/pe_parser.py

- **Purpose**: Deep PE header and import/export table analysis using the `pefile` library. Extracts architecture, timestamps, sections, imports, exports, Authenticode presence, and flags suspicious API imports.
- **Inputs**: File path (string) to a validated PE file.
- **Outputs**: `PEAnalysis` dataclass.
- **Dependencies**: `datetime`, `dataclasses`, `typing`, `pefile` (external).
- **Callers**: `main.py:51`.
- **Callees**: `pefile.PE()`.

---

## Lines 1-17: Module docstring

```python
"""
static/pe_parser.py — Deep PE header and import/export table analysis.
...
"""
```

Lists the seven categories of data this module extracts and notes that Authenticode checking is presence-only, not cryptographic validation.

## Lines 19-23: Imports

```python
import datetime
from dataclasses import dataclass, field
from typing import Optional

import pefile
```

`datetime` for timestamp formatting. `pefile` is the only external dependency in this module.

## Lines 33-89: SUSPICIOUS_IMPORTS dictionary

```python
SUSPICIOUS_IMPORTS: dict[str, str] = {
    "VirtualAlloc":           "Allocates memory — often used to stage shellcode.",
    "VirtualAllocEx":         "Allocates memory in another process (remote injection).",
    ...
    "URLDownloadToFileA":     "Downloads a file from a URL to disk.",
}
```

A curated dictionary mapping ~38 Windows API function names to human-readable explanations of why each is suspicious. Functions are grouped into categories by comments: memory manipulation (lines 34-38), process injection (lines 41-45), dynamic resolution (lines 48-53), anti-debug (lines 56-59), hooking (lines 62-63), process/thread manipulation (lines 66-71), registry (lines 74-77), crypto (lines 80-82), and networking (lines 85-88). The descriptions reference MITRE ATT&CK and Elastic detection rules (line 31-32).

## Lines 93-112: SUSPICIOUS_COMBOS list

```python
SUSPICIOUS_COMBOS: list[tuple[frozenset[str], str]] = [
    (
        frozenset({"GetProcAddress", "LoadLibraryA"}),
        "Dynamic API resolution combo ...",
    ),
    (
        frozenset({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}),
        "Classic remote code-injection triad ...",
    ),
    (
        frozenset({"VirtualAlloc", "VirtualProtect"}),
        "Memory alloc + permission change ...",
    ),
    (
        frozenset({"OpenProcess", "WriteProcessMemory"}),
        "Opens another process and writes into it ...",
    ),
]
```

Four combinations of APIs that are stronger signals when found together. Uses `frozenset` for O(1) membership testing. Each combination is a tuple of (required functions, explanation). The combo matching logic at lines 281-299 accepts A/W suffix variants.

## Lines 119-168: Data classes

```python
@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    characteristics: int
    characteristics_str: str
```

Five dataclasses are defined: `SectionInfo` (lines 119-126), `ImportEntry` (lines 129-135), `ExportEntry` (lines 138-142), `SuspiciousComboHit` (lines 145-149), and `PEAnalysis` (lines 152-168). All are plain containers with no methods. Each field has an inline comment documenting its meaning.

## Lines 176-187: Section characteristics flags

```python
_SECTION_CHAR_FLAGS = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    ...
    0x80000000: "MEM_WRITE",
}
```

A dictionary mapping PE section characteristic bit values to human-readable names. Only the most commonly encountered flags are included (10 of the ~20 defined in the PE specification).

## Lines 190-193: `_characteristics_to_str()`

```python
def _characteristics_to_str(chars: int) -> str:
    flags = [name for bit, name in _SECTION_CHAR_FLAGS.items() if chars & bit]
    return " | ".join(flags) if flags else f"0x{chars:08X}"
```

Converts a bitfield integer to a pipe-separated string. Falls back to hex representation if no known flags match.

## Lines 200-207: Machine type constants

```python
_MACHINE_TYPES = {
    0x014C: "I386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0x01C4: "ARMNT",
    0xAA64: "ARM64",
}
```

Maps PE machine field values to architecture names. Six architectures are covered.

## Lines 214-344: `analyze_pe()`

```python
def analyze_pe(file_path: str) -> PEAnalysis:
    pe = pefile.PE(file_path)
```

Opens the file with pefile. If pefile cannot parse it, `pefile.PEFormatError` propagates to the caller.

```python
    machine_val = pe.FILE_HEADER.Machine
    machine_str = _MACHINE_TYPES.get(machine_val, f"UNKNOWN(0x{machine_val:04X})")
```

Reads the machine field from the COFF header. Falls back to a formatted unknown string for unrecognized architectures.

```python
    raw_ts = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_dt = datetime.datetime.utcfromtimestamp(raw_ts)
        compile_str = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        compile_str = f"Invalid/out-of-range timestamp (raw=0x{raw_ts:08X})"
```

Converts the COFF timestamp to a human-readable string. The try/except handles invalid timestamps (e.g., 0xFFFFFFFF) that would cause `utcfromtimestamp` to raise. Note: `utcfromtimestamp` is deprecated since Python 3.12; a future update should use `datetime.datetime.fromtimestamp(raw_ts, tz=datetime.timezone.utc)`.

```python
    sections: list[SectionInfo] = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        sections.append(SectionInfo(
            name=name,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            characteristics=section.Characteristics,
            characteristics_str=_characteristics_to_str(section.Characteristics),
        ))
```

Iterates PE sections. Section names are 8 bytes, null-padded, decoded as UTF-8 with replacement for non-UTF-8 bytes.

```python
    imports: list[ImportEntry] = []
    all_import_names: set[str] = set()

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if imp.name is not None:
                    func_name = imp.name.decode('utf-8', errors='replace')
                else:
                    func_name = f"Ordinal_{imp.ordinal}"

                is_sus = func_name in SUSPICIOUS_IMPORTS
                reason = SUSPICIOUS_IMPORTS.get(func_name, "")

                imports.append(ImportEntry(
                    dll=dll_name, function=func_name,
                    is_suspicious=is_sus, suspicion_reason=reason,
                ))
                all_import_names.add(func_name)
```

Parses the import table. Uses `hasattr` to check if the PE has an import directory (not all PE files do). Ordinal-only imports (no name) are formatted as `Ordinal_<number>`. Each import is checked against the `SUSPICIOUS_IMPORTS` dictionary. The `all_import_names` set is built for combo detection.

```python
    suspicious_imports = [i for i in imports if i.is_suspicious]
```

Filters to just the flagged imports. This list is stored in the result for easy access by the printer and scorer.

```python
    combo_hits: list[SuspiciousComboHit] = []
    for required_set, description in SUSPICIOUS_COMBOS:
        matched_funcs = []
        for func in required_set:
            if func in all_import_names:
                matched_funcs.append(func)
            elif func + "A" in all_import_names:
                matched_funcs.append(func + "A")
            elif func + "W" in all_import_names:
                matched_funcs.append(func + "W")

        if len(matched_funcs) == len(required_set):
            combo_hits.append(SuspiciousComboHit(
                functions=sorted(matched_funcs),
                description=description,
            ))
```

Checks each suspicious combination. For each required function, it checks for exact match first, then tries the A (ANSI) and W (wide) suffixed variants. A combo matches only if all functions in the set are present. The matched functions are sorted for deterministic output.

```python
    exports: list[ExportEntry] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='replace') if exp.name else None
            exports.append(ExportEntry(ordinal=exp.ordinal, name=name))
```

Parses the export table, if present. Similar guard with `hasattr`.

```python
    has_sig = False
    sig_detail = "No Authenticode signature data directory present."

    SECURITY_DIR_INDEX = 4
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > SECURITY_DIR_INDEX:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIR_INDEX]
            if sec_dir.VirtualAddress != 0 and sec_dir.Size != 0:
                has_sig = True
                sig_detail = (
                    f"Authenticode data directory present "
                    f"(offset=0x{sec_dir.VirtualAddress:X}, "
                    f"size={sec_dir.Size} bytes).  "
                    "Note: presence only — cryptographic validity not checked."
                )
```

Checks for Authenticode signature by examining data directory index 4 (IMAGE_DIRECTORY_ENTRY_SECURITY). Only checks for presence (non-zero address and size), not cryptographic validity. The defensive `hasattr` checks handle edge cases where pefile might not populate these attributes.

```python
    pe.close()

    return PEAnalysis(
        machine=machine_str, machine_hex=machine_val,
        compile_time=compile_str, compile_time_raw=raw_ts,
        sections=sections, imports=imports, exports=exports,
        suspicious_imports=suspicious_imports,
        suspicious_combos=combo_hits,
        has_signature=has_sig, signature_detail=sig_detail,
    )
```

Closes the pefile instance to release resources, then returns the fully populated `PEAnalysis` dataclass.
