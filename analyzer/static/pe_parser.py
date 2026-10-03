"""
static/pe_parser.py — Deep PE header and import/export table analysis.

Uses the `pefile` library to parse the Portable Executable structure and
extract the fields most useful for malware triage:

  - Machine architecture (x86, x64, ARM, …)
  - Compile timestamp (often forged in malware, but still informative)
  - Section table with characteristics flags
  - Full import table: which DLLs the binary links to and which functions
    it calls — this is one of the strongest static-analysis signals.
  - Export table (if any) — unusual in .exe files, common in .dll.
  - Authenticode digital-signature presence (not cryptographic validation,
    just whether the data-directory entry exists and has nonzero size).
  - A curated list of "suspicious" API imports commonly associated with
    injection, process hollowing, hooking, and anti-debug techniques.
"""

import datetime
from dataclasses import dataclass, field
from typing import Optional

import pefile


# ---------------------------------------------------------------------------
# Curated list of Windows API functions frequently abused by malware.
#
# Each entry maps a function name (case-insensitive match) to a short
# explanation of *why* it is suspicious.  These are well-documented in
# threat-intel literature (MITRE ATT&CK, Elastic's detection rules, etc.).
# ---------------------------------------------------------------------------
SUSPICIOUS_IMPORTS: dict[str, str] = {
    # --- Memory manipulation (shellcode injection, RWX regions) ---
    "VirtualAlloc":           "Allocates memory — often used to stage shellcode.",
    "VirtualAllocEx":         "Allocates memory in another process (remote injection).",
    "VirtualProtect":         "Changes page permissions — e.g. making memory executable.",
    "VirtualProtectEx":       "Changes page permissions in another process.",

    # --- Process injection primitives ---
    "WriteProcessMemory":     "Writes into another process's address space.",
    "CreateRemoteThread":     "Creates a thread in another process (classic injection).",
    "CreateRemoteThreadEx":   "Extended variant of CreateRemoteThread.",
    "NtUnmapViewOfSection":   "Unmaps a section of a process — used in process hollowing.",
    "QueueUserAPC":           "Queues an APC to a thread — APC injection technique.",

    # --- Dynamic resolution (evasion of static import analysis) ---
    "GetProcAddress":         "Resolves API addresses at runtime — hides true imports.",
    "LoadLibraryA":           "Loads a DLL by name at runtime.",
    "LoadLibraryW":           "Loads a DLL by name at runtime (wide-char variant).",
    "LoadLibraryExA":         "Extended DLL loading.",
    "LoadLibraryExW":         "Extended DLL loading (wide-char variant).",
    "LdrLoadDll":             "Low-level ntdll DLL loader — harder to hook.",

    # --- Anti-analysis / anti-debugging ---
    "IsDebuggerPresent":      "Checks if a debugger is attached.",
    "CheckRemoteDebuggerPresent": "Checks for remote debuggers.",
    "NtQueryInformationProcess":  "Can query debug flags, process info.",
    "OutputDebugStringA":     "Sometimes used as an anti-debug trick.",

    # --- Hooking / persistence ---
    "SetWindowsHookExA":      "Installs a system-wide hook (keylogger, DLL injection).",
    "SetWindowsHookExW":      "Wide-char variant of SetWindowsHookEx.",

    # --- Process / thread manipulation ---
    "OpenProcess":            "Opens a handle to another process.",
    "CreateProcessA":         "Spawns a new process.",
    "CreateProcessW":         "Spawns a new process (wide-char variant).",
    "TerminateProcess":       "Forcibly kills a process.",
    "SuspendThread":          "Suspends a thread — used in hollowing.",
    "ResumeThread":           "Resumes a suspended thread.",

    # --- Registry manipulation (persistence, config) ---
    "RegSetValueExA":         "Writes to the Windows registry.",
    "RegSetValueExW":         "Writes to the Windows registry (wide-char).",
    "RegCreateKeyExA":        "Creates a registry key.",
    "RegCreateKeyExW":        "Creates a registry key (wide-char).",

    # --- Crypto / encoding (ransomware indicator) ---
    "CryptEncrypt":           "Encrypts data — seen in ransomware.",
    "CryptDecrypt":           "Decrypts data — seen in C2 comms decryption.",
    "CryptAcquireContextA":   "Acquires a crypto provider handle.",

    # --- Networking (C2, exfiltration) ---
    "InternetOpenA":          "Opens an internet session (WinINet).",
    "InternetOpenUrlA":       "Fetches a URL — possible C2 beacon.",
    "HttpSendRequestA":       "Sends an HTTP request.",
    "URLDownloadToFileA":     "Downloads a file from a URL to disk.",
}

# We also flag specific *combinations* that are stronger signals than any
# single import alone.  Each combo is a frozenset of function names.
SUSPICIOUS_COMBOS: list[tuple[frozenset[str], str]] = [
    (
        frozenset({"GetProcAddress", "LoadLibraryA"}),
        "Dynamic API resolution combo (GetProcAddress + LoadLibrary) — "
        "hides true capabilities from static import analysis.",
    ),
    (
        frozenset({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}),
        "Classic remote code-injection triad — allocates, writes, and "
        "executes code in another process.",
    ),
    (
        frozenset({"VirtualAlloc", "VirtualProtect"}),
        "Memory alloc + permission change — common shellcode staging pattern.",
    ),
    (
        frozenset({"OpenProcess", "WriteProcessMemory"}),
        "Opens another process and writes into it — injection indicator.",
    ),
]


# ---------------------------------------------------------------------------
# Data classes — plain containers, no logic.
# ---------------------------------------------------------------------------

@dataclass
class SectionInfo:
    """One row of the PE section table."""
    name: str                  # Section name, e.g. '.text', '.rsrc'
    virtual_size: int          # Size when loaded into memory
    raw_size: int              # Size on disk
    characteristics: int       # Raw flags bitfield
    characteristics_str: str   # Human-readable flags, e.g. 'MEM_EXECUTE | MEM_READ'


@dataclass
class ImportEntry:
    """One imported function from a specific DLL."""
    dll: str                   # e.g. 'KERNEL32.dll'
    function: str              # e.g. 'VirtualAlloc'
    is_suspicious: bool        # True if the function is in our curated list
    suspicion_reason: str      # Why it's flagged (empty string if not suspicious)


@dataclass
class ExportEntry:
    """One exported symbol."""
    ordinal: int
    name: Optional[str]        # May be None for ordinal-only exports


@dataclass
class SuspiciousComboHit:
    """A matched suspicious-import combination."""
    functions: list[str]       # The specific functions that matched
    description: str           # Why this combo matters


@dataclass
class PEAnalysis:
    """Complete result of PE header / import / export analysis."""
    machine: str               # Architecture string, e.g. 'I386', 'AMD64'
    machine_hex: int           # Raw machine field value
    compile_time: str          # Human-readable timestamp string
    compile_time_raw: int      # Raw Unix timestamp from the PE header

    sections: list[SectionInfo]
    imports: list[ImportEntry]
    exports: list[ExportEntry]

    suspicious_imports: list[ImportEntry]        # Subset of `imports` that are flagged
    suspicious_combos: list[SuspiciousComboHit]  # Matched import combinations

    has_signature: bool        # Authenticode data-directory entry present?
    signature_detail: str      # Brief note about signature presence


# ---------------------------------------------------------------------------
# Characteristic flags → readable strings
# ---------------------------------------------------------------------------

# From the PE specification — only the most commonly encountered flags.
_SECTION_CHAR_FLAGS = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA",
    0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED",
    0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}


def _characteristics_to_str(chars: int) -> str:
    """Convert the section characteristics bitfield into a readable string."""
    flags = [name for bit, name in _SECTION_CHAR_FLAGS.items() if chars & bit]
    return " | ".join(flags) if flags else f"0x{chars:08X}"


# ---------------------------------------------------------------------------
# Machine type constants from the PE spec.
# ---------------------------------------------------------------------------

_MACHINE_TYPES = {
    0x014C: "I386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0x01C4: "ARMNT",
    0xAA64: "ARM64",
}


# ---------------------------------------------------------------------------
# Public analysis function
# ---------------------------------------------------------------------------

def analyze_pe(file_path: str) -> PEAnalysis:
    """Parse a PE file and return a fully-populated PEAnalysis dataclass.

    Assumes the file has already passed the MZ/PE magic-byte check in
    fingerprint.py.  If pefile can't parse it, we let the exception
    propagate — the caller should handle pefile.PEFormatError.
    """
    pe = pefile.PE(file_path)

    # --- Machine / architecture ---
    machine_val = pe.FILE_HEADER.Machine
    machine_str = _MACHINE_TYPES.get(machine_val, f"UNKNOWN(0x{machine_val:04X})")

    # --- Compile timestamp ---
    # The TimeDateStamp in the COFF header is a Unix epoch value.
    # Malware often zeroes it out or sets it to an absurd future date.
    raw_ts = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_dt = datetime.datetime.utcfromtimestamp(raw_ts)
        compile_str = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        # Handles timestamps that are out of range (e.g. 0xFFFFFFFF).
        compile_str = f"Invalid/out-of-range timestamp (raw=0x{raw_ts:08X})"

    # --- Section table ---
    sections: list[SectionInfo] = []
    for section in pe.sections:
        # Section names are 8 bytes, null-padded.  Decode and strip nulls.
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        sections.append(SectionInfo(
            name=name,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            characteristics=section.Characteristics,
            characteristics_str=_characteristics_to_str(section.Characteristics),
        ))

    # --- Import table ---
    imports: list[ImportEntry] = []
    all_import_names: set[str] = set()   # For combo detection later

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                # Some imports are ordinal-only (no name).
                if imp.name is not None:
                    func_name = imp.name.decode('utf-8', errors='replace')
                else:
                    func_name = f"Ordinal_{imp.ordinal}"

                # Check against our curated suspicious-import list.
                is_sus = func_name in SUSPICIOUS_IMPORTS
                reason = SUSPICIOUS_IMPORTS.get(func_name, "")

                imports.append(ImportEntry(
                    dll=dll_name,
                    function=func_name,
                    is_suspicious=is_sus,
                    suspicion_reason=reason,
                ))
                all_import_names.add(func_name)

    # Filter to just the suspicious ones for easy access.
    suspicious_imports = [i for i in imports if i.is_suspicious]

    # --- Suspicious combinations ---
    combo_hits: list[SuspiciousComboHit] = []
    for required_set, description in SUSPICIOUS_COMBOS:
        # A combo matches if *all* functions in the set are present.
        # We also accept wide-char variants (A/W suffix) as equivalent.
        matched_funcs = []
        for func in required_set:
            # Check exact match, or with A/W suffix variants.
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

    # --- Export table ---
    exports: list[ExportEntry] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='replace') if exp.name else None
            exports.append(ExportEntry(ordinal=exp.ordinal, name=name))

    # --- Authenticode signature presence ---
    # The IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) data directory points to
    # the Authenticode signature.  We just check if it exists and has a
    # nonzero size — we do NOT validate the signature cryptographically.
    has_sig = False
    sig_detail = "No Authenticode signature data directory present."

    # pefile stores the optional header data directories in a list.
    # Index 4 = IMAGE_DIRECTORY_ENTRY_SECURITY.
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

    pe.close()

    return PEAnalysis(
        machine=machine_str,
        machine_hex=machine_val,
        compile_time=compile_str,
        compile_time_raw=raw_ts,
        sections=sections,
        imports=imports,
        exports=exports,
        suspicious_imports=suspicious_imports,
        suspicious_combos=combo_hits,
        has_signature=has_sig,
        signature_detail=sig_detail,
    )
