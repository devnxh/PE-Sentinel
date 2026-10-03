# PE-Sentinel — Static PE Malware Analysis CLI

A command-line tool for static analysis of Windows Portable Executable (PE)
files (.exe / .dll). PE-Sentinel examines file structure, imports, entropy,
strings, and YARA rules to classify binaries as **clean**, **suspicious**, or
**malicious** — all without executing them.

Built as a portfolio project demonstrating static malware analysis skills.

---

## Features

- **File fingerprinting** — SHA-256 / MD5 hashes + PE header validation
- **PE header parsing** — architecture, compile timestamp, section table,
  imports, exports, Authenticode presence
- **Suspicious import detection** — curated list of ~40 Windows APIs commonly
  abused by malware (injection, hooking, anti-debug, crypto, C2)
- **Import combination analysis** — flags dangerous API combos (e.g.
  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
- **Shannon entropy analysis** — per-section entropy to detect packed/encrypted
  sections (threshold: 7.2/8.0)
- **Packing indicators** — virtual-vs-raw size mismatch detection
- **String extraction** — ASCII + UTF-16LE with regex scanning for IPs, URLs,
  registry paths, PowerShell patterns, Base64 blobs
- **YARA scanning** — ships 3 example rules (UPX packer, PowerShell invocation,
  packer entry-point signatures)
- **Transparent scoring** — 0–100 score with itemized reasons

---

## Setup

### Prerequisites

- Python 3.10 or later
- pip

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd PE-Sentinel

# Install dependencies (only pefile and yara-python)
pip install -r requirements.txt
```

> **Note on yara-python:** On some systems you may need a C compiler for
> yara-python. If `pip install yara-python` fails, try:
> - Windows: `pip install yara-python` (pre-built wheels usually available)
> - Linux: `sudo apt-get install libyara-dev` first, then pip install
> - macOS: `brew install yara` first, then pip install

---

## Usage

### Analyze a single file

```bash
python main.py analyze <file_path>

# With verbose output (shows all matched strings, full YARA metadata):
python main.py analyze <file_path> --verbose
```

**Example:**
```bash
python main.py analyze samples/notepad.exe
```

### Batch-analyze a directory

```bash
python main.py batch <folder_path>
```

**Example:**
```bash
python main.py batch samples/

# Output:
# File                                               Verdict        Score
# ────────────────────────────────────────────────── ──────────── ─────
# notepad.exe                                        CLEAN            8
# suspicious_sample.dll                              SUSPICIOUS      45
# definitely_bad.exe                                 MALICIOUS       78
```

---

## Scoring System

PE-Sentinel uses a transparent, weighted scoring system. Every point in the
final score is traceable to a specific finding.

### Weights

| Signal                        | Points Each | Cap   | Rationale                                                    |
|-------------------------------|-------------|-------|--------------------------------------------------------------|
| Suspicious import (individual)| 2.0         | 16.0  | Each flagged API is a mild signal; many together add up.     |
| Import combination            | 8.0         | 20.0  | Combos (e.g. alloc+write+execute) are much stronger signals. |
| Packed section (entropy >7.2) | 6.0         | 18.0  | Packing hides true behaviour; legitimate packers exist too.  |
| Virtual/raw size mismatch     | 4.0         | 18.0  | Another packing indicator, shares cap with entropy.          |
| YARA rule match               | 10.0        | 30.0  | Rule-based detection; strongest signal but capped.           |
| Suspicious string match       | 1.5         | 12.0  | IPs/URLs/PowerShell in strings; noisy, so low per-hit value. |
| Missing Authenticode signature| 4.0         | —     | Most legit software is signed; absence is a minor flag.      |
| Compile timestamp anomaly     | 3.0         | —     | Zeroed or future timestamps suggest deliberate tampering.    |
| EXE with export table         | 3.0         | —     | Unusual for executables; may indicate DLL masquerading.      |

### Bands

| Score Range | Verdict      | Meaning                                        |
|-------------|--------------|------------------------------------------------|
| 0 – 30      | **CLEAN**       | Normal binary, no significant indicators.      |
| 31 – 60     | **SUSPICIOUS**  | Some indicators present — warrants review.     |
| 61 – 100    | **MALICIOUS**   | Strong indicators of malicious intent.         |

### Design choices

- **Caps prevent any single category from dominating.** Even if a binary
  matches all YARA rules, YARA alone contributes at most 30 points — it needs
  corroboration from imports or packing to reach "malicious."
- **Combinations are weighted higher than individuals.** A binary importing
  both `WriteProcessMemory` and `CreateRemoteThread` is far more suspicious
  than one importing either alone.
- **The score is additive and transparent.** The report lists every finding
  with its exact point contribution so you can audit the verdict.

---

## Project Structure

```
PE-Sentinel/
├── main.py                      # CLI entry point (argparse, orchestration)
├── analyzer/
│   ├── fingerprint.py           # SHA-256/MD5 hashing, PE magic validation
│   ├── static/
│   │   ├── pe_parser.py         # PE header, import/export table analysis
│   │   ├── entropy.py           # Shannon entropy per section
│   │   ├── strings.py           # String extraction + regex pattern scanning
│   │   └── yara_scan.py         # YARA rule compilation and scanning
│   ├── scoring/
│   │   └── verdict.py           # Score computation and verdict assignment
│   └── output/
│       └── printer.py           # Terminal output formatting
├── rules/
│   ├── upx_packer.yar           # Detects UPX-packed executables
│   ├── suspicious_powershell.yar # Detects PowerShell download/execute patterns
│   └── packer_entry_point.yar   # Detects common packer entry-point signatures
├── samples/                     # Place test PE files here
├── tests/                       # Test suite
├── requirements.txt             # pefile, yara-python
└── README.md                    # This file
```

---

## YARA Rules

Three example rules are included in `rules/`:

1. **upx_packer.yar** — Detects UPX-packed executables by looking for UPX0/UPX1
   section names and the "UPX!" decompression marker.

2. **suspicious_powershell.yar** — Flags PE files containing PowerShell
   executable references combined with dangerous cmdlets (Invoke-Expression,
   DownloadString) or evasion flags (-EncodedCommand, -WindowStyle Hidden).

3. **packer_entry_point.yar** — Matches common packer entry-point byte
   signatures: ASPack, PECompact, MPRESS, Themida, and generic PUSHAD stubs.

You can add your own `.yar` / `.yara` files to the `rules/` directory — they
will be automatically discovered and compiled at scan time.

---

## Test Results

### Single-file analysis — `notepad.exe` (benign)

```
$ python main.py analyze samples\notepad.exe

========================================================================
  PE-Sentinel - Static PE Analysis Report
========================================================================

------------------------------------------------------------------------
  FILE INFORMATION
------------------------------------------------------------------------
    File Name : notepad.exe
    File Path : D:\PE-Sentinel\samples\notepad.exe
    File Size : 360,448 bytes (352.0 KB)
    SHA-256   : f8f6599de9b8a27f4dbabd996b9d2a02a55640f87ee523338c43cfbe74cd9443
    MD5       : cb9bf52a3aa2a1cfb4bc94801e5bacae
    PE Valid  : Yes
    Detail    : Valid PE: MZ header and PE signature confirmed.

------------------------------------------------------------------------
  PE SUMMARY
------------------------------------------------------------------------
    Architecture    : AMD64 (0x8664)
    Compile Time    : 2042-11-10 03:52:44 UTC
    Digital Sig     : Not present
    Signature Note  : No Authenticode signature data directory present.
    Total Imports   : 315
    Total Exports   : 0

    Section        VirtSize    RawSize  Entropy  Flags
    ------------ ---------- ---------- --------  ------------------------
    .text           157,394    159,744   6.2323  CNT_CODE | MEM_EXECUTE | MEM_READ
    fothk             4,096      4,096   0.0159  CNT_CODE | MEM_EXECUTE | MEM_READ
    .rdata           42,456     45,056   5.5577  CNT_INITIALIZED_DATA | MEM_READ
    .data            10,048      4,096   1.6217  CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
    .pdata            4,620      8,192   3.3065  CNT_INITIALIZED_DATA | MEM_READ
    .didat              248      4,096   0.2524  CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
    .rsrc           123,344    126,976   6.9680  CNT_INITIALIZED_DATA | MEM_READ
    .reloc              848      4,096   1.6068  CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ

------------------------------------------------------------------------
  SUSPICIOUS IMPORTS
------------------------------------------------------------------------
    Found 6 suspicious API import(s):

    [!] api-ms-win-core-libraryloader-l1-2-0.dll :: GetProcAddress
        Reason: Resolves API addresses at runtime - hides true imports.
    [!] api-ms-win-core-processthreads-l1-1-0.dll :: CreateProcessW
        Reason: Spawns a new process (wide-char variant).
    [!] api-ms-win-core-processthreads-l1-1-0.dll :: TerminateProcess
        Reason: Forcibly kills a process.
    [!] api-ms-win-core-debug-l1-1-0.dll :: IsDebuggerPresent
        Reason: Checks if a debugger is attached.
    [!] api-ms-win-core-registry-l1-1-0.dll :: RegSetValueExW
        Reason: Writes to the Windows registry (wide-char).
    [!] api-ms-win-core-registry-l1-1-0.dll :: RegCreateKeyExW
        Reason: Creates a registry key (wide-char).

------------------------------------------------------------------------
  PACKING INDICATORS
------------------------------------------------------------------------
    No packing indicators detected.

------------------------------------------------------------------------
  SUSPICIOUS STRINGS
------------------------------------------------------------------------
    Total strings extracted: 1,523 (ASCII: 1,377, UTF-16: 146)
    Suspicious pattern matches: 7

    [Base64 Blob] - 2 match(es):
        "RtlRegisterFeatureConfigurationChangeNotification"  (ascii)
        "RtlUnregisterFeatureConfigurationChangeNotification"  (ascii)

    [IPv4 Address] - 2 match(es):
        "5.1.0.0"  (ascii)
        "6.0.0.0"  (ascii)

    [URL] - 3 match(es):
        "http://schemas.microsoft.com/SMI/2016/WindowsSettings"  (ascii)
        "https://go.microsoft.com/fwlink/?LinkId=834783"  (utf-16le)
        "https://go.microsoft.com/fwlink/p/?linkid=838060"  (utf-16le)

------------------------------------------------------------------------
  YARA SCAN RESULTS
------------------------------------------------------------------------
    Rules loaded  : 3
    Rule files    : 3
    No YARA rules matched.

========================================================================
  VERDICT
========================================================================
    Score : 30 / 100
    Band  : CLEAN

    Score Breakdown:
        Missing Signature          4.0  ####
        Suspicious Imports        12.0  ############
        Suspicious Strings        10.5  ##########
        Timestamp Anomaly          3.0  ###

    Reasons (15 finding(s)):
        [Suspicious Import] (+2.0) Imports GetProcAddress
        [Suspicious Import] (+2.0) Imports CreateProcessW
        [Suspicious Import] (+2.0) Imports TerminateProcess
        [Suspicious Import] (+2.0) Imports IsDebuggerPresent
        [Suspicious Import] (+2.0) Imports RegSetValueExW
        [Suspicious Import] (+2.0) Imports RegCreateKeyExW
        [Suspicious String] (+1.5) Base64 Blob: "RtlRegisterFeatureConfigurationChangeNotification"
        [Suspicious String] (+1.5) Base64 Blob: "RtlUnregisterFeatureConfigurationChangeNotification"
        [Suspicious String] (+1.5) IPv4 Address: "5.1.0.0"
        [Suspicious String] (+1.5) IPv4 Address: "6.0.0.0"
        [Suspicious String] (+1.5) URL: "http://schemas.microsoft.com/SMI/2016/WindowsSettings"
        [Suspicious String] (+1.5) URL: "https://go.microsoft.com/fwlink/?LinkId=834783"
        [Suspicious String] (+1.5) URL: "https://go.microsoft.com/fwlink/p/?linkid=838060"
        [Signature] (+4.0) No Authenticode digital signature present.
        [Timestamp] (+3.0) Compile timestamp is anomalous (raw=0x890B130C): set to far future.
========================================================================
```

**Result:** Score 30 — **CLEAN** ✅. Notepad lands at the top of the clean band.
The elevated score is expected: Windows 11 notepad uses catalog signing (no embedded
Authenticode), deterministic builds (future-looking timestamp), and legitimately
imports APIs like `GetProcAddress` and `IsDebuggerPresent`.

### Batch analysis

```
$ python main.py batch samples

File                                               Verdict      Score
-------------------------------------------------- ------------ -----
certutil.exe                                       SUSPICIOUS      35
notepad.exe                                        CLEAN           30
---------------------------------------------------------------------
Total: 2  |  Clean: 1  |  Suspicious: 1  |  Malicious: 0
```

`certutil.exe` scores SUSPICIOUS (35) because it imports a broader set of
sensitive APIs (crypto, networking, registry) — which is accurate for a
certificate utility, but also why it's a popular LOLBin (living-off-the-land
binary) abused by attackers.

### Unit tests

```
$ python -m unittest discover tests/ -v

test_empty_data ... ok
test_high_entropy ... ok
test_moderate_entropy ... ok
test_single_byte_value ... ok
test_two_equally_likely_values ... ok
test_known_hash ... ok
test_nonempty ... ok
test_non_pe_file ... ok
test_nonexistent_file ... ok
test_mz_but_no_pe_sig ... ok
test_no_mz ... ok
test_too_small ... ok
test_valid_pe ... ok
test_basic_extraction ... ok
test_min_length_filter ... ok
test_no_strings ... ok
test_benign_ip_filtered ... ok
test_ip_detection ... ok
test_registry_detection ... ok
test_url_detection ... ok
test_basic_utf16 ... ok
test_clean_band ... ok
test_unsigned_is_still_clean ... ok
test_score_clamped_to_100 ... ok
test_suspicious_imports_add_points ... ok
test_yara_match_adds_points ... ok

----------------------------------------------------------------------
Ran 26 tests in 0.010s

OK
```

---

## Design Assumptions

These choices were made where the spec was silent:

1. **Batch mode is non-recursive** — only scans files directly in the given
   folder, not subdirectories.
2. **Non-PE files are silently skipped in batch mode** — since a folder may
   contain mixed content (READMEs, configs, etc.).
3. **Entropy threshold of 7.2** — chosen as a conservative cutoff; typical
   compiled code is 4.5–6.5, while compressed/encrypted data is 7.0–7.9.
4. **Size-mismatch ratio of 3×** — virtual size must be ≥3× raw size to flag
   as a packing indicator.
5. **String minimum length of 5** — shorter strings produce too many false
   positives from random byte sequences.
6. **Benign IPs are filtered** — 0.0.0.0, 127.0.0.1, 255.255.255.255 are
   excluded from suspicious-string matches.
7. **Score is clamped to 0–100** even though the theoretical maximum from
   all weights is higher.
8. **Authenticode is presence-only** — we check the data-directory entry
   exists but do not validate the signature chain.
9. **Cross-platform** — uses `pefile` for PE parsing (works on Linux/macOS)
   and avoids all Windows-only APIs.

---

## License

This project is for educational and portfolio purposes.

