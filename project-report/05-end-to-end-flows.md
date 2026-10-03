# 05 — End-to-End Flows

## Flow 1: Single File Analysis (`python main.py analyze <file>`)

### Trace

1. `main.py:216-217` — `__main__` guard calls `main()`.
2. `main.py:158-213` — `main()` creates `argparse.ArgumentParser`, defines `analyze` and `batch` subcommands, parses args.
3. `main.py:207-208` — Dispatches to `cmd_analyze(args)`.
4. `main.py:74-98` — `cmd_analyze()` validates file exists, calls `_analyze_single_file()`.
5. `main.py:36-71` — `_analyze_single_file()` runs the pipeline:
   - `main.py:43` — Step 1: `fingerprint_file(file_path)` in `analyzer/fingerprint.py:100-124`.
   - `main.py:45-48` — Checks `fp.is_pe`; raises `ValueError` if not a PE.
   - `main.py:51` — Step 2: `analyze_pe(file_path)` in `analyzer/static/pe_parser.py:214-344`.
   - `main.py:56-60` — Step 3: Builds `sections_info` from PE results; calls `analyze_entropy(file_path, sections_info)` in `analyzer/static/entropy.py:95-191`.
   - `main.py:63` — Step 4: `analyze_strings(file_path)` in `analyzer/static/strings.py:176-236`.
   - `main.py:66` — Step 5: `scan_with_yara(file_path, RULES_DIR)` in `analyzer/static/yara_scan.py:80-185`.
   - `main.py:69` — Step 6: `compute_verdict(fp, pe, ent, strs, yara)` in `analyzer/scoring/verdict.py:130-312`.
6. `main.py:97` — `print_full_analysis(fp, pe, ent, strs, yara_res, verdict, verbose)` in `analyzer/output/printer.py:67-240`.
7. `main.py:98` — Returns exit code 0.

### Sequence Diagram

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.py
    participant FP as fingerprint.py
    participant PP as pe_parser.py
    participant EN as entropy.py
    participant ST as strings.py
    participant YS as yara_scan.py
    participant VD as verdict.py
    participant PR as printer.py

    User->>CLI: python main.py analyze sample.exe
    CLI->>CLI: parse args (argparse)
    CLI->>CLI: validate file exists

    CLI->>FP: fingerprint_file(path)
    FP->>FP: read file, compute SHA-256/MD5
    FP->>FP: validate MZ + PE signature
    FP-->>CLI: FileFingerprint

    CLI->>CLI: check is_pe (abort if false)

    CLI->>PP: analyze_pe(path)
    PP->>PP: parse headers, sections, imports, exports
    PP->>PP: match against SUSPICIOUS_IMPORTS dict
    PP->>PP: check SUSPICIOUS_COMBOS
    PP->>PP: check Authenticode data directory
    PP-->>CLI: PEAnalysis

    CLI->>EN: analyze_entropy(path, sections_info)
    EN->>EN: read file, compute per-section entropy
    EN->>EN: flag packed sections (>7.2)
    EN->>EN: flag size mismatches (>3x)
    EN-->>CLI: EntropyAnalysis

    CLI->>ST: analyze_strings(path)
    ST->>ST: extract ASCII strings
    ST->>ST: extract UTF-16LE strings
    ST->>ST: scan for IP/URL/registry/shell/base64 patterns
    ST-->>CLI: StringsAnalysis

    CLI->>YS: scan_with_yara(path, rules_dir)
    YS->>YS: discover .yar files
    YS->>YS: compile rules
    YS->>YS: scan file
    YS-->>CLI: YaraScanResult

    CLI->>VD: compute_verdict(fp, pe, ent, strs, yara)
    VD->>VD: score imports (cap 16)
    VD->>VD: score combos (cap 20)
    VD->>VD: score packing (cap 18)
    VD->>VD: score YARA (cap 30)
    VD->>VD: score strings (cap 12)
    VD->>VD: check signature, timestamp, exports
    VD->>VD: clamp 0-100, assign band
    VD-->>CLI: Verdict

    CLI->>PR: print_full_analysis(all results)
    PR->>User: formatted terminal output
```

## Flow 2: Batch Analysis (`python main.py batch <folder>`)

### Trace

1. `main.py:216-217` — `__main__` guard calls `main()`.
2. `main.py:158-213` — Parses args, dispatches to `cmd_batch(args)` at `main.py:209-210`.
3. `main.py:101-155` — `cmd_batch()`:
   - `main.py:109-111` — Validates directory exists.
   - `main.py:115-119` — Lists and sorts all files in the directory (non-recursive, `main.py:113-114`).
   - `main.py:125` — Calls `print_batch_header()` (`printer.py:247-250`).
   - `main.py:130-143` — Iterates over files:
     - Calls `_analyze_single_file()` for each (same pipeline as Flow 1).
     - On success: calls `print_batch_line()` (`printer.py:253-257`), increments band counter.
     - On `ValueError`: silently skips (not a PE, `main.py:138-140`).
     - On other `Exception`: calls `print_error()` (`printer.py:268-270`), increments error counter.
   - `main.py:148-153` — Calls `print_batch_footer()` (`printer.py:260-265`).
4. `main.py:155` — Returns 1 if errors occurred, 0 otherwise.

### Sequence Diagram

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.py
    participant PR as printer.py
    participant Pipeline as _analyze_single_file

    User->>CLI: python main.py batch samples/
    CLI->>CLI: validate directory exists
    CLI->>CLI: list and sort files

    CLI->>PR: print_batch_header()
    PR->>User: column headers

    loop for each file in directory
        CLI->>Pipeline: _analyze_single_file(file)
        alt Valid PE
            Pipeline-->>CLI: (fp, pe, ent, strs, yara, verdict)
            CLI->>PR: print_batch_line(name, band, score)
            PR->>User: "filename  CLEAN  12"
        else Not a PE (ValueError)
            Pipeline-->>CLI: ValueError
            CLI->>CLI: skip silently
        else Other error
            Pipeline-->>CLI: Exception
            CLI->>PR: print_error(file, msg)
            PR->>User: "[ERROR] file: msg"
        end
    end

    CLI->>PR: print_batch_footer(counts)
    PR->>User: summary line
```

## Flow 3: PE Validation (within fingerprint_file)

### Trace

1. `fingerprint.py:100-124` — `fingerprint_file()`:
   - `fingerprint.py:107` — Normalizes path with `os.path.abspath()`.
   - `fingerprint.py:110-111` — Opens file in binary mode, reads entire contents.
   - `fingerprint.py:113` — Calls `_compute_hashes(raw)` (`fingerprint.py:38-47`): computes SHA-256 and MD5 in a single pass.
   - `fingerprint.py:114` — Calls `_validate_pe_magic(raw)` (`fingerprint.py:50-97`).
2. `fingerprint.py:50-97` — `_validate_pe_magic()`:
   - `fingerprint.py:63-64` — Checks file length >= 2 bytes.
   - `fingerprint.py:67-71` — Checks bytes 0-1 are `MZ` (0x4D5A).
   - `fingerprint.py:75-76` — Checks file length >= 0x40 (64 bytes) for complete DOS header.
   - `fingerprint.py:79` — Reads `e_lfanew` (4-byte LE uint at offset 0x3C).
   - `fingerprint.py:83-87` — Validates `e_lfanew` points within file bounds.
   - `fingerprint.py:90-95` — Reads 4 bytes at `e_lfanew`, checks for `PE\0\0`.

### Flowchart

```mermaid
flowchart TD
    A["Start: _validate_pe_magic(raw)"] --> B{"len(raw) < 2?"}
    B -->|Yes| C["Return: too small"]
    B -->|No| D{"raw[0:2] == MZ?"}
    D -->|No| E["Return: missing MZ"]
    D -->|Yes| F{"len(raw) < 0x40?"}
    F -->|Yes| G["Return: too short for DOS header"]
    F -->|No| H["Read e_lfanew at 0x3C"]
    H --> I{"e_lfanew + 4 > len(raw)?"}
    I -->|Yes| J["Return: e_lfanew past EOF"]
    I -->|No| K{"raw[e_lfanew:+4] == PE\\0\\0?"}
    K -->|No| L["Return: invalid PE signature"]
    K -->|Yes| M["Return: Valid PE"]
```

## Flow 4: Scoring Decision Logic

### Trace

1. `verdict.py:130-312` — `compute_verdict()`:
   - Lines 161-173: Iterates suspicious imports, adds 2.0 points each up to cap of 16.0.
   - Lines 176-189: Iterates import combos, adds 8.0 points each up to cap of 20.0.
   - Lines 192-218: Iterates packed and mismatched sections, adds 6.0 and 4.0 points respectively up to shared cap of 18.0.
   - Lines 221-234: Iterates YARA matches, adds 10.0 points each up to cap of 30.0.
   - Lines 237-253: Iterates string matches, adds 1.5 points each up to cap of 12.0.
   - Lines 256-265: Adds 4.0 for missing Authenticode signature.
   - Lines 268-280: Adds 3.0 for anomalous timestamp (epoch 0 or > 2030).
   - Lines 283-294: Adds 3.0 for `.exe` with export table.
   - Line 297: Clamps to 0-100.
   - Lines 300-305: Assigns band (0-30=CLEAN, 31-60=SUSPICIOUS, 61-100=MALICIOUS).

### Flowchart

```mermaid
flowchart TD
    A["compute_verdict()"] --> B["Score imports<br/>+2.0 each, cap 16"]
    B --> C["Score combos<br/>+8.0 each, cap 20"]
    C --> D["Score packing<br/>entropy +6.0, mismatch +4.0<br/>shared cap 18"]
    D --> E["Score YARA<br/>+10.0 each, cap 30"]
    E --> F["Score strings<br/>+1.5 each, cap 12"]
    F --> G{"Has signature?"}
    G -->|No| H["+4.0 missing sig"]
    G -->|Yes| I["0"]
    H --> J
    I --> J{"Timestamp anomalous?<br/>0 or > 2030-01-01"}
    J -->|Yes| K["+3.0 timestamp"]
    J -->|No| L["0"]
    K --> M
    L --> M{"EXE with exports?"}
    M -->|Yes| N["+3.0 exports"]
    M -->|No| O["0"]
    N --> P["Clamp 0-100"]
    O --> P
    P --> Q{"Score <= 30?"}
    Q -->|Yes| R["CLEAN"]
    Q -->|No| S{"Score <= 60?"}
    S -->|Yes| T["SUSPICIOUS"]
    S -->|No| U["MALICIOUS"]
```
