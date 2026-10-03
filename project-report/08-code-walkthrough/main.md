# Code Walkthrough: main.py

- **Purpose**: CLI entry point. Parses command-line arguments and orchestrates the analysis pipeline. Contains no analysis logic.
- **Inputs**: Command-line arguments (`analyze <file> [--verbose]` or `batch <folder>`).
- **Outputs**: Exit code (0 success, 1 error). Analysis results printed to stdout via `printer.py`.
- **Dependencies**: `argparse`, `os`, `sys`, all analyzer submodules.
- **Callers**: Invoked directly by the user (`python main.py ...`).
- **Callees**: `fingerprint_file`, `analyze_pe`, `analyze_entropy`, `analyze_strings`, `scan_with_yara`, `compute_verdict`, `print_full_analysis`, `print_batch_header`, `print_batch_line`, `print_batch_footer`, `print_error`.

---

## Lines 1-11: Module docstring

```python
"""
main.py — PE-Sentinel CLI entry point.

Usage:
    python main.py analyze <file_path> [--verbose]
    python main.py batch   <folder_path>

This module wires together all analyzer components and provides the
two subcommands specified in the project requirements.  It contains
NO analysis logic — only argument parsing and orchestration.
"""
```

Documents the module's purpose and establishes the design contract: this file contains zero analysis logic. The uppercase "NO" emphasizes the separation of concerns.

## Lines 13-29: Imports

```python
import argparse
import os
import sys

from analyzer.fingerprint import fingerprint_file, FileFingerprint
from analyzer.static.pe_parser import analyze_pe
from analyzer.static.entropy import analyze_entropy
from analyzer.static.strings import analyze_strings
from analyzer.static.yara_scan import scan_with_yara
from analyzer.scoring.verdict import compute_verdict
from analyzer.output.printer import (
    print_full_analysis,
    print_batch_header,
    print_batch_line,
    print_batch_footer,
    print_error,
)
```

Standard library imports (`argparse`, `os`, `sys`) come first, then project imports grouped by subpackage. `FileFingerprint` is imported alongside `fingerprint_file` but is not directly used in this file — it is imported for type-awareness, though Python does not enforce this at runtime. The `printer` imports are explicitly named to document every output function this module uses.

## Lines 32-33: RULES_DIR constant

```python
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
```

Computes the absolute path to the `rules/` directory relative to the script location. Uses `os.path.abspath(__file__)` to resolve the script's real path regardless of how it was invoked (relative path, symlink, etc.). This ensures YARA rules are found even when the user runs `python main.py` from a different working directory.

## Lines 36-71: `_analyze_single_file()`

```python
def _analyze_single_file(file_path: str, verbose: bool = False) -> tuple:
    """Run the full analysis pipeline on one file.

    Returns (fingerprint, pe_analysis, entropy, strings, yara_result, verdict)
    or raises an exception if any step fails.
    """
```

Private function (underscore prefix). Accepts a file path and verbose flag. Returns a 6-tuple of dataclass results. The `verbose` parameter is accepted but not used within this function — it is passed through to the caller for use in `print_full_analysis()`. The return type is `tuple` rather than a typed `NamedTuple`, which sacrifices some type safety for simplicity.

```python
    fp = fingerprint_file(file_path)

    if not fp.is_pe:
        raise ValueError(
            f"Not a valid PE file: {fp.pe_validation_detail}"
        )
```

Step 1: fingerprint the file. If the file is not a valid PE (MZ/PE signature check failed), raise `ValueError` immediately. This is the only early-exit condition — all other analysis steps assume a valid PE.

```python
    pe = analyze_pe(file_path)
```

Step 2: parse PE headers. The file has already been validated as a PE by the fingerprint step.

```python
    sections_info = [
        {"name": s.name, "virtual_size": s.virtual_size, "raw_size": s.raw_size}
        for s in pe.sections
    ]
    ent = analyze_entropy(file_path, sections_info)
```

Step 3: build section metadata dictionaries from the PE parser's `SectionInfo` objects and pass them to the entropy analyzer. This is the only place where one analysis module's output feeds into another. The dictionary format (`dict` with string keys) is used instead of passing `SectionInfo` objects to avoid a direct import dependency between `entropy.py` and `pe_parser.py`.

```python
    strs = analyze_strings(file_path)
```

Step 4: extract and scan strings. Independent of all other analysis steps.

```python
    yara = scan_with_yara(file_path, RULES_DIR)
```

Step 5: YARA scan. Also independent. Uses the `RULES_DIR` constant defined at module level.

```python
    verd = compute_verdict(fp, pe, ent, strs, yara)

    return fp, pe, ent, strs, yara, verd
```

Step 6: compute the verdict by passing all five analysis results. Returns all six dataclasses as a tuple.

## Lines 74-98: `cmd_analyze()`

```python
def cmd_analyze(args: argparse.Namespace) -> int:
    """Handle the 'analyze' subcommand — full analysis of one PE file.

    Returns 0 on success, 1 on error.
    """
    file_path = args.file_path

    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return 1
```

Extracts `file_path` from parsed args. Validates file existence before attempting analysis. Returns 1 with an error message if the file does not exist.

```python
    try:
        fp, pe, ent, strs, yara_res, verdict = _analyze_single_file(
            file_path, verbose=args.verbose
        )
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        return 1
```

Two-tier exception handling: `ValueError` catches the specific "not a PE" case with a clean message. The bare `Exception` catch is a safety net for unexpected failures (pefile parse errors, file I/O errors, etc.). Both print to stdout (not stderr) and return 1. Bug risk: the bare `Exception` catch may swallow exceptions that should propagate (e.g., `KeyboardInterrupt` is not caught because it inherits from `BaseException`, not `Exception`, so this is acceptable).

```python
    print_full_analysis(fp, pe, ent, strs, yara_res, verdict, verbose=args.verbose)
    return 0
```

On success, print the full report and return 0.

## Lines 101-155: `cmd_batch()`

```python
def cmd_batch(args: argparse.Namespace) -> int:
    """Handle the 'batch' subcommand — analyze every PE file in a folder.

    Prints ONE summary line per file: filename, verdict band, score.
    Returns 0 if all files succeeded, 1 if any errors occurred.
    """
    folder_path = args.folder_path

    if not os.path.isdir(folder_path):
        print(f"[ERROR] Directory not found: {folder_path}")
        return 1
```

Validates the directory exists.

```python
    all_files = sorted([
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
    ])
```

Lists all files (not directories) in the folder, non-recursive, sorted alphabetically. The comment at line 113-114 explains the design choice: "non-recursive — the spec says 'every PE file in a folder', implying one level."

```python
    if not all_files:
        print(f"[INFO] No files found in {folder_path}")
        return 0
```

Graceful handling of empty directories.

```python
    print_batch_header()

    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "errors": 0}
    total_analyzed = 0
```

Prints column headers and initializes counters. The `counts` dictionary keys must match the lowercase version of verdict bands.

```python
    for file_path in all_files:
        file_name = os.path.basename(file_path)

        try:
            fp, pe, ent, strs, yara_res, verdict = _analyze_single_file(file_path)
            print_batch_line(file_name, verdict.band, verdict.score)
            counts[verdict.band.lower()] += 1
            total_analyzed += 1
        except ValueError:
            continue
        except Exception as e:
            print_error(file_name, str(e))
            counts["errors"] += 1
```

Iterates over all files. `ValueError` (not a PE) is silently skipped — this is intentional because folders commonly contain non-PE files (READMEs, configs, etc.). Other exceptions are logged but do not stop the batch.

```python
    if total_analyzed == 0:
        print("    (no valid PE files found in this directory)")

    print_batch_footer(
        total=total_analyzed,
        clean=counts["clean"],
        suspicious=counts["suspicious"],
        malicious=counts["malicious"],
    )

    return 1 if counts["errors"] > 0 else 0
```

Prints a message if no PE files were found. Footer shows aggregate counts. Returns 1 if any errors occurred, 0 otherwise.

## Lines 158-213: `main()`

```python
def main() -> int:
    """Parse CLI arguments and dispatch to the appropriate subcommand."""
    parser = argparse.ArgumentParser(
        prog="pe-sentinel",
        description=(
            "PE-Sentinel — Static PE malware analysis tool.\n"
            "Analyzes Windows PE files (.exe/.dll) without executing them\n"
            "and classifies them as clean / suspicious / malicious."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
```

Creates the top-level argument parser. `RawDescriptionHelpFormatter` preserves the newlines in the description string when printing help.

```python
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
    )
```

Creates a subparser group. The `dest="command"` stores the chosen subcommand name in `args.command`.

```python
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Perform full static analysis on a single PE file.",
    )
    analyze_parser.add_argument(
        "file_path",
        help="Path to the PE file (.exe / .dll) to analyze.",
    )
    analyze_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Show extended details (all matched strings, full YARA meta).",
    )
```

Defines the `analyze` subcommand with one positional argument and one optional flag.

```python
    batch_parser = subparsers.add_parser(
        "batch",
        help="Analyze all PE files in a directory (one summary line each).",
    )
    batch_parser.add_argument(
        "folder_path",
        help="Path to the directory containing PE files.",
    )
```

Defines the `batch` subcommand with one positional argument.

```python
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "batch":
        return cmd_batch(args)
    else:
        parser.print_help()
        return 1
```

Parses arguments and dispatches. If no subcommand is given, prints help. The `else` branch is a defensive guard — with only two subcommands defined, it should never execute, but it prevents silent failure if a new subcommand is added without a handler.

## Lines 216-217: Entry point guard

```python
if __name__ == "__main__":
    sys.exit(main())
```

Standard Python entry point. Passes `main()`'s return value to `sys.exit()` so the process exit code reflects success or failure.
