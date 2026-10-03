"""
main.py — PE-Sentinel CLI entry point.

Usage:
    python main.py analyze <file_path> [--verbose]
    python main.py batch   <folder_path>

This module wires together all analyzer components and provides the
two subcommands specified in the project requirements.  It contains
NO analysis logic — only argument parsing and orchestration.
"""

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


# Path to the YARA rules directory, relative to this script.
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def _analyze_single_file(file_path: str, verbose: bool = False) -> tuple:
    """Run the full analysis pipeline on one file.

    Returns (fingerprint, pe_analysis, entropy, strings, yara_result, verdict)
    or raises an exception if any step fails.
    """
    # Step 1: Fingerprint — hash the file and validate PE magic bytes.
    fp = fingerprint_file(file_path)

    if not fp.is_pe:
        raise ValueError(
            f"Not a valid PE file: {fp.pe_validation_detail}"
        )

    # Step 2: Parse PE headers, imports, exports.
    pe = analyze_pe(file_path)

    # Step 3: Compute per-section entropy.
    # We pass section info from the PE parser so entropy.py knows
    # what sections exist (it re-reads the file for raw bytes).
    sections_info = [
        {"name": s.name, "virtual_size": s.virtual_size, "raw_size": s.raw_size}
        for s in pe.sections
    ]
    ent = analyze_entropy(file_path, sections_info)

    # Step 4: Extract and scan strings.
    strs = analyze_strings(file_path)

    # Step 5: YARA scan.
    yara = scan_with_yara(file_path, RULES_DIR)

    # Step 6: Score and verdict.
    verd = compute_verdict(fp, pe, ent, strs, yara)

    return fp, pe, ent, strs, yara, verd


def cmd_analyze(args: argparse.Namespace) -> int:
    """Handle the 'analyze' subcommand — full analysis of one PE file.

    Returns 0 on success, 1 on error.
    """
    file_path = args.file_path

    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return 1

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

    # Print the full report (output order enforced by printer.py).
    print_full_analysis(fp, pe, ent, strs, yara_res, verdict, verbose=args.verbose)
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """Handle the 'batch' subcommand — analyze every PE file in a folder.

    Prints ONE summary line per file: filename, verdict band, score.
    Returns 0 if all files succeeded, 1 if any errors occurred.
    """
    folder_path = args.folder_path

    if not os.path.isdir(folder_path):
        print(f"[ERROR] Directory not found: {folder_path}")
        return 1

    # Discover all files in the directory (non-recursive — the spec says
    # "every PE file in a folder", implying one level).
    all_files = sorted([
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
    ])

    if not all_files:
        print(f"[INFO] No files found in {folder_path}")
        return 0

    print_batch_header()

    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "errors": 0}
    total_analyzed = 0

    for file_path in all_files:
        file_name = os.path.basename(file_path)

        try:
            fp, pe, ent, strs, yara_res, verdict = _analyze_single_file(file_path)
            print_batch_line(file_name, verdict.band, verdict.score)
            counts[verdict.band.lower()] += 1
            total_analyzed += 1
        except ValueError:
            # Not a PE file — skip silently (common in mixed-content folders).
            continue
        except Exception as e:
            print_error(file_name, str(e))
            counts["errors"] += 1

    if total_analyzed == 0:
        print("    (no valid PE files found in this directory)")

    print_batch_footer(
        total=total_analyzed,
        clean=counts["clean"],
        suspicious=counts["suspicious"],
        malicious=counts["malicious"],
    )

    return 1 if counts["errors"] > 0 else 0


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

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
    )

    # ── 'analyze' subcommand ────────────────────────────────────────────
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

    # ── 'batch' subcommand ──────────────────────────────────────────────
    batch_parser = subparsers.add_parser(
        "batch",
        help="Analyze all PE files in a directory (one summary line each).",
    )
    batch_parser.add_argument(
        "folder_path",
        help="Path to the directory containing PE files.",
    )

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


if __name__ == "__main__":
    sys.exit(main())
