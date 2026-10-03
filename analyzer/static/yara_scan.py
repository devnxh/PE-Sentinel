"""
static/yara_scan.py — YARA rule loading and scanning.

YARA is the de-facto standard for writing pattern-matching rules that
identify malware families, packer signatures, and suspicious behaviours.
This module:

  1. Discovers all .yar / .yara files in the `rules/` directory.
  2. Compiles them using yara-python.
  3. Scans the target PE file against all compiled rules.
  4. Returns matched rule names along with their `meta` fields
     (description, author, etc.) for display in the analysis output.

If no rules directory exists or is empty, the module returns an empty
result rather than crashing — YARA rules are optional enrichment.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    # yara-python may fail to import on some systems (e.g. missing
    # C library).  We degrade gracefully rather than crashing.
    YARA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """One YARA rule that matched against the scanned file."""
    rule_name: str                        # Rule identifier (e.g. "UPX_Packer")
    namespace: str                        # Namespace (usually the filename)
    meta: dict[str, str]                  # Meta fields from the rule
    tags: list[str]                       # Tags attached to the rule
    description: str                      # Extracted from meta['description'] or ""


@dataclass
class YaraScanResult:
    """Complete result of scanning a file against all loaded YARA rules."""
    rules_loaded: int                     # How many rules were compiled
    rule_files: list[str]                 # Paths to the rule files loaded
    matches: list[YaraMatch]             # Rules that matched
    errors: list[str]                     # Any compilation/scan errors
    yara_available: bool                  # Whether yara-python is importable


# ---------------------------------------------------------------------------
# Rule discovery
# ---------------------------------------------------------------------------

def _find_rule_files(rules_dir: str) -> list[str]:
    """Recursively find all .yar and .yara files under `rules_dir`.

    Returns absolute paths sorted alphabetically for deterministic ordering.
    """
    if not os.path.isdir(rules_dir):
        return []

    rule_files = []
    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            if fname.lower().endswith(('.yar', '.yara')):
                rule_files.append(os.path.join(root, fname))

    return sorted(rule_files)


# ---------------------------------------------------------------------------
# Public scanning function
# ---------------------------------------------------------------------------

def scan_with_yara(file_path: str, rules_dir: str) -> YaraScanResult:
    """Compile YARA rules from `rules_dir` and scan `file_path`.

    Parameters
    ----------
    file_path : str
        Absolute path to the PE file to scan.
    rules_dir : str
        Path to the directory containing .yar / .yara rule files.

    Returns
    -------
    YaraScanResult with all matches, loaded rule count, and any errors.
    """
    # Early out if yara-python isn't available.
    if not YARA_AVAILABLE:
        return YaraScanResult(
            rules_loaded=0,
            rule_files=[],
            matches=[],
            errors=["yara-python is not installed or failed to import."],
            yara_available=False,
        )

    rule_files = _find_rule_files(rules_dir)

    if not rule_files:
        return YaraScanResult(
            rules_loaded=0,
            rule_files=[],
            matches=[],
            errors=[],
            yara_available=True,
        )

    # --- Compile rules ---
    # yara.compile() accepts a `filepaths` dict mapping namespace → path.
    # We use the filename (without extension) as the namespace so rule
    # names don't collide across files.
    errors: list[str] = []
    filepaths_dict: dict[str, str] = {}
    for path in rule_files:
        namespace = os.path.splitext(os.path.basename(path))[0]
        # If two files have the same basename, append a counter.
        orig_ns = namespace
        counter = 1
        while namespace in filepaths_dict:
            namespace = f"{orig_ns}_{counter}"
            counter += 1
        filepaths_dict[namespace] = path

    try:
        compiled_rules = yara.compile(filepaths=filepaths_dict)
    except yara.SyntaxError as e:
        # If any rule has a syntax error, the whole compilation fails.
        # Report it and return empty results.
        return YaraScanResult(
            rules_loaded=0,
            rule_files=rule_files,
            matches=[],
            errors=[f"YARA compilation error: {e}"],
            yara_available=True,
        )
    except Exception as e:
        return YaraScanResult(
            rules_loaded=0,
            rule_files=rule_files,
            matches=[],
            errors=[f"Unexpected error compiling YARA rules: {e}"],
            yara_available=True,
        )

    # --- Scan the target file ---
    try:
        raw_matches = compiled_rules.match(file_path)
    except Exception as e:
        return YaraScanResult(
            rules_loaded=len(filepaths_dict),
            rule_files=rule_files,
            matches=[],
            errors=[f"YARA scan error: {e}"],
            yara_available=True,
        )

    # --- Convert yara match objects to our dataclass ---
    matches: list[YaraMatch] = []
    for m in raw_matches:
        meta = dict(m.meta) if m.meta else {}
        # Extract the 'description' meta field if present.
        description = meta.get("description", meta.get("desc", ""))

        matches.append(YaraMatch(
            rule_name=m.rule,
            namespace=m.namespace,
            meta={k: str(v) for k, v in meta.items()},
            tags=list(m.tags) if m.tags else [],
            description=str(description),
        ))

    return YaraScanResult(
        rules_loaded=len(filepaths_dict),
        rule_files=rule_files,
        matches=matches,
        errors=errors,
        yara_available=True,
    )
