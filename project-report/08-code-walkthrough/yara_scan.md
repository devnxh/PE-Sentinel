# Code Walkthrough: analyzer/static/yara_scan.py

- **Purpose**: YARA rule discovery, compilation, and scanning. Provides pattern-matching based detection using the industry-standard YARA engine.
- **Inputs**: File path (string), rules directory (string).
- **Outputs**: `YaraScanResult` dataclass.
- **Dependencies**: `os`, `dataclasses`, `typing`, `yara` (external, optional).
- **Callers**: `main.py:66`.
- **Callees**: `yara.compile()`, `compiled_rules.match()`.

---

## Lines 1-16: Module docstring

Documents the four-step process: discover, compile, scan, return matches.

## Lines 18-28: Imports with graceful degradation

```python
import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
```

The yara-python import is wrapped in a try/except. If the C library is missing or the wheel is not installed, the module sets `YARA_AVAILABLE = False` and degrades gracefully. This is documented in the module docstring: "If no rules directory exists or is empty, the module returns an empty result rather than crashing." `field` and `Optional` are imported but unused — dead imports.

## Lines 35-52: Data classes

```python
@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    meta: dict[str, str]
    tags: list[str]
    description: str

@dataclass
class YaraScanResult:
    rules_loaded: int
    rule_files: list[str]
    matches: list[YaraMatch]
    errors: list[str]
    yara_available: bool
```

`YaraMatch` holds one matched rule with its metadata. `YaraScanResult` is the aggregate, including error reporting and availability status.

## Lines 59-73: `_find_rule_files()`

```python
def _find_rule_files(rules_dir: str) -> list[str]:
    if not os.path.isdir(rules_dir):
        return []

    rule_files = []
    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            if fname.lower().endswith(('.yar', '.yara')):
                rule_files.append(os.path.join(root, fname))

    return sorted(rule_files)
```

Recursively walks the rules directory for `.yar` and `.yara` files. Returns sorted paths for deterministic ordering. Returns empty list if directory does not exist.

## Lines 80-185: `scan_with_yara()`

```python
def scan_with_yara(file_path: str, rules_dir: str) -> YaraScanResult:
    if not YARA_AVAILABLE:
        return YaraScanResult(
            rules_loaded=0, rule_files=[], matches=[],
            errors=["yara-python is not installed or failed to import."],
            yara_available=False,
        )
```

Early return if yara-python is unavailable. Returns an error message in the `errors` list so the printer can display a warning.

```python
    rule_files = _find_rule_files(rules_dir)

    if not rule_files:
        return YaraScanResult(
            rules_loaded=0, rule_files=[], matches=[], errors=[],
            yara_available=True,
        )
```

Early return if no rule files found. Not an error — just means no rules to apply.

```python
    errors: list[str] = []
    filepaths_dict: dict[str, str] = {}
    for path in rule_files:
        namespace = os.path.splitext(os.path.basename(path))[0]
        orig_ns = namespace
        counter = 1
        while namespace in filepaths_dict:
            namespace = f"{orig_ns}_{counter}"
            counter += 1
        filepaths_dict[namespace] = path
```

Builds a namespace-to-filepath dictionary for `yara.compile()`. Uses the filename without extension as the namespace. Handles namespace collisions by appending a counter suffix — prevents errors when two rule files have the same basename.

```python
    try:
        compiled_rules = yara.compile(filepaths=filepaths_dict)
    except yara.SyntaxError as e:
        return YaraScanResult(
            rules_loaded=0, rule_files=rule_files, matches=[],
            errors=[f"YARA compilation error: {e}"],
            yara_available=True,
        )
    except Exception as e:
        return YaraScanResult(
            rules_loaded=0, rule_files=rule_files, matches=[],
            errors=[f"Unexpected error compiling YARA rules: {e}"],
            yara_available=True,
        )
```

Compiles all rules at once. Two-tier error handling: `yara.SyntaxError` for malformed rules, generic `Exception` for other compilation failures. Both return an error result instead of raising.

```python
    try:
        raw_matches = compiled_rules.match(file_path)
    except Exception as e:
        return YaraScanResult(
            rules_loaded=len(filepaths_dict), rule_files=rule_files,
            matches=[], errors=[f"YARA scan error: {e}"],
            yara_available=True,
        )
```

Scans the target file. Errors during scanning are caught and reported.

```python
    matches: list[YaraMatch] = []
    for m in raw_matches:
        meta = dict(m.meta) if m.meta else {}
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
```

Converts yara-python match objects to the project's `YaraMatch` dataclass. Extracts `description` from meta, trying both "description" and "desc" keys. Converts all meta values to strings for consistent typing.
