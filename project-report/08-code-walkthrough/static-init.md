# Code Walkthrough: analyzer/static/__init__.py

- **Purpose**: Package marker for the `analyzer.static` subpackage.
- **Inputs**: None.
- **Outputs**: None.
- **Dependencies**: None.
- **Callers**: Python import system.
- **Callees**: None.

---

## Line 1: Package comment

```python
# analyzer.static package
```

Marks the `static/` directory as a Python package. No initialization logic. Submodules (`pe_parser`, `entropy`, `strings`, `yara_scan`) are imported by full path from `main.py` and other consumers.
