# PE-Sentinel Technical Report — Table of Contents

This report provides a complete technical analysis of the PE-Sentinel project,
a static malware analysis CLI tool for Windows Portable Executable files.

## How to Read This Report

Start with the executive summary (01) for a high-level understanding. The
repository map (02) and tech stack (03) provide context for the rest of the
report. The architecture (04) and end-to-end flows (05) explain how the system
works as a whole. The data model (06) and API documentation (07) cover the
internal interfaces. The code walkthrough (08) contains line-by-line analysis
of every source file. Configuration and deployment (09) explains how to run the
tool. The security review (10), testing analysis (11), history (12), and risk
assessment (13) provide quality evaluations. The glossary (14) defines all
project-specific terms.

All file references use the format `path/file:line` or `path/file:line-line`.
Claims are labeled `Verified` (default), `Inferred`, or `Unknown`.

## Report Files

| # | File | Description |
|---|------|-------------|
| 00 | [00-index.md](00-index.md) | This file. Table of contents and reading guide. |
| 01 | [01-executive-summary.md](01-executive-summary.md) | Project purpose, features, maturity, architecture overview. |
| 02 | [02-repository-map.md](02-repository-map.md) | Annotated directory tree, file inventory with roles and line counts. |
| 03 | [03-tech-stack.md](03-tech-stack.md) | Languages, libraries, tools with versions, purposes, and alternatives. |
| 04 | [04-architecture.md](04-architecture.md) | Layers, components, boundaries, design patterns, diagrams. |
| 05 | [05-end-to-end-flows.md](05-end-to-end-flows.md) | Traced execution flows with sequence diagrams. |
| 06 | [06-data-model.md](06-data-model.md) | Dataclasses, fields, relationships, ER diagram. |
| 07 | [07-api-and-interfaces.md](07-api-and-interfaces.md) | CLI commands, public functions, inputs, outputs. |
| 08 | [08-code-walkthrough/](08-code-walkthrough/) | Line-by-line analysis of every first-party source file. |
| 09 | [09-configuration-and-deployment.md](09-configuration-and-deployment.md) | Environment, config, build, run, deploy. |
| 10 | [10-security-review.md](10-security-review.md) | Security analysis with findings and recommendations. |
| 11 | [11-testing-and-quality.md](11-testing-and-quality.md) | Test coverage, gaps, code quality. |
| 12 | [12-history-and-evolution.md](12-history-and-evolution.md) | Git history and project timeline. |
| 13 | [13-risks-and-recommendations.md](13-risks-and-recommendations.md) | Technical debt, risks, prioritized improvements. |
| 14 | [14-glossary.md](14-glossary.md) | Project-specific terms and acronyms. |

## Code Walkthrough Files (08-code-walkthrough/)

| File | Source |
|------|--------|
| [main.md](08-code-walkthrough/main.md) | main.py |
| [analyzer-init.md](08-code-walkthrough/analyzer-init.md) | analyzer/__init__.py |
| [fingerprint.md](08-code-walkthrough/fingerprint.md) | analyzer/fingerprint.py |
| [static-init.md](08-code-walkthrough/static-init.md) | analyzer/static/__init__.py |
| [pe_parser.md](08-code-walkthrough/pe_parser.md) | analyzer/static/pe_parser.py |
| [entropy.md](08-code-walkthrough/entropy.md) | analyzer/static/entropy.py |
| [strings.md](08-code-walkthrough/strings.md) | analyzer/static/strings.py |
| [yara_scan.md](08-code-walkthrough/yara_scan.md) | analyzer/static/yara_scan.py |
| [scoring-init.md](08-code-walkthrough/scoring-init.md) | analyzer/scoring/__init__.py |
| [verdict.md](08-code-walkthrough/verdict.md) | analyzer/scoring/verdict.py |
| [output-init.md](08-code-walkthrough/output-init.md) | analyzer/output/__init__.py |
| [printer.md](08-code-walkthrough/printer.md) | analyzer/output/printer.py |
| [upx_packer_yar.md](08-code-walkthrough/upx_packer_yar.md) | rules/upx_packer.yar |
| [suspicious_powershell_yar.md](08-code-walkthrough/suspicious_powershell_yar.md) | rules/suspicious_powershell.yar |
| [packer_entry_point_yar.md](08-code-walkthrough/packer_entry_point_yar.md) | rules/packer_entry_point.yar |
| [tests-init.md](08-code-walkthrough/tests-init.md) | tests/__init__.py |
| [test_entropy.md](08-code-walkthrough/test_entropy.md) | tests/test_entropy.py |
| [test_fingerprint.md](08-code-walkthrough/test_fingerprint.md) | tests/test_fingerprint.py |
| [test_strings.md](08-code-walkthrough/test_strings.md) | tests/test_strings.py |
| [test_verdict.md](08-code-walkthrough/test_verdict.md) | tests/test_verdict.py |
