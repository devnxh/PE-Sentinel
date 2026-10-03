# 09 — Configuration and Deployment

## Environment Variables

The project uses no environment variables. All configuration is done through
module-level constants and command-line arguments.

## Configuration Constants

Configuration is embedded in source code as module-level constants. There are no
config files, no `.env` templates, and no runtime configuration mechanism.

| Constant | File | Value | Purpose |
|----------|------|-------|---------|
| `RULES_DIR` | `main.py:33` | `<script_dir>/rules` | Path to YARA rules directory |
| `ENTROPY_PACKED_THRESHOLD` | `entropy.py:31` | 7.2 | Entropy above this flags section as packed |
| `SIZE_MISMATCH_RATIO` | `entropy.py:36` | 3.0 | Virtual/raw size ratio threshold |
| `MIN_RAW_SIZE` | `entropy.py:41` | 512 | Minimum section size for entropy analysis |
| `MIN_STRING_LENGTH` | `strings.py:28` | 5 | Minimum string length to extract |
| `MAX_STRINGS_RETURNED` | `strings.py:32` | 5000 | Maximum strings per encoding type |
| `WEIGHT_SUSPICIOUS_IMPORT` | `verdict.py:48` | 2.0 | Points per suspicious import |
| `CAP_SUSPICIOUS_IMPORTS` | `verdict.py:51` | 16.0 | Maximum total from individual imports |
| `WEIGHT_IMPORT_COMBO` | `verdict.py:57` | 8.0 | Points per import combination |
| `CAP_IMPORT_COMBOS` | `verdict.py:58` | 20.0 | Maximum total from combinations |
| `WEIGHT_PACKED_SECTION` | `verdict.py:62` | 6.0 | Points per packed section |
| `WEIGHT_SIZE_MISMATCH` | `verdict.py:64` | 4.0 | Points per size mismatch |
| `CAP_PACKING` | `verdict.py:66` | 18.0 | Maximum total from packing indicators |
| `WEIGHT_YARA_HIT` | `verdict.py:70` | 10.0 | Points per YARA rule match |
| `CAP_YARA` | `verdict.py:72` | 30.0 | Maximum total from YARA |
| `WEIGHT_STRING_MATCH` | `verdict.py:76` | 1.5 | Points per suspicious string |
| `CAP_STRINGS` | `verdict.py:78` | 12.0 | Maximum total from strings |
| `WEIGHT_NO_SIGNATURE` | `verdict.py:83` | 4.0 | Points for missing Authenticode |
| `WEIGHT_TIMESTAMP_ANOMALY` | `verdict.py:88` | 3.0 | Points for anomalous timestamp |
| `WEIGHT_EXE_WITH_EXPORTS` | `verdict.py:93` | 3.0 | Points for .exe with exports |
| `BAND_CLEAN_MAX` | `verdict.py:100` | 30 | Maximum score for CLEAN band |
| `BAND_SUSPICIOUS_MAX` | `verdict.py:101` | 60 | Maximum score for SUSPICIOUS band |
| `LINE_WIDTH` | `printer.py:31` | 72 | Terminal output column width |

## Build Steps

There is no build step. The project is pure Python and runs directly from source.

## Prerequisites

1. Python 3.10 or later (`README.md:36`).
2. pip (for installing dependencies).
3. Optional: C compiler for yara-python installation (`README.md:50-54`).

## Installation

From `README.md:41-48`:

```bash
git clone <repo-url>
cd PE-Sentinel
pip install -r requirements.txt
```

The `requirements.txt` (`requirements.txt:1-2`) specifies:

```
pefile>=2023.2.7
yara-python>=4.3.0
```

## Running the Tool

### Single file analysis

```bash
python main.py analyze <file_path>
python main.py analyze <file_path> --verbose
```

Source: `README.md:63-67`, `main.py:176-189`.

### Batch analysis

```bash
python main.py batch <folder_path>
```

Source: `README.md:77-78`, `main.py:192-199`.

### Running tests

```bash
python -m unittest discover tests/ -v
```

Source: `README.md:330`.

## Docker / CI / CD

There is no Dockerfile, no docker-compose.yml, no CI/CD configuration (no `.github/workflows/`, no `.gitlab-ci.yml`, no Jenkinsfile, no Makefile). The project is intended to be run locally from a cloned repository.

## Hosting Assumptions

The tool runs locally on the user's machine. It requires:
- Read access to the PE files being analyzed.
- Read access to the `rules/` directory.
- Write access to stdout.
- No network access, no database, no persistent storage.
