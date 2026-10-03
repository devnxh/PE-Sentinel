# Code Walkthrough: rules/suspicious_powershell.yar

- **Purpose**: Detects PE files containing embedded PowerShell download/execute patterns.
- **Inputs**: PE file bytes.
- **Outputs**: Match/no-match with metadata.
- **Dependencies**: YARA engine.
- **Callers**: `yara_scan.py`.

---

## Lines 1-16: Rule comment

Explains the six categories of PowerShell abuse: downloading, encoded commands, hidden windows, execution policy bypass, and fileless execution via IEX.

## Lines 18-62: Rule definition

```yara
rule Suspicious_PowerShell_Invocation
{
    meta:
        description = "Detects PE files containing PowerShell download/execute patterns"
        author      = "PE-Sentinel"
        severity    = "high"
```

Severity is "high" — the highest among the three included rules.

```yara
    strings:
        $ps_exe_1  = "powershell"  ascii nocase
        $ps_exe_2  = "powershell.exe" ascii nocase
        $ps_exe_3  = "pwsh.exe"    ascii nocase

        $ps_cmd_1  = "Invoke-Expression"  ascii nocase
        ...
        $ps_cmd_8  = "IEX"                ascii

        $ps_flag_1 = "-EncodedCommand"    ascii nocase
        ...
        $ps_flag_6 = "-nop"              ascii nocase
```

Three groups of strings: PowerShell executable references (3), dangerous cmdlets/methods (8), and evasion flags (6). Most use `nocase` for case-insensitive matching. `$ps_cmd_8` ("IEX") is case-sensitive to avoid false positives on the short string.

```yara
    condition:
        uint16(0) == 0x5A4D and
        any of ($ps_exe_*) and
        (
            any of ($ps_cmd_*) or
            any of ($ps_flag_*)
        )
}
```

Requires: PE file AND at least one PowerShell reference AND at least one dangerous cmdlet or evasion flag. A single reference to "powershell" alone does not trigger the rule — it needs corroboration from cmdlets or flags.
