/*
  suspicious_powershell.yar — Detect embedded PowerShell invocation patterns.

  Malware frequently drops or executes PowerShell commands to:
    - Download second-stage payloads ("DownloadString", "DownloadFile")
    - Execute encoded commands ("-EncodedCommand", "-enc")
    - Run hidden windows ("-WindowStyle Hidden", "-w hidden")
    - Bypass execution policy ("-ExecutionPolicy Bypass")
    - Use Invoke-Expression (IEX) for fileless execution

  This rule fires when a PE binary contains multiple PowerShell-related
  strings, which is abnormal for most legitimate compiled executables.
  A single reference to "powershell" could be benign (e.g. a sysadmin
  tool), but the combination of invocation patterns + evasion flags is
  a strong indicator of malicious intent.
*/

rule Suspicious_PowerShell_Invocation
{
    meta:
        description = "Detects PE files containing PowerShell download/execute patterns"
        author      = "PE-Sentinel"
        severity    = "high"

    strings:
        // PowerShell executable references.
        $ps_exe_1  = "powershell"  ascii nocase
        $ps_exe_2  = "powershell.exe" ascii nocase
        $ps_exe_3  = "pwsh.exe"    ascii nocase

        // Dangerous cmdlets and methods.
        $ps_cmd_1  = "Invoke-Expression"  ascii nocase
        $ps_cmd_2  = "Invoke-WebRequest"  ascii nocase
        $ps_cmd_3  = "Invoke-Command"     ascii nocase
        $ps_cmd_4  = "DownloadString"     ascii nocase
        $ps_cmd_5  = "DownloadFile"       ascii nocase
        $ps_cmd_6  = "Net.WebClient"      ascii nocase
        $ps_cmd_7  = "Start-Process"      ascii nocase
        $ps_cmd_8  = "IEX"                ascii

        // Evasion flags.
        $ps_flag_1 = "-EncodedCommand"    ascii nocase
        $ps_flag_2 = "-enc "              ascii nocase
        $ps_flag_3 = "-WindowStyle Hidden" ascii nocase
        $ps_flag_4 = "-w hidden"          ascii nocase
        $ps_flag_5 = "-ExecutionPolicy Bypass" ascii nocase
        $ps_flag_6 = "-nop"              ascii nocase

    condition:
        // Must be a PE file.
        uint16(0) == 0x5A4D and

        // At least one PowerShell executable reference...
        any of ($ps_exe_*) and

        // ...combined with at least one dangerous cmdlet/method
        // OR at least one evasion flag.
        (
            any of ($ps_cmd_*) or
            any of ($ps_flag_*)
        )
}
