# Code Walkthrough: rules/upx_packer.yar

- **Purpose**: Detects executables packed with UPX (Ultimate Packer for eXecutables).
- **Inputs**: PE file bytes (scanned by YARA engine).
- **Outputs**: Match/no-match with metadata.
- **Dependencies**: YARA engine.
- **Callers**: `yara_scan.py` via `yara.compile()` and `compiled_rules.match()`.

---

## Lines 1-17: Rule comment

Explains that UPX is the most common open-source PE packer, that malware frequently uses it to evade signature detection, and documents the two detection methods: UPX section names and the UPX decompression marker.

## Lines 19-47: Rule definition

```yara
rule UPX_Packed_Executable
{
    meta:
        description = "Detects executables packed with UPX (Ultimate Packer for eXecutables)"
        author      = "PE-Sentinel"
        reference   = "https://upx.github.io/"
        severity    = "medium"
```

Metadata fields: description (extracted by `yara_scan.py:169`), author, reference URL, and severity level.

```yara
    strings:
        $upx_section_0 = "UPX0" ascii
        $upx_section_1 = "UPX1" ascii
        $upx_marker = "UPX!" ascii
        $upx_stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 }
```

Four string patterns:
- `$upx_section_0` and `$upx_section_1`: UPX section names in the PE section headers.
- `$upx_marker`: "UPX!" decompression marker.
- `$upx_stub`: byte pattern for the UPX decompression stub. `60` = PUSHAD, `BE` = MOV ESI. The `??` wildcards match any byte value.

```yara
    condition:
        uint16(0) == 0x5A4D and
        (
            ($upx_section_0 and $upx_section_1) or
            ($upx_marker and $upx_stub)
        )
}
```

Condition: file must start with "MZ" (PE file check), AND either both UPX section names are present OR both the marker and stub pattern are found.
