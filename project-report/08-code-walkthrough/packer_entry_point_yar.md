# Code Walkthrough: rules/packer_entry_point.yar

- **Purpose**: Detects common packer/crypter entry-point byte signatures (ASPack, PECompact, MPRESS, Themida, generic PUSHAD stubs).
- **Inputs**: PE file bytes.
- **Outputs**: Match/no-match with metadata.
- **Dependencies**: YARA engine.
- **Callers**: `yara_scan.py`.

---

## Lines 1-21: Rule comment

Explains that packed PE files have their original entry point replaced with a decompression stub, and documents five specific packer signatures with their byte-level disassembly.

## Lines 23-79: Rule definition

```yara
rule Packer_Entry_Point_Signature
{
    meta:
        description = "Detects common packer/crypter entry-point byte signatures ..."
        author      = "PE-Sentinel"
        severity    = "medium"
```

Severity "medium" — same as UPX, since packing alone is not proof of malice.

```yara
    strings:
        $aspack_ep = { 60 E8 03 00 00 00 E9 }
        $pecompact_ep = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }
        $mpress_ep = { 60 E8 00 00 00 00 58 }
        $generic_pushad = { 60 E8 ?? ?? ?? ?? }
        $themida_ep = { B8 ?? ?? ?? ?? 60 0B C0 }
```

Five byte patterns for different packers. Each is annotated in comments with the corresponding x86 disassembly. `??` are wildcard bytes (match any value). The patterns are documented in the rule comments (lines 31-58) with instruction-level explanations.

```yara
    condition:
        uint16(0) == 0x5A4D and
        (
            $aspack_ep or
            $pecompact_ep or
            $mpress_ep or
            $themida_ep or
            $generic_pushad at 0
        )
}
```

PE file check, then any of the specific packer patterns. The `$generic_pushad at 0` constraint limits the generic PUSHAD+CALL pattern to offset 0 to reduce false positives — the comment (lines 74-77) explains this is a rough heuristic. Note: offset 0 means the start of the file (MZ header area), which is unusual for an entry-point check. In practice, the MZ header bytes would not match the `60 E8` pattern, so this constraint effectively means the generic pattern almost never fires. This may be a bug — the intent was likely to constrain it to near the entry point. [Inferred]
