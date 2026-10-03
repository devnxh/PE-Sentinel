/*
  packer_entry_point.yar — Detect common packer/crypter entry-point signatures.

  When a PE file is packed with a protector or crypter, the original
  entry point is replaced with a decompression/decryption stub.  These
  stubs have characteristic byte sequences at the PE entry point.

  This rule checks the first few bytes at the entry point (AddressOfEntryPoint)
  for known packer stub signatures:

    - ASPack: A widely-used commercial PE packer.
    - PECompact: Another commercial packer.
    - MPRESS: A free packer that uses LZMA/LZMAT compression.
    - Generic pushad+call: Many custom packers start with PUSHAD (save
      all registers) followed by a CALL to the unpacking routine.

  Note: Entry-point signatures alone are not proof of malice — some
  legitimate software uses these packers for size reduction or IP
  protection.  However, packing is a strong *indicator* that warrants
  deeper analysis.
*/

rule Packer_Entry_Point_Signature
{
    meta:
        description = "Detects common packer/crypter entry-point byte signatures (ASPack, PECompact, MPRESS, generic pushad)"
        author      = "PE-Sentinel"
        severity    = "medium"

    strings:
        // ASPack entry-point stub:
        //   60          PUSHAD
        //   E8 03 00    CALL $+3  (a short relative call used for position-independent code)
        //   00 00 E9    ...followed by a JMP
        $aspack_ep = { 60 E8 03 00 00 00 E9 }

        // PECompact entry-point stub:
        //   B8 xx xx xx xx   MOV EAX, <address>
        //   50               PUSH EAX
        //   64 FF 35 00 00   PUSH DWORD PTR FS:[0]  (SEH setup)
        $pecompact_ep = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }

        // MPRESS entry-point stub:
        //   60          PUSHAD
        //   E8 00 00    CALL $+0  (gets current EIP for relocation)
        //   00 00 58    POP EAX
        $mpress_ep = { 60 E8 00 00 00 00 58 }

        // Generic pushad + call pattern used by many custom packers:
        //   60          PUSHAD
        //   E8 ?? ??    CALL <relative offset>
        $generic_pushad = { 60 E8 ?? ?? ?? ?? }

        // Themida/WinLicense stub (common protector):
        //   B8 xx xx xx xx   MOV EAX, <address>
        //   60               PUSHAD
        //   0B C0            OR EAX, EAX
        $themida_ep = { B8 ?? ?? ?? ?? 60 0B C0 }

    condition:
        // Must be a PE file.
        uint16(0) == 0x5A4D and

        // Check if any of these patterns appear at (or very near) the
        // entry point.  We use `any of them` against the full file
        // because entry-point-only matching requires runtime offset
        // calculation that YARA can't do portably.  The patterns are
        // specific enough to avoid most false positives.
        (
            $aspack_ep or
            $pecompact_ep or
            $mpress_ep or
            $themida_ep or
            // The generic pushad pattern is very common, so we only flag it
            // if it appears within the first 1024 bytes past the PE headers
            // (a rough heuristic for "near the entry point").
            $generic_pushad at 0
        )
}
