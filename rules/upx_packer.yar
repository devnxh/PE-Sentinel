/*
  upx_packer.yar — Detect UPX-packed executables.

  UPX (Ultimate Packer for eXecutables) is the most common open-source
  PE packer.  While UPX itself is legitimate, malware authors frequently
  use it to compress their payloads and evade simple signature-based
  detection.

  Detection method:
    - UPX leaves characteristic section names ("UPX0", "UPX1", "UPX2")
      in the PE section table.
    - The UPX stub also contains the ASCII string "UPX!" near the end
      of the packed data as a decompression marker.

  These signatures survive even when the binary is stripped, because
  they are part of the UPX decompressor stub itself.
*/

rule UPX_Packed_Executable
{
    meta:
        description = "Detects executables packed with UPX (Ultimate Packer for eXecutables)"
        author      = "PE-Sentinel"
        reference   = "https://upx.github.io/"
        severity    = "medium"

    strings:
        // UPX section names — these appear in the PE section headers.
        $upx_section_0 = "UPX0" ascii
        $upx_section_1 = "UPX1" ascii

        // The UPX decompression stub marker.
        $upx_marker = "UPX!" ascii

        // Alternative: some UPX versions use this stub signature.
        $upx_stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 }

    condition:
        // Must be a PE file (MZ header).
        uint16(0) == 0x5A4D and

        // Match if we see UPX section names OR the UPX marker + stub.
        (
            ($upx_section_0 and $upx_section_1) or
            ($upx_marker and $upx_stub)
        )
}
