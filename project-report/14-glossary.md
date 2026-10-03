# 14 — Glossary

| Term | Definition |
|------|-----------|
| **Authenticode** | Microsoft's code-signing technology. PE files can contain an embedded Authenticode signature in the SECURITY data directory (index 4). PE-Sentinel checks for the presence of this directory entry but does not validate the cryptographic chain. (`pe_parser.py:308-328`) |
| **Band** | One of three verdict categories: CLEAN (0-30), SUSPICIOUS (31-60), MALICIOUS (61-100). Assigned by `compute_verdict()` based on the final score. (`verdict.py:299-305`) |
| **Base64 Blob** | A long run of Base64-legal characters found in a PE file's strings. May indicate an encoded payload. Detected by the regex at `strings.py:99-101` with a minimum length of 40 characters. |
| **Benign IP** | An IPv4 address that is expected in PE files and should not be flagged as suspicious: 0.0.0.0, 127.0.0.1, 255.255.255.255, 1.0.0.0, 0.0.0.1. (`strings.py:107-110`) |
| **BSS** | A PE section containing uninitialized data. Has a raw size of 0 on disk and a nonzero virtual size in memory. Excluded from entropy analysis. |
| **Cap** | A maximum point limit for a scoring category. Prevents any single signal type from dominating the final score. Example: YARA matches cap at 30 points. (`verdict.py:72`) |
| **COFF Header** | The Common Object File Format header within a PE file. Contains the machine type and compile timestamp fields. Accessed via `pefile.PE().FILE_HEADER`. |
| **Combo** | A suspicious combination of imported APIs that is a stronger signal than any individual import. Four combos are defined in `SUSPICIOUS_COMBOS` (`pe_parser.py:93-112`). Example: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. |
| **Data Directory** | An array of 16 entries in the PE Optional Header, each pointing to a specific data structure. Index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY (Authenticode). (`pe_parser.py:317`) |
| **DOS Header** | The first structure in a PE file. Starts with the "MZ" magic bytes. Contains the `e_lfanew` pointer at offset 0x3C that locates the PE signature. |
| **e_lfanew** | A 4-byte little-endian unsigned integer at offset 0x3C in the DOS header. Points to the location of the PE signature within the file. (`fingerprint.py:79`) |
| **Entropy** | Shannon entropy, a measure of randomness/information density in data. Measured on a 0-8 scale for bytes. Compiled code: 4.5-6.5. Packed/encrypted: 7.0-7.9. (`entropy.py:65-92`) |
| **FileFingerprint** | A dataclass containing file identity data: path, name, size, SHA-256, MD5, PE validation status. The first result produced in the analysis pipeline. (`fingerprint.py:22-36`) |
| **IOC** | Indicator of Compromise. A forensic artifact (IP address, URL, file hash, registry key) that indicates malicious activity. PE-Sentinel's string patterns detect several IOC types. |
| **LOLBin** | Living-Off-the-Land Binary. A legitimate system binary (like certutil.exe) abused by attackers for malicious purposes. Referenced in `README.md:323-325`. |
| **MITRE ATT&CK** | A knowledge base of adversary tactics and techniques. Referenced in `pe_parser.py:31` as the source for the suspicious import list. |
| **MZ** | The two-byte magic number (0x4D 0x5A) at the start of every PE file. Named after Mark Zbikowski, a Microsoft developer. (`fingerprint.py:66-67`) |
| **Packing** | The practice of compressing or encrypting a PE file's contents. The packed binary contains a decompression stub that restores the original code at runtime. Detected by high entropy and virtual/raw size mismatches. |
| **PE** | Portable Executable. The file format for executables (.exe), DLLs (.dll), and other binary types on Windows. Based on COFF (Common Object File Format). |
| **PE Signature** | The 4-byte sequence `PE\0\0` (0x50 0x45 0x00 0x00) located at the offset pointed to by e_lfanew. Confirms the file is a PE, not just a DOS executable. |
| **pefile** | A Python library for parsing PE files. Used in `pe_parser.py` and `entropy.py`. |
| **Pipeline** | The fixed sequence of analysis stages: fingerprint, PE parse, entropy, strings, YARA, verdict. Implemented in `_analyze_single_file()` (`main.py:36-71`). |
| **Process Hollowing** | A code injection technique where an attacker creates a process in a suspended state, replaces its code with malicious code, then resumes it. Detected by the NtUnmapViewOfSection + SuspendThread import combination. |
| **Score** | A 0-100 integer representing the suspiciousness of a PE file. Computed by `compute_verdict()` from weighted signals. Clamped to the 0-100 range. |
| **Section Table** | A list of sections in a PE file (e.g., .text, .data, .rsrc). Each section has a name, virtual size, raw size, and characteristics flags. |
| **Shannon Formula** | H = -SUM(p(x) * log2(p(x))) for each distinct byte value x in the data. Used in `_shannon_entropy()`. |
| **Size Mismatch** | When a PE section's virtual size is significantly larger (3x or more) than its raw size. Indicates the section is decompressed at load time — a packing indicator. |
| **SUSPICIOUS_IMPORTS** | A curated dictionary of approximately 38 Windows API functions commonly abused by malware, mapped to explanations. (`pe_parser.py:33-89`) |
| **UPX** | Ultimate Packer for eXecutables. The most common open-source PE packer. Detected by the `upx_packer.yar` YARA rule. |
| **Verdict** | The final classification of a PE file: CLEAN, SUSPICIOUS, or MALICIOUS. Represented by the `Verdict` dataclass (`verdict.py:117-123`). |
| **YARA** | An open-source pattern matching engine used to identify and classify malware. Rules are written in a domain-specific language and stored in `.yar` files. |
| **yara-python** | Python bindings for the YARA engine. Optional dependency — the tool degrades gracefully if unavailable. (`yara_scan.py:22-28`) |
