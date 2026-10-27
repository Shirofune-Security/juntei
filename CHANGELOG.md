# Changes

## 0.1.0 [xxxx/xx/xx]

**New Features:**

- First version of Juntei, a Windows forensics artifact parser. (@YamatoSecurity)
- `parse-amcache` command: parses `Amcache.hve` (modern Windows 10/11 and legacy Windows 8/8.1/Server 2012 R2 schemas) with Yamato Security's ys-amcache-parser: inventoried executables with SHA-1, PnP devices, and findings for system binaries outside `System32` and executables in staging directories. One file (`-f`) or every Amcache hive under a directory (`-d`); output to the terminal or saved as text, JSON, JSONL or CSV tables (`-o`, `-t`), with a Hayabusa-style progress bar and results summary. (@YamatoSecurity)
- `parse-mft` command: parses `$MFT` with Omer Ben-Amram's mft crate: one CSV row per entry (full path, flags, sizes, `$STANDARD_INFORMATION` / `$FILE_NAME` timestamps, alternate data streams) or every attribute as JSON / JSONL, the same output as its `mft_dump` command. One file (`-f`) or every `$MFT` under a directory (`-d`), entry ranges (`-r`), resident `$DATA` stream extraction (`-e`), a progress bar over the entries and a summary of in-use, deleted and damaged entries. Damaged or crafted records (a parent-reference loop, an unusable first record) no longer stop the run. (@YamatoSecurity)
