# Changes

## 0.1.0 [xxxx/xx/xx]

**New Features:**

- First version of Juntei, a Windows forensics artifact parser. (@YamatoSecurity)
- `parse-amcache` command: parses `Amcache.hve` (modern Windows 10/11 and legacy Windows 8/8.1/Server 2012 R2 schemas) with Yamato Security's ys-amcache-parser: inventoried executables with SHA-1, PnP devices, and findings for system binaries outside `System32` and executables in staging directories. One file (`-f`) or every Amcache hive under a directory (`-d`); output to the terminal or saved as text, JSON, JSONL or CSV tables (`-o`, `-t`), with a Hayabusa-style progress bar and results summary. (@YamatoSecurity)
