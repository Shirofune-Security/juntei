# ShimCache test files

A `SYSTEM` hive with its transaction logs and AppCompatCache values from the test sets
ys-shimcache-parser is checked against, with the values of a reference parser.

| File | Source | Expected (`parse-shimcache`) |
| --- | --- | --- |
| `SYSTEM.gz`, `SYSTEM.LOG1.gz`, `SYSTEM.LOG2.gz` | The [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)'s `Windows/Registry/Win11/RathbunVM/RathbunVM_W11RegistryHives.7z` (MIT, Copyright (c) 2022 DFIR Artifact Museum), gzipped; the tests unpack them | a dirty Windows 11 hive whose logs apply 16 entries: `ControlSet001`, 359 entries, 30 executed, 27 findings |
| `SYSTEM.expected.csv` | The reference's CSV output for that hive, `SourceFile` set to `SYSTEM` | every row: `parse-shimcache`'s first 8 columns have its values (its times to the second) |
| `WinXPx86.bin`, `win7x86.bin`, `Win80.bin` | The DFIR Artifact Museum's `Windows/AppCompatCache/` | Windows XP: 17 entries in the order of its LRU array, no execution flag; 32-bit Windows 7: 91 entries, 75 executed; Windows 8.0 (first dword 0): 104 entries, 88 executed |
| `win11shim.raw` | [artemis](https://github.com/puffyCid/artemis) (`forensics/tests/test_data/windows/shimcache/`, MIT, Copyright (c) 2023 puffyCid) | Windows 11: 2 entries, x64, not executed |
