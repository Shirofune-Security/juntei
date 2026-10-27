# $MFT test file

`MFT` is the first 1,024 entries (1 MiB) of `samples/MFT` from Omer Ben-Amram's
[mft](https://github.com/omerbenamram/mft) repository (MIT / Apache-2.0), a Windows XP-era $MFT.
Entries whose parent directory lies beyond the cut have an `[Unknown]` path.

| | Expected (`parse-mft`) |
| --- | --- |
| Entries | 1,016 in use, 0 deleted (8 empty entries skipped) |
| Directories / files | 153 / 863 |
| Entries with alternate data streams | 2 (`$BadClus`, `$Secure`) |
| Resident `$DATA` streams | 24 |
| Paths | entry 0 `$MFT`, 5 `.`, 30 `WINDOWS/system32/config` |

The CSV, JSON and JSONL output of `parse-mft` and its extracted streams are byte-identical to
`mft_dump` of [ys-mft-parser](https://github.com/Yamato-Security/ys-mft-parser) on this file and on
the full 13 MB sample. Damaged inputs (a parent-reference cycle, an all-zero first record) are
crafted from this file by the tests.
