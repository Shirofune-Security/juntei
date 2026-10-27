# Prefetch test files

The same files ys-prefetch-parser tests with: the first five come from
[frnsc-prefetch](https://github.com/ForensicRS/frnsc-prefetch) (`artifacts/`, MIT license,
Copyright (c) 2024 Samuel Garcés Marín), the damaged one also from
[artemis](https://github.com/puffycid/artemis) (MIT).

| File | Format version | Expected (`parse-prefetch`) |
| --- | --- | --- |
| `CMD.EXE-087B4001.pf` | 17 (Windows XP) | run count 2, 1 run time |
| `NOTEPAD.EXE-D8414F97.pf` | 23 (Windows 7) | run count 2, 1 run time |
| `CMD.EXE-4A81B364.pf` | 26 (Windows 8.1) | run count 2, 2 run times |
| `CMD.EXE-6D6290C5.pf` | 30 (Windows 10), compressed | run count 4, 4 run times (2024-02-04 04:15:17 – 2024-02-05 06:17:41 UTC) |
| `RUST_OUT.EXE-5D2C8541.pf` | 30 (Windows 10), compressed | run count 1, run from `\USERS\…\APPDATA\LOCAL\TEMP\` (medium finding) |
| `corrupt/SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf` | damaged compressed stream | could not be parsed |

Every value matches libscca (libyal's reference implementation).
