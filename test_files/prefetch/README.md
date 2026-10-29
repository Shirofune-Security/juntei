# Prefetch test files

From the test sets of [frnsc-prefetch](https://github.com/ForensicRS/frnsc-prefetch) (`artifacts/`,
MIT license, Copyright (c) 2024 Samuel Garcés Marín) and [artemis](https://github.com/puffycid/artemis)
(`forensics/tests/test_data/windows/prefetch/`, MIT license, Copyright (c) 2023 puffyCid).

| File | Source | Format version | Expected (`parse-prefetch`) |
| --- | --- | --- | --- |
| `CMD.EXE-087B4001.pf` | A public Prefetch test set (`TestFiles/XPPro/`, MIT, `LICENSE-test-set.txt`), also in frnsc-prefetch | 17 (Windows XP) | run count 2, 1 run time |
| `CONSENT.EXE-531BD9EA.pf` | artemis (`win7/`) | 23 (Windows 7) | run count 3, 1 run time, 72 file references |
| `CMD.EXE-4A81B364.pf` | artemis (`win81/`) | 26 (Windows 8.1) | run count 15, 8 run times |
| `CMD.EXE-6D6290C5.pf` | frnsc-prefetch | 30 (Windows 10), compressed | run count 4, 4 run times (2024-02-04 04:15:17 – 2024-02-05 06:17:41 UTC) |
| `RUST_OUT.EXE-5D2C8541.pf` | frnsc-prefetch | 30 (Windows 10), compressed | run count 1, run from `\USERS\…\APPDATA\LOCAL\TEMP\` (medium finding) |
| `corrupt/SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf` | frnsc-prefetch, also artemis | damaged compressed stream | could not be parsed |

Every value matches libscca (libyal's reference implementation).
