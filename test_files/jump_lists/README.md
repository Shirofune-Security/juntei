# Jump list test files

Jump lists from public test sets, with the values of a reference jump list parser.

| File | Source | Expected (`parse-jump-lists`) |
| --- | --- | --- |
| `f01b4d95cf55d32a.automaticDestinations-ms` | The [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)'s `Windows/JumpLists/Win10/RathbunVM/` (MIT, Copyright (c) 2022 DFIR Artifact Museum) | Windows 10 Explorer, `DestList` version 4: 9 entries, 4 pinned; entry 7 is `C:\Users\AndrewRathbun\Desktop\Targets` (MFT entry 105479) on `desktop-gnccvrk` |
| `9b9cdc69c1c24e2b.automaticDestinations-ms` | The DFIR Artifact Museum's `Windows/JumpLists/Win2012R2/StolenSzechuan/` | Notepad on Windows Server 2012 R2, `DestList` version 1 (no interaction count; written as 0): 5 files in `C:\FileShare\Secret` on `citadel-dc01`, with the network share `\\CITADEL-DC01\FileShare` |
| `5f7b5f1e01b83767.automaticDestinations-ms` | [jumplist_parser](https://github.com/AbdulRhmanAlfaifi/jumplist_parser) (`samples/` at 647e8c7, MIT OR Apache-2.0, Copyright (c) AbdulRhman Alfaifi) | Windows 10 Quick Access, `DestList` version 6, the file ending inside its last sector: 37 entries; entry 1 is `D:\autorun.inf`, staged for a CD burn |
| `5d696d521de238c3.customDestinations-ms` | jumplist_parser (`samples/` at 647e8c7) | Windows 11 Chrome: "Most visited", "Recently closed" and two tasks, then the end of an earlier, longer version of the list with two more links (`http://192.168.50.33:5000/`, `http://192.168.50.33:3000/`); the reference refuses the file (its footer is missing) |

Every column the reference writes for these files has its value, times to 100 ns.
