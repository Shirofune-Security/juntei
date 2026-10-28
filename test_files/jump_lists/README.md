# Jump list test files

Jump lists from the test sets ys-jump-lists-parser is checked against, with the values of Eric
Zimmerman's JLECmd.

| File | Source | Expected (`parse-jump-lists`) |
| --- | --- | --- |
| `f01b4d95cf55d32a.automaticDestinations-ms` | [Eric Zimmerman's JumpList](https://github.com/EricZimmerman/JumpList) (`TestFiles/Win10/f01b4d95cf55d32a.automaticDestinations-ms`, MIT, Copyright (c) Eric R. Zimmerman) | Windows 10 Explorer, `DestList` version 3: 9 entries; the most recent `C:\Temp` (entry 7, MFT entry 192) on `desktop-annfp9d` |
| `1b4dd67f29cb1962.automaticDestinations-ms` | Eric Zimmerman's JumpList (`TestFiles/Win7/1b4dd67f29cb1962.automaticDestinations-ms`) | Windows 7 Explorer, `DestList` version 1 (no interaction count; written as 0, as JLECmd does): 4 libraries on `win7x64` |
| `5f7b5f1e01b83767.automaticDestinations-ms` | [jumplist_parser](https://github.com/AbdulRhmanAlfaifi/jumplist_parser) (`samples/` at 647e8c7, MIT OR Apache-2.0, Copyright (c) AbdulRhman Alfaifi) | Windows 10 Quick Access, `DestList` version 6, the file ending inside its last sector: 37 entries; entry 1 is `D:\autorun.inf`, staged for a CD burn |
| `5d696d521de238c3.customDestinations-ms` | jumplist_parser (`samples/` at 647e8c7) | Windows 11 Chrome: "Most visited", "Recently closed" and two tasks, then the end of an earlier, longer version of the list with two more links (`http://192.168.50.33:5000/`, `http://192.168.50.33:3000/`); JLECmd refuses the file ("footer missing") |

Every column JLECmd writes for these files has JLECmd's value (times to the second, the precision
of its CSV).
