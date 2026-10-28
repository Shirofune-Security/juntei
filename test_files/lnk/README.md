# Shortcut test files

Shortcuts from the MIT-licensed test sets of three other LNK parsers, the same samples
ys-lnk-parser tests against. LnkParse3 keeps its samples base64-encoded; these are decoded.

| File | Source | Expected (`parse-lnk`) |
| --- | --- | --- |
| `opus_help.lnk` | [Eric Zimmerman's Lnk](https://github.com/EricZimmerman/Lnk) (`TestFiles/Win10/Opus 11 Help.lnk.test`, MIT, Copyright (c) Eric R. Zimmerman) | fixed drive, MFT entry 108088, machine `sagerez`, MAC `a4:34:d9:43:f3:63` |
| `msbuild_prompt.lnk` | Eric Zimmerman's Lnk (`TestFiles/Win10/MSBuild Command Prompt for VS2015.lnk.test`) | `cmd.exe /k` (shell started with arguments) |
| `network_share_unicode.lnk` | [lnk_parser](https://github.com/AbdulRhmanAlfaifi/lnk_parser) (`samples/WIN10/1607_14393`, MIT, Copyright (c) 2023 AbdulRhman Alfaifi) | network share `\\127.0.0.1\TEST` |
| `removable_drive.lnk` | [LnkParse3](https://github.com/Matmaus/LnkParse3) (`tests/samples/sample5`, MIT, Copyright (c) 2018 Silas Cutler, 2019 Matúš Jasnický) | removable drive, arguments `/b` |
| `padded_cli_arguments.lnk` | LnkParse3 (`tests/samples/padded_cli_arguments`) | string data claiming more than 260 characters, hiding 1,431 characters of arguments from parsers that trust the count; no terminal block |
| `appended_data.lnk` | LnkParse3 (`tests/samples/unknown_target`) | 67,649 bytes after the end of the link |

Every column these files share with LECmd has LECmd's value, except the target path of
`appended_data.lnk`, where LECmd shows damaged items.
