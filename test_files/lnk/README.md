# Shortcut test files

Shortcuts from the public test sets of other LNK parsers. LnkParse3 keeps its samples
base64-encoded; these are decoded.

| File | Source | Expected (`parse-lnk`) |
| --- | --- | --- |
| `nero_infotool.lnk` | [plaso](https://github.com/log2timeline/plaso) (`test_data/NeroInfoTool.lnk`, Apache-2.0) | fixed drive, MFT entry 81349, machine `win-3qmdjgkf3g9`, MAC `70:5a:b6:16:a5:f3`, icon environment `%ProgramFiles%\Nero\…\InfoTool.exe` |
| `network_share_unicode.lnk` | [lnk_parser](https://github.com/AbdulRhmanAlfaifi/lnk_parser) (`samples/WIN10/1607_14393`, MIT, Copyright (c) 2023 AbdulRhman Alfaifi) | network share `\\127.0.0.1\TEST` |
| `cmd_powershell.lnk` | lnk_parser (`samples/mal/exec_cmd_powershell.lnk`) | `cmd.exe /c powershell.exe -c "Write-Host This is a test"` (shell started with arguments) |
| `removable_drive.lnk` | [LnkParse3](https://github.com/Matmaus/LnkParse3) (`tests/samples/sample5`, MIT, Copyright (c) 2018 Silas Cutler, 2019 Matúš Jasnický) | removable drive, arguments `/b` |
| `padded_cli_arguments.lnk` | LnkParse3 (`tests/samples/padded_cli_arguments`) | string data claiming more than 260 characters, hiding 1,431 characters of arguments from parsers that trust the count; no terminal block |
| `appended_data.lnk` | LnkParse3 (`tests/samples/unknown_target`) | 67,649 bytes after the end of the link |

Every column these files share with a reference LNK parser has its value, except the target path
of `appended_data.lnk`, where it shows damaged items; it refuses `padded_cli_arguments.lnk`.
