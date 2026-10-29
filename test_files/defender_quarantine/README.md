# Defender quarantine test files

`Quarantine/`: a Microsoft Defender quarantine folder written as Defender writes them, by
[ys-defender-history-parser](https://github.com/Yamato-Security/ys-defender-history-parser)'s
`tests/oracle/gen_quarantine.py` (MIT OR Apache-2.0; `tests/fixtures/written/Quarantine/` there).
Each part is RC4-encrypted with Defender's key, with the headers' sizes and CRCs and the contents'
SHA-1 names as Defender writes them; dissect.target's quarantine reader reads the same values from
it. The threat names, paths and identifiers are made up, and the quarantined "file" is a line of
text: nothing here is malware.

| File | What it is | Expected (`parse-defender-quarantine`) |
| --- | --- | --- |
| `Entries/{80012345-0000-0000-1A2B-3C4D5E6F7081}` | an entry: `HackTool:Win32/Example!MSR`, one file | `C:\Users\alice\Downloads\tool\tool.exe`, 61 bytes, owner `S-1-5-21-1111-2222-3333-1001`, `ZoneId` 3, `HostUrl` `https://example.com/tool.zip`, SHA-256 `828804761c959b70327e6b05c4cab83c30aafdcc193bc29209d41b15e6d9c358` |
| `ResourceData/AA/AAB535B2BF6E319A41A914FDF71F7509D42E847F`, `Resources/AA/…` | that file's content (its security descriptor, data and `Zone.Identifier` stream) and its resource record | |
| `Entries/{80054321-0000-0000-9A8B-7C6D5E4F3021}` | an entry: `Trojan:Win32/Example.A`, a service and a startup item | the service's content a hive (4,096 bytes) |
| `ResourceData/E2/E2600EF2CC97428CF2377419502B3D3330483F01` | the service's content: a registry hive's first bytes | |
| `ResourceData/5C/5CA5633C0E2AE818B85C5695677170EA42D55131` | a content no entry holds | an `orphan-content` record |
