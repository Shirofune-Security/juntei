# Juntei

Juntei is a Windows forensics artifact parser by [Yamato Security](https://github.com/Yamato-Security),
a sibling of [Hayabusa](https://github.com/Yamato-Security/hayabusa) for the artifacts that are
not event logs.

## Supported artifacts

| Artifact | Command | Status |
| --- | --- | --- |
| Amcache (`Amcache.hve`) | `parse-amcache` | Supported |
| `$MFT` | `parse-mft` | Supported |
| Prefetch (`*.pf`) | `parse-prefetch` | Supported |
| USN journal (`$UsnJrnl:$J`) | `parse-usn-journal` | Supported |
| SRUM (`SRUDB.dat`) | `parse-srum` | Supported |
| Shortcuts (`*.lnk`) | `parse-lnk` | Supported |
| Jump lists (`*.automaticDestinations-ms`, `*.customDestinations-ms`) | `parse-jump-lists` | Supported |
| ShimCache / AppCompatCache (`SYSTEM` hive) | `parse-shimcache` | Supported |
| More Windows artifacts | | Planned |

## Build

```
git clone https://github.com/Yamato-Security/juntei.git
cd juntei
cargo build --release
```

The binary is `target/release/juntei`.

## Usage

```
juntei <COMMAND> [OPTIONS]
```

Run `juntei` to list the commands and `juntei <COMMAND> -h` for the options of one. While results
are saved to a file, a Hayabusa-style progress bar shows the file being parsed, and every run ends
with a results summary.

### `parse-amcache`

Parses `Amcache.hve` (`C:\Windows\AppCompat\Programs\Amcache.hve`), the Windows
application-compatibility inventory, in the modern (Windows 10/11) and legacy (Windows 8/8.1,
Server 2012 R2) schemas:

- **Executables** (`InventoryApplicationFile`): path, SHA-1, publisher, versions, size, link date
  and every other recorded value. An entry shows that a file was present, not that it ran.
- **PnP devices** (`InventoryDevicePnp`): description, hardware IDs, driver and install dates.
- **Findings**: a Windows system binary name outside `System32`/`SysWOW64` (high, T1036.005), and
  an executable in a directory often used to stage malware (medium, T1204).

```
Input:
  -d, --directory <DIR>  Directory to search recursively for Amcache hives (Amcache.hve)
  -f, --file <FILE>      File path to one Amcache.hve

Records:
      --files    Include every inventoried executable (InventoryApplicationFile)
      --devices  Include every inventoried PnP device (InventoryDevicePnp)
  -a, --all      Include executables and devices (default for -o and for json, jsonl, csv)

Output:
  -o, --output <PATH>       Save the results to a file (text, json, jsonl) or a directory (csv)
  -t, --output-type <TYPE>  Output type: csv (default with -o), json, jsonl, text (default on the terminal)
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Summary and findings on the terminal
juntei parse-amcache -f Amcache.hve

# ... with every executable
juntei parse-amcache -f Amcache.hve --files

# Every hive of a triage collection as CSV tables
juntei parse-amcache -d triage/ -o amcache-csv

# One JSON document
juntei parse-amcache -f Amcache.hve -o amcache.json -t json

# JSON Lines on stdout, for jq
juntei parse-amcache -f Amcache.hve -t jsonl | jq 'select(.record_type == "file" and .sha1 != null)'
```

- On the terminal, the report has the summary and the findings; `--files`, `--devices` or `-a`
  add the records. Saved results and JSON / JSONL / CSV include every record unless `--files` or
  `--devices` narrows them.
- CSV output is a directory of four tables: `<name>_summary.csv`, `_findings.csv`, `_files.csv`
  and `_devices.csv`. With `-d`, each hive gets its own subdirectory named after its path
  (`HOST1/C/Windows/AppCompat/Programs/Amcache.hve` → `HOST1_C_Windows_AppCompat_Programs_Amcache/`).
- With `-d`, files named `Amcache.hve` (or any `*.hve` with `amcache` in its name) are parsed;
  `.LOG1` / `.LOG2` transaction logs are not applied.
- JSON / JSONL written to stdout (no `-o`) contain only the data; messages go to stderr.

Amcache parsing and the output formats come from Yamato Security's
[ys-amcache-parser](https://github.com/Yamato-Security/ys-amcache-parser) (Apache-2.0), a fork of
Albert Hui's [amcache-forensic](https://github.com/SecurityRonin/amcache-forensic). See its
[output documentation](https://github.com/Yamato-Security/ys-amcache-parser/blob/main/docs/output.md)
for every field.

### `parse-mft`

Parses the NTFS Master File Table (`$MFT`): one record per file and directory, including deleted
ones, with the full path, flags, sizes, `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps,
alternate data streams and the timestomping indicators. The CSV has the columns of Eric
Zimmerman's MFTECmd, computed as MFTECmd computes them.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for $MFT files
  -f, --file <FILE>      File path to one $MFT

Filtering:
  -r, --ranges <RANGES>  Parse only these entry numbers (ex: 0-15,30)

Output:
  -o, --output <PATH>                   Save every entry to a file (with -d: a directory with one file per $MFT)
  -t, --output-type <TYPE>              Output type: csv (default, MFTECmd's columns), ys-mft-parser-csv, json, jsonl. Without -o, the entries are written to stdout
  -e, --extract-resident-streams <DIR>  Write the resident $DATA streams (the content of small files and alternate data streams) to files in DIR
  -C, --clobber                         Overwrite files when saving

CSV Output:
      --all-times      Write every $FILE_NAME time, not only those that differ from $STANDARD_INFORMATION (MFTECmd's --at)
      --short-names    Write rows for DOS (8.3) names too (MFTECmd's --sn)
      --cutoff <DATE>  Only records whose $STANDARD_INFORMATION created or modified time is on or after DATE, in UTC unless an offset is given (ex: 2025-10-19, 2025-10-19T13:45:30Z)

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Entry counts (in use, deleted, directories, alternate data streams, damaged entries)
juntei parse-mft -f '$MFT'

# Every file name and alternate data stream as CSV, with MFTECmd's columns
juntei parse-mft -f '$MFT' -o mft.csv

# Only what was created or modified since an incident began, every $FILE_NAME time included
juntei parse-mft -f '$MFT' -o recent.csv --cutoff 2025-10-19 --all-times

# The $MFT of every host in a triage collection, one JSONL file each
juntei parse-mft -d triage/ -o mft-jsonl -t jsonl

# Entries 0-15 and 30 as JSON Lines on stdout
juntei parse-mft -f '$MFT' -t jsonl -r 0-15,30

# The content of small files and alternate data streams stored in the $MFT itself
juntei parse-mft -f '$MFT' -e resident-streams
```

- Without `-o` or `-t`, only the summary is shown.
- CSV has MFTECmd's 35 columns and rows, in its order (in-use records, then free ones): one row
  per file name (hard links each have one; DOS 8.3 names only with `--short-names`) and one more
  per alternate data stream (`IsAds`, with `ZoneIdContents` for `Zone.Identifier`). The columns
  include the parent entry and sequence numbers, `ParentPath` as MFTECmd builds it (`.\Windows\System32`;
  `.\PathUnknown\Directory with ID 0x…` when the chain doesn't reach the root), `FileName` and
  `Extension`, both sets of four timestamps (the `0x30` ones only where they differ, unless
  `--all-times`), `UpdateSequenceNumber`, `LogfileSequenceNumber`, `SecurityId`, `SiFlags`,
  `NameType`, `ReferenceCount`, `ReparseTarget`, `ObjectIdFileDroid`, `LoggedUtilStream`, and the
  timestomping indicators: `SI<FN` (`$STANDARD_INFORMATION` created before a different `$FILE_NAME`
  created), `uSecZeros` (created or modified on a whole millisecond) and `Copied` (modified before
  created). Times are RFC 3339 UTC with NTFS's 100 ns (`2007-06-30T12:50:52.2523952Z`), as in
  juntei's other output; MFTECmd writes `2007-06-30 12:50:52.2523952`. `ParseErrors` holds
  juntei's own descriptions of damaged records and of their extension records (MFTECmd leaves
  the extension records' out).
- `-t ys-mft-parser-csv` has the columns of the `ys-mft-parser` command's CSV instead (upstream's
  `mft_dump`; `-t mft-dump-csv` still works): one row per entry, ending with the
  `$STANDARD_INFORMATION` and `$FILE_NAME` MFT-modified times. JSON / JSONL have every attribute
  of every entry and its `full_path`. Times keep the 100 ns precision of NTFS (7 decimal places).
- With `-d`, files named `$MFT` (or ending in `$MFT`) are parsed; `-o` is a directory with one
  file per `$MFT`, named after its path (`HOST1/C/$MFT` → `HOST1_C__MFT.csv`).
- In ys-mft-parser's CSV and in JSON, full paths use `\`, as Windows shows them, with the long names
  that extension records hold. A file whose parent directory's record was reused is `[Orphaned]` (unless the old directory left its
  name in an extension record); a deleted file in a deleted directory keeps its path; a parent that
  can't be read is `[Unknown]`.
- Extracted streams are named `<full path>__<entry>-<sequence>_<stream number>_<stream name>.dontrun`
  and include the streams stored in extension records; empty streams are not written. Characters
  that are unsafe in file names become `_`. They are evidence: do not run them.
- Damaged or crafted records do not crash the run: a file without a usable FILE record header is
  skipped, a parent-reference loop is cut (an `[Orphaned]` path), and unreadable entries are
  counted.

$MFT parsing, ys-mft-parser's CSV and the JSON format come from Yamato Security's
[ys-mft-parser](https://github.com/Yamato-Security/ys-mft-parser), a maintained fork of Omer
Ben-Amram's [mft](https://github.com/omerbenamram/mft) crate (MIT / Apache-2.0). On eight `$MFT`
files (the mft crate's sample, the NIST hacking case and six from DFIRArtifactMuseum; 1,048,733
rows), every row and column of the CSV, in order, equals MFTECmd 2026.10.6's (built from source),
with and without `--all-times` and `--short-names` and with `--cutoff`, apart from the time format.

### `parse-prefetch`

Parses Windows Prefetch files (`C:\Windows\Prefetch\*.pf`) from Windows XP to Windows 11
(format versions 17, 23, 26, 30 and 31, including the compressed files of Windows 8 and later):
the executable, how many times it ran, its last eight run times, the volumes, directories and files
it loaded (with their NTFS file references), and findings.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for prefetch files (*.pf)
  -f, --file <FILE>      File path to one prefetch file

Records:
  -T, --timeline  One record per execution (the last 8 run times of every file), sorted by time

Output:
  -o, --output <FILE>       Save every record to a file
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Summary and high findings on the terminal
juntei parse-prefetch -d Prefetch/

# One CSV row per prefetch file
juntei parse-prefetch -d Prefetch/ -o prefetch.csv

# One row per execution, sorted by time, for a timeline
juntei parse-prefetch -d Prefetch/ -T -o prefetch-timeline.csv

# Every field (volumes, directories, loaded files with file references) as JSON Lines
juntei parse-prefetch -d Prefetch/ -o prefetch.jsonl -t jsonl
```

- Without `-o` or `-t`, only the summary is shown. With `-d`, every `*.pf` file under the
  directory goes into one output; the `SourceFile` column tells them apart.
- CSV columns: `SourceFile`, `ExecutableName`, `ExecutablePath`, `PrefetchHash`, `FormatVersion`,
  `RunCount`, `LastRun`, `PreviousRun1`–`PreviousRun7`, `VolumeCount`, `VolumeDevicePaths`,
  `VolumeSerialNumbers`, `VolumeCreated`, `DirectoryCount`, `FileCount`, `Findings`, `Files`,
  `Directories` (lists are joined with `, `). With `-T`: `RunTime`, `ExecutableName`,
  `ExecutablePath`, `PrefetchHash`, `RunCount`, `SourceFile`.
- Times are UTC (RFC 3339) with the 100 ns precision of the file. Windows keeps the last 8 run
  times (only the last one before Windows 8); the run count covers every run.
- `ExecutablePath` is the loaded file with the executable's name. Windows stores at most 29
  characters of the name, so a longer name is resolved when exactly one loaded file starts with it;
  otherwise the column holds the name.
- Findings (following [prefetch-forensic](https://github.com/SecurityRonin/prefetch-forensic)'s
  audit, with the lists of [forensicnomicon](https://crates.io/crates/forensicnomicon)):
  `SystemBinaryRelocated` (high, T1036.005), a Windows system binary loaded from outside
  `System32` / `SysWOW64`; `SuspiciousExecutionPath` (medium, T1204), an executable run from a
  staging directory such as `Temp`, `Downloads`, `ProgramData` or `Users\Public`. Installers raise
  the medium one often, so the summary lists only the high findings.
- Damaged files are reported and skipped; they do not stop the run.

Prefetch parsing comes from Yamato Security's
[ys-prefetch-parser](https://github.com/Yamato-Security/ys-prefetch-parser), a maintained fork of
Samuel Garcés Marín's [frnsc-prefetch](https://github.com/ForensicRS/frnsc-prefetch) crate (MIT)
whose output matches libscca, libyal's reference implementation.

### `parse-usn-journal`

Parses the NTFS USN change journal (`$Extend\$UsnJrnl:$J`): every change Windows recorded to every
file of a volume (created, written, renamed, deleted, …), with the full path its directory had *at
the time of the record*. Records of format versions 2 and 3 (and the range-tracking version 4 in
JSON) are read straight through the gigabytes of sparse zeros a collected `$J` starts with.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for USN journals ($J)
  -f, --file <FILE>      File path to one USN journal ($J), or with --carve any file
  -m, --mft <FILE>       The volume's $MFT, for paths (default: the $MFT next to the journal's $Extend directory)
      --carve            Carve records out of a disk image, unallocated space or any other file that is not a journal

Output:
  -o, --output <PATH>       Save every record to a file (with -d: a directory with one file per journal)
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Record counts, time range, creates / deletes / renames and damage on the terminal
juntei parse-usn-journal -f 'C/$Extend/$J'

# Every record as CSV, with paths from the volume's $MFT
juntei parse-usn-journal -f 'C/$Extend/$J' -m 'C/$MFT' -o usnjrnl.csv

# Every journal of a triage collection (each with the $MFT of its volume), one JSONL file each
juntei parse-usn-journal -d triage/ -o usn-jsonl -t jsonl

# Records that survive in a disk image or unallocated space
juntei parse-usn-journal -f disk.raw --carve -o carved.csv
```

- CSV has MFTECmd's `$J` columns, in its order (`Name`, `Extension`, `EntryNumber`, `SequenceNumber`,
  `ParentEntryNumber`, `ParentSequenceNumber`, `ParentPath`, `UpdateSequenceNumber`,
  `UpdateTimestamp`, `UpdateReasons`, `FileAttributes`, `OffsetToData`, `SourceFile`), then
  `SourceInfo`, `SecurityId` and `Version`. Reasons and attributes use Windows' names joined with `|`
  (`FILE_CREATE|CLOSE`), unknown bits in hex. JSON / JSONL have every field, and the range-tracking
  (V4) records with their extents.
- Paths are rewound: the journal is read twice, once to learn every directory's renames, moves,
  creations and deletions, once to give each record the path its directory had then. With the
  volume's `$MFT` (`-m`, or found next to the journal's `$Extend` directory in KAPE-style layouts),
  directories the journal does not name are known too. A directory nobody knows shows as
  `[Unknown <entry>-<sequence>]`. On six real journals, the paths equal MFTECmd's `ParentPath`
  wherever MFTECmd resolves one, and 4,321 records MFTECmd leaves as `PathUnknown` are resolved.
- With `-d`, files named `$J` (or ending in `$J`) are parsed; `-o` is a directory with one file per
  journal, named after its path (`HOST1/C/$Extend/$J` → `HOST1_C__Extend__J.csv`).
- `--carve` reads any file 8 bytes at a time and keeps only records laid out exactly as NTFS writes
  them (no false positives in 880 MB of `$MFT` data); `OffsetToData` is the offset in that file.
  Paths come from the `$MFT` given with `-m`, as it is now.
- Damaged data (bytes that are not records, a record cut off at the end) is reported and skipped.

USN journal parsing comes from Yamato Security's
[ys-usn-journal-parser](https://github.com/Yamato-Security/ys-usn-journal-parser), a maintained fork
of [sootmark-usn](https://github.com/Sootmark/usn) (MIT OR Apache-2.0).

### `parse-srum`

Parses the System Resource Usage Monitor database (`Windows\System32\sru\SRUDB.dat`): about 30
days of what every program did, hour by hour, per user: bytes sent and received on which network
interface, CPU time and disk activity in the foreground and background, network connections,
energy use and the application timeline. Evidence of exfiltration and of programs that ran, kept
after they were deleted. SRUM is kept from Windows 8 on; databases of Windows 10, 11 and Windows
Server 2022 (with its own providers) are tested.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for SRUM databases (SRUDB.dat)
  -f, --file <FILE>      File path to one SRUM database (SRUDB.dat)
  -r, --software <FILE>  The SOFTWARE hive, for account and Wi-Fi names (default: config/SOFTWARE of the same Windows, or a SOFTWARE next to the database)

Output:
  -o, --output <PATH>       Save every entry: a directory of CSV tables, or a file (json, jsonl; with -d a directory with one file per database)
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, json and jsonl entries are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Entries per table, time range, bytes sent and received, the top senders
juntei parse-srum -f C/Windows/System32/sru/SRUDB.dat

# Every table as CSV, with account and Wi-Fi names from the SOFTWARE hive
juntei parse-srum -f SRUDB.dat -r SOFTWARE -o srum-csv

# Every host of a triage collection (each with the SOFTWARE hive of its Windows)
juntei parse-srum -d triage/ -o srum

# JSON Lines on stdout, for jq
juntei parse-srum -f SRUDB.dat -t jsonl | jq 'select(.Provider == "NetworkUsages")'
```

- CSV output is a directory with one table per provider, named as Eric Zimmerman's SrumECmd names
  them (`NetworkUsages.csv`, `AppResourceUseInfo.csv`, `NetworkConnections.csv`,
  `AppTimelineProvider.csv`, `vfuprov.csv`, `EnergyUsage.csv` with the long-term table's rows
  marked by `IsLt`, `PushNotifications.csv`, and on Windows Server `ProcessorTime.csv`,
  `SizeInBytes.csv`, `TotalUsed.csv`, `NetworkBytes.csv`), a table it doesn't know under its own
  name, and `SruDbIdMapTable.csv`, the ids the entries refer to. JSON / JSONL have one object per
  entry with the same columns, after `SourceFile`, `Table` and `Provider`.
- Every table starts with SrumECmd's columns: `Id`, `Timestamp`, the program (`ExeInfo`, with
  `!!name!date!…!description` ids split into `ExeInfoDescription` and `ExeTimestamp`), `AppType`
  (`NormalApp`, `Service`, `ModernApp`, `Object`), the account (`Sid`, `UserName`) and the raw
  `UserId` and `AppId`. Then the table's own columns as the database names them, FILETIME columns
  (`ConnectStartTime`, `EndTime`, …) as times, `InterfaceType` after `InterfaceLuid`
  (`IF_TYPE_IEEE80211`, …) and `ProfileName` after `L2ProfileId`. Times are UTC (RFC 3339);
  `Timestamp` is rounded to the millisecond as SrumECmd rounds it.
- Account and Wi-Fi names come from the SOFTWARE hive, read as SrumECmd reads it (`ProfileList`
  and the `WlanSvc` profiles): `-r`, or found in the same collection (`Windows/System32/config/SOFTWARE`
  next to `sru/`, or a `SOFTWARE` next to the database). A hive that can't be read is reported and
  the entries are written without names.
- With `-d`, files named `SRUDB.dat` (or ending in it) are parsed; `-o` is a directory with one
  subdirectory of CSV tables (or one JSON / JSONL file) per database, named after its path.
- A database left dirty (copied from a running system) is read as it is and reported: changes
  still only in its transaction logs (`SRU*.log`) are missing. Damaged pages and records are
  reported and skipped.

SRUM parsing comes from Yamato Security's
[ys-srum-parser](https://github.com/Yamato-Security/ys-srum-parser), a maintained fork of Sootmark's
[ese](https://github.com/Sootmark/ese) and [srum](https://github.com/Sootmark/srum) crates (MIT OR
Apache-2.0). On eleven real databases, every column of all 45,255 entries `parse-srum` writes
equals a decoding written independently from dissect.esedb's values.

### `parse-lnk`

Parses Windows shortcuts (`*.lnk`, MS-SHLLINK): what a link starts and with which arguments, the
target's times, size, attributes and MFT reference when the link was made, the volume (drive type,
serial number, label) or network share it was on, and the machine that made it (NetBIOS name, MAC
address and time from the distributed link tracking IDs). Shortcuts in `Recent`, on the desktop and
in the Start menu show files and programs that were opened, from drives that may be gone; shortcuts
in e-mail attachments and archives are a common way to start malware.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for shortcuts (*.lnk)
  -f, --file <FILE>      File path to one shortcut
      --code-page <CP>   Code page of text that isn't Unicode: the system's ANSI code page (932 for Japanese) [default: 1252]

Output:
  -o, --output <FILE>       Save every record to a file
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Targets, machines, time range and findings on the terminal
juntei parse-lnk -d C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent

# One CSV row per shortcut, with LECmd's columns
juntei parse-lnk -d triage/ -o lnk.csv

# Shortcuts made on a Japanese system (ANSI text in code page 932)
juntei parse-lnk -d triage/ --code-page 932 -o lnk.csv

# Every field (target items, extra data blocks, property stores, console settings) as JSON Lines
juntei parse-lnk -f invoice.pdf.lnk -t jsonl | jq .
```

- CSV has Eric Zimmerman's LECmd columns (`SourceFile` … `FileDroidBirth`, with `Anomalies` named
  `Problems`) and then `IconIndex`, `HotKey`, `IconEnvironment`, `KnownFolder`, `SpecialFolder`,
  `DarwinId`, `ShimLayer`, `NetworkDevice`, `NetworkProvider`, `ConsoleCodePage` and
  `AppendedBytes`. Times are UTC (RFC 3339) and the source file's own times come from the file
  system. JSON / JSONL have one object per shortcut with every field: each target item (its type,
  name, MFT reference and times), the extra data blocks, the property stores (with property names)
  and the console settings.
- Findings on the terminal: a name, relative path or working directory that claims more than 260
  characters (Windows reads only 260, so the arguments Windows runs hide inside it from tools that
  trust the count; they're read as Windows reads them), data after the end of the link, and shells
  or script hosts (`cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe`, `rundll32.exe`, …)
  started with arguments.
- Text that isn't Unicode (old links, and some fields of new ones) is in the ANSI code page of the
  system that made the link: Windows-1252 unless `--code-page` says otherwise.
- Damaged links are parsed as far as they go and their problems reported (`Problems`); a file that
  isn't a link is reported and skipped.

LNK parsing comes from Yamato Security's
[ys-lnk-parser](https://github.com/Yamato-Security/ys-lnk-parser), a maintained fork of Sootmark's
[shell](https://github.com/Sootmark/shell) crate (MIT OR Apache-2.0) with features and fixes from
other LNK parsers. On 1,118 links from public test sets, the 30 columns `parse-lnk` shares with
LECmd have LECmd's values except 16: 13 target paths (LECmd shows a damaged item or cuts a name in
4 and a placeholder in 6, and names an MTP device or Control Panel applet that `parse-lnk` doesn't
in 3), 2 lists of extra data blocks (blocks with unknown signatures or cut off, which LECmd calls
`DamagedDataBlock`) and 1 MFT reference LECmd reads from the wrong bytes.

### `parse-jump-lists`

Parses Windows jump lists: what each application's taskbar and Start menu entry offers. An
automatic jump list (`*.automaticDestinations-ms`, under
`AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`) is Windows' own record of the
files and folders an application opened: for each, when it was last used, how often (Windows 10
and later), whether it is pinned, the machine and the distributed link tracking IDs of the target,
its path, and a shortcut with the target's times, size, volume and MFT reference. A custom jump
list (`*.customDestinations-ms`, under `CustomDestinations`) is the application's own menu: its
categories ("Most visited", "Recently closed"), its tasks and their shortcuts. The file name starts
with the application's AppID.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for jump lists (*.automaticDestinations-ms, *.customDestinations-ms)
  -f, --file <FILE>      File path to one jump list
      --code-page <CP>   Code page of text in links that isn't Unicode: the system's ANSI code page (932 for Japanese) [default: 1252]

Output:
  -o, --output <PATH>       Save every entry: a directory of CSV tables, or a file (json, jsonl)
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, json and jsonl are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Applications, machines, time range and findings on the terminal
juntei parse-jump-lists -d C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent

# JLECmd's two CSV tables: jl/AutomaticDestinations.csv and jl/CustomDestinations.csv
juntei parse-jump-lists -d triage/ -o jl

# Every entry, link and property as JSON Lines, one jump list per line
juntei parse-jump-lists -f f01b4d95cf55d32a.automaticDestinations-ms -t jsonl | jq .
```

- CSV has Eric Zimmerman's JLECmd's columns: `AutomaticDestinations.csv` (`SourceFile` …
  `Notes`: one row per `DestList` entry with its link, and one per link stream no entry names,
  noted `Found in Directory, not DestList` as JLECmd writes them with `--withDir`) and then
  `DisplayPath` (shell namespace GUIDs named), `PinPosition`, `NetworkPath`, `Name`, `IconLocation`
  and `Problems`; `CustomDestinations.csv` (`SourceFile` … `Arguments`: one row per link, with its
  category in `EntryName`, `Tasks` for tasks) and then `Notes` (links left over after the last
  category), `NetworkPath`, `Name`, `IconLocation` and `Problems`. `EntryNumber` is in hexadecimal
  (the stream's name), as JLECmd writes it. Times are UTC (RFC 3339). JSON / JSONL have one object
  per jump list with every field: the `DestList` header, each entry (with its score, checksum and
  property store) and its link as `parse-lnk` writes one, the `DestListPropertyStore`, the streams,
  each custom category, the bytes after the last one and the links in them.
- Application names come from Eric Zimmerman's list of AppIDs.
- Findings on the terminal: links left over from an earlier version of a custom list (Windows
  rewrites the file in place, and when the new list is shorter, the end of the old one stays: a
  browser's recently closed pages, say), link streams no `DestList` entry names (removed or
  damaged entries), items staged for a CD or DVD burn, and shells or script hosts (`cmd.exe`,
  `powershell.exe`, `mshta.exe`, …) started with arguments.
- Damaged jump lists are parsed as far as they go: a file that ends inside its last sector is read
  (as Windows 11 leaves them), and the problems are reported (an entry whose stream is missing, a
  stream the file cuts short, a count that disagrees). A file that is neither kind is reported and
  skipped.

Jump list parsing comes from Yamato Security's
[ys-jump-lists-parser](https://github.com/Yamato-Security/ys-jump-lists-parser), built from the
jump list and compound file code of Sootmark's [shell](https://github.com/Sootmark/shell) crate
(MIT OR Apache-2.0), with links read by ys-lnk-parser. On the 77 public jump lists it was compared
on, every one of the 13,057 cells `parse-jump-lists` shares with JLECmd 2026.10 (times to 100 ns)
has JLECmd's value, and the six files JLECmd refuses (empty custom lists, a missing footer, a file
that isn't a jump list) are read or reported.

### `parse-shimcache`

Parses the ShimCache (AppCompatCache) of `SYSTEM` hives: the executables Windows checked for
compatibility shims, most recently used first, with each file's path and last-modification time
(the file's, not when it ran) and, from Windows 7 on, whether it was executed. Entries outlive the
files: a cache keeps programs that were deleted, renamed or run from removable drives. Windows
writes the cache when it shuts down, so the latest entries of a live system are not in it yet.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for SYSTEM hives
  -f, --file <FILE>      File path to one SYSTEM hive, or an AppCompatCache value saved to a file
      --no-logs          Read a dirty hive as it is, without its transaction logs (SYSTEM.LOG1, SYSTEM.LOG2)

Output:
  -o, --output <FILE>       Save every entry to a file
  -t, --output-type <TYPE>  Output type: csv (default), json, jsonl. Without -o, the entries are written to stdout
  -C, --clobber             Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Caches, entries, time range and findings on the terminal
juntei parse-shimcache -f C/Windows/System32/config/SYSTEM

# One CSV row per entry, with AppCompatCacheParser's columns, for every host of a triage collection
juntei parse-shimcache -d triage/ -o shimcache.csv

# Every field (flags, data, packaged app records, findings) as JSON Lines
juntei parse-shimcache -f SYSTEM -t jsonl | jq .
```

- Every format from Windows XP to 11: XP, Server 2003 / Vista / 2008 (32 and 64 bit), 7 / 2008 R2
  (32 and 64 bit), 8.0 / 2012, 8.1 / 2012 R2 and 10 / 11. Every control set with a cache is read
  (`ControlSet001`, `ControlSet002`, …), and an entry already seen in an earlier one is marked
  `Duplicate`.
- A dirty hive (one Windows had not finished writing) is read with its transaction logs
  (`SYSTEM.LOG1`, `SYSTEM.LOG2` next to it) applied, as Windows applies them when it loads the
  hive, even when its base block is damaged (the logs give it one); without usable logs, entries
  may be missing, and the summary says so. Entries left in the slack
  of the cache's value (dropped from the cache, Windows 8 to 11) are recovered (`FromSlack`).
- CSV has Eric Zimmerman's AppCompatCacheParser's columns (`ControlSet` … `FromSlack`), with its
  `Executed` (`Yes`, `No`, or `NA` where the format has no flag: Windows XP and 32-bit Vista), and
  then `CacheFormat`, `CacheLastWrittenUTC` (when Windows last saved the cache), `InsertFlags`,
  `ShimFlags`, `DataSize`, `Machine` (x64, x86, ARM64; Windows 10 and 11), `FileSize` and
  `LastUpdateTimeUTC` (Windows XP), a packaged app's `PackageName`, `PackageVersion` and
  `PackagePublisherId`, and `Findings`. Times are UTC (RFC 3339). JSON / JSONL have one object per
  entry with every field, its data and the records in it.
- `-f` also takes an AppCompatCache value on its own (its bytes, exported from the registry or
  carved), read without a control set.
- Findings on the terminal: Windows system binaries recorded outside `System32` / `SysWOW64`
  (masquerading) and executables in directories commonly used to stage malware (Temp, Downloads,
  `$Recycle.Bin`, …). A ShimCache entry shows that the file was there, and its execution flag
  that it ran: findings are leads, not verdicts.
- Damaged caches are read as far as they go and the damaged entries counted; a file that is
  neither a hive nor a cache is reported and skipped.

ShimCache parsing comes from Yamato Security's
[ys-shimcache-parser](https://github.com/Yamato-Security/ys-shimcache-parser), a maintained fork
of Security Ronin's [shimcache-forensic](https://github.com/SecurityRonin/shimcache-forensic)
(Apache-2.0) with its own registry hive reader and transaction log replay. On the 20 public
`SYSTEM` hives (24 control sets, 7,290 entries) and 17 AppCompatCache values it was compared on,
every entry has the path, time, execution flag, flags and position Eric Zimmerman's
AppCompatCacheParser 2026.10.1 gives it.

## License

Juntei is released under the [GNU Affero General Public License v3.0](LICENSE).
