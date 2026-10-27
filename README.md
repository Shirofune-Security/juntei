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
| `$UsnJrnl:$J` | | Planned |
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
ones, with the full path, flags, sizes, `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps and
alternate data streams.

```
Input:
  -d, --directory <DIR>  Directory to search recursively for $MFT files
  -f, --file <FILE>      File path to one $MFT

Filtering:
  -r, --ranges <RANGES>  Parse only these entry numbers (ex: 0-15,30)

Output:
  -o, --output <PATH>                   Save every entry to a file (with -d: a directory with one file per $MFT)
  -t, --output-type <TYPE>              Output type: csv (default), json, jsonl. Without -o, the entries are written to stdout
  -e, --extract-resident-streams <DIR>  Write the resident $DATA streams (the content of small files and alternate data streams) to files in DIR
  -C, --clobber                         Overwrite files when saving

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner
```

```
# Entry counts (in use, deleted, directories, alternate data streams, damaged entries)
juntei parse-mft -f '$MFT'

# Every entry as CSV
juntei parse-mft -f '$MFT' -o mft.csv

# The $MFT of every host in a triage collection, one JSONL file each
juntei parse-mft -d triage/ -o mft-jsonl -t jsonl

# Entries 0-15 and 30 as JSON Lines on stdout
juntei parse-mft -f '$MFT' -t jsonl -r 0-15,30

# The content of small files and alternate data streams stored in the $MFT itself
juntei parse-mft -f '$MFT' -e resident-streams
```

- Without `-o` or `-t`, only the summary is shown. CSV has one row per entry (the columns of
  `mft_dump`); JSON / JSONL have every attribute of every entry.
- With `-d`, files named `$MFT` (or ending in `$MFT`) are parsed; `-o` is a directory with one
  file per `$MFT`, named after its path (`HOST1/C/$MFT` → `HOST1_C__MFT.csv`).
- Full paths use `/`. A file whose parent directory's record was reused is `[Orphaned]`; a deleted
  file in a deleted directory keeps its path; an unresolvable parent is `[Unknown]`.
- Extracted streams are named `<full path>__<entry>-<sequence>_<stream number>_<stream name>.dontrun`;
  characters that are unsafe in file names become `_`. They are evidence: do not run them.
- Damaged or crafted records do not crash the run: a file without a usable FILE record header is
  skipped, a parent-reference loop gives an `[Unknown]` path, and unreadable entries are counted.

$MFT parsing and the CSV / JSON formats come from Yamato Security's
[ys-mft-parser](https://github.com/Yamato-Security/ys-mft-parser), a maintained fork of Omer
Ben-Amram's [mft](https://github.com/omerbenamram/mft) crate (MIT / Apache-2.0).

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

## License

Juntei is released under the [GNU Affero General Public License v3.0](LICENSE).
