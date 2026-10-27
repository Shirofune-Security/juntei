# Juntei

Juntei is a Windows forensics artifact parser by [Yamato Security](https://github.com/Yamato-Security),
a sibling of [Hayabusa](https://github.com/Yamato-Security/hayabusa) for the artifacts that are
not event logs.

## Supported artifacts

| Artifact | Command | Status |
| --- | --- | --- |
| Amcache (`Amcache.hve`) | `parse-amcache` | Supported |
| Prefetch (`*.pf`) | | Planned |
| `$MFT` | | Planned |
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

## License

Juntei is released under the [GNU Affero General Public License v3.0](LICENSE).
