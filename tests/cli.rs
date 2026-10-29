//! End-to-end tests: run the built binary against the test hives in `test_files/amcache/`.
//!
//! The expected counts are those of the `ys-amcache-parser` command, which was cross-validated
//! against Eric Zimmerman's AmcacheParser and regipy (see `test_files/amcache/README.md`).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const WIN10: &str = "test_files/amcache/amcache_win10.hve";
const LEGACY: &str = "test_files/amcache/amcache_2012r2_old.hve";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_juntei"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .expect("juntei runs");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// A triage-like tree: two hosts, a transaction log and a hive that is not a hive.
fn triage() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let programs = dir.path().join("HOST1/C/Windows/AppCompat/Programs");
    std::fs::create_dir_all(&programs).unwrap();
    std::fs::copy(repo(WIN10), programs.join("Amcache.hve")).unwrap();
    std::fs::write(programs.join("Amcache.hve.LOG1"), b"log").unwrap();
    std::fs::create_dir_all(dir.path().join("HOST2")).unwrap();
    std::fs::copy(repo(LEGACY), dir.path().join("HOST2/Amcache.hve")).unwrap();
    std::fs::write(dir.path().join("HOST2/Broken_Amcache.hve"), b"not a hive").unwrap();
    dir
}

/// Every JSON document in a stream of newline-separated (pretty) documents.
fn json_documents(text: &str) -> Vec<Value> {
    serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .map(|v| v.unwrap())
        .collect()
}

#[test]
fn banner_and_help() {
    let r = run(&[]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("┗━━┻━━━┻┛  ┗┛ ┗┛ ┗━━━┻━━┛"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("by Yamato Security"));
    assert!(r.stdout.contains("parse-amcache"));
    let r = run(&["parse-amcache", "-h", "-K"]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("juntei parse-amcache <INPUT> [OPTIONS]"),
        "{}",
        r.stdout
    );
}

#[test]
fn terminal_report_has_the_summary_and_findings() {
    let r = run(&["parse-amcache", "-f", WIN10, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Start time: "));
    assert!(
        r.stdout
            .contains("Amcache: 123 file entries, 189 device entries")
    );
    assert!(r.stdout.contains("Findings (4):"));
    assert!(r.stdout.contains(
        "[MEDIUM] AMCACHE-SUSPICIOUS-PATH  c:\\users\\testuser\\downloads\\sysmon\\sysmon64.exe"
    ));
    // no detailed records on the terminal unless asked for
    assert!(
        !r.stdout.contains("Inventoried executables:\n"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("Results Summary:"));
    assert!(r.stdout.contains("Inventoried executables: 123"));
    assert!(r.stdout.contains("Inventoried devices: 189"));
    assert!(r.stdout.contains("Findings: 4 (medium: 4)"));
    assert!(r.stdout.contains("Elapsed time: "));
    let r = run(&["parse-amcache", "-f", WIN10, "-K", "-q", "--files"]);
    assert!(
        !r.stdout.contains("by Yamato Security"),
        "-q hides the banner"
    );
    assert!(r.stdout.contains("7z.exe"), "--files adds the executables");
}

#[test]
fn legacy_hives_are_read() {
    let r = run(&["parse-amcache", "-f", LEGACY, "-K", "-q"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains("Amcache: 136 file entries, 0 device entries")
    );
    assert!(
        r.stdout
            .contains("Schemas: modern (Windows 10/11) 0, legacy (Windows 8/8.1/2012 R2) 1")
    );
    assert!(r.stdout.contains("Findings: 2 (medium: 2)"));
}

#[test]
fn json_and_jsonl_files_hold_every_record() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("amcache.json");
    let r = run(&[
        "parse-amcache",
        "-f",
        WIN10,
        "-o",
        json.to_str().unwrap(),
        "-t",
        "json",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Parsing in progress. Please wait."));
    assert!(r.stdout.contains("Results saved: "));
    let docs = json_documents(&std::fs::read_to_string(&json).unwrap());
    assert_eq!(docs.len(), 1);
    let doc = &docs[0];
    assert_eq!(doc["amcache_schema"], "modern");
    assert_eq!(doc["summary"]["file_count"], 123);
    assert_eq!(doc["files"].as_array().unwrap().len(), 123);
    assert_eq!(doc["devices"].as_array().unwrap().len(), 189);
    assert_eq!(doc["findings"].as_array().unwrap().len(), 4);
    let sevenzip = doc["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["full_path"] == "c:\\program files\\7-zip\\7z.exe")
        .expect("7z.exe is inventoried");
    assert_eq!(sevenzip["sha1"], "1189cebeb8ffed7316f98b895ff949a726f4026f");

    let jsonl = dir.path().join("amcache.jsonl");
    let r = run(&[
        "parse-amcache",
        "-f",
        WIN10,
        "-o",
        jsonl.to_str().unwrap(),
        "-t",
        "jsonl",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = std::fs::read_to_string(&jsonl).unwrap();
    // summary + 4 findings + 123 files + 189 devices
    assert_eq!(text.lines().count(), 317);
    // --files narrows the default of every record
    let r = run(&[
        "parse-amcache",
        "-f",
        WIN10,
        "-o",
        jsonl.to_str().unwrap(),
        "-t",
        "jsonl",
        "-C",
        "--files",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        std::fs::read_to_string(&jsonl).unwrap().lines().count(),
        128
    );
}

#[test]
fn csv_tables_go_into_one_directory_per_hive() {
    let tree = triage();
    let out = tempfile::tempdir().unwrap();
    let out_dir = out.path().join("csv");
    let r = run(&[
        "parse-amcache",
        "-d",
        tree.path().to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("Amcache hives: 3"),
        "the .LOG1 file is not a hive"
    );
    assert!(r.stdout.contains("Could not parse "), "{}", r.stdout);
    assert!(
        r.stdout
            .contains("Amcache hives parsed: 2 (could not parse: 1)")
    );
    assert!(r.stdout.contains("Inventoried executables: 259"));
    assert!(r.stdout.contains("Findings: 6 (medium: 6)"));
    assert!(r.stdout.contains("(8 CSV files)"));
    for (sub, rows) in [
        ("HOST1_C_Windows_AppCompat_Programs_Amcache", 123),
        ("HOST2_Amcache", 136),
    ] {
        let files = out_dir.join(sub).join("Amcache_files.csv");
        let text =
            std::fs::read_to_string(&files).unwrap_or_else(|e| panic!("{}: {e}", files.display()));
        let mut rdr = csv::Reader::from_reader(text.as_bytes());
        assert_eq!(rdr.records().count(), rows, "{sub}");
        for table in ["summary", "findings", "devices"] {
            assert!(
                out_dir
                    .join(sub)
                    .join(format!("Amcache_{table}.csv"))
                    .is_file()
            );
        }
    }
    // the results are not overwritten without -C
    let r = run(&[
        "parse-amcache",
        "-d",
        tree.path().to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("already exists"), "{}", r.stdout);
    let r = run(&[
        "parse-amcache",
        "-d",
        tree.path().to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "-C",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
}

#[test]
fn structured_stdout_holds_only_the_data() {
    let tree = triage();
    let r = run(&[
        "parse-amcache",
        "-d",
        tree.path().to_str().unwrap(),
        "-t",
        "json",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let docs = json_documents(&r.stdout);
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0]["amcache_schema"], "modern");
    assert_eq!(docs[1]["amcache_schema"], "legacy");
    assert!(
        r.stderr.contains("Could not parse "),
        "errors go to stderr: {}",
        r.stderr
    );
    let r = run(&["parse-amcache", "-f", WIN10, "-t", "jsonl"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in r.stdout.lines() {
        serde_json::from_str::<Value>(line).unwrap_or_else(|e| panic!("{e}: {line}"));
    }
}

#[test]
fn text_reports_can_be_saved() {
    let tree = triage();
    let out = tempfile::tempdir().unwrap();
    let file = out.path().join("amcache.txt");
    let r = run(&[
        "parse-amcache",
        "-d",
        tree.path().to_str().unwrap(),
        "-o",
        file.to_str().unwrap(),
        "-t",
        "text",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = std::fs::read_to_string(&file).unwrap();
    assert_eq!(text.matches("Amcache hive: ").count(), 2);
    assert!(text.contains("Amcache: 123 file entries, 189 device entries"));
    assert!(text.contains("Amcache: 136 file entries, 0 device entries"));
    assert!(
        text.contains("Inventoried executables:"),
        "-o includes every record"
    );
}

#[test]
fn input_and_output_errors() {
    let r = run(&["parse-amcache", "-f", "no/such/Amcache.hve", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The file does not exist"), "{}", r.stdout);
    let r = run(&["parse-amcache", "-f", "README.md", "-K", "-q"]);
    assert_eq!(r.code, 1, "nothing could be parsed");
    assert!(
        r.stdout.contains("Could not parse README.md"),
        "{}",
        r.stdout
    );
    let empty = tempfile::tempdir().unwrap();
    let r = run(&["parse-amcache", "-d", empty.path().to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout
            .contains("No Amcache hives (Amcache.hve) were found"),
        "{}",
        r.stdout
    );
    let r = run(&["parse-amcache", "-f", WIN10, "-t", "csv", "-K"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("CSV output needs -o <DIR>"),
        "{}",
        r.stdout
    );
}

// ----- parse-mft --------------------------------------------------------------------------------

const MFT: &str = "test_files/mft/MFT";

/// (EntryId, FullPath) of every CSV row (paths use `\` on every OS, as Windows shows them).
fn full_paths(csv_text: &str) -> Vec<(String, String)> {
    let mut rdr = csv::Reader::from_reader(csv_text.as_bytes());
    let headers = rdr.headers().unwrap().clone();
    let id = headers.iter().position(|h| h == "EntryId").unwrap();
    let path = headers.iter().position(|h| h == "FullPath").unwrap();
    rdr.records()
        .map(|r| {
            let r = r.unwrap();
            (r[id].to_string(), r[path].to_string())
        })
        .collect()
}

#[test]
fn mft_summary_on_the_terminal() {
    let r = run(&["parse-mft", "-f", MFT, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("$MFT files: 1"), "{}", r.stdout);
    assert!(r.stdout.contains("Parsing in progress. Please wait."));
    assert!(
        r.stdout
            .contains("Entries: 1,016 (in use: 1,016, deleted: 0)")
    );
    assert!(r.stdout.contains("Directories / files: 153 / 863"));
    assert!(r.stdout.contains("Entries with alternate data streams: 2"));
    assert!(r.stdout.contains("Empty entries (skipped): 8"));
    assert!(r.stdout.contains("To save every entry, add -o <FILE>"));
}

#[test]
fn mft_csv_json_and_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("mft.csv");
    let r = run(&[
        "parse-mft",
        "-f",
        MFT,
        "-o",
        csv_path.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Results saved: "));
    // One row per file name and per alternate data stream, as MFTECmd writes them
    assert!(
        r.stdout
            .contains("CSV rows (file names and alternate data streams): 1,014"),
        "{}",
        r.stdout
    );
    let (header, rows) = csv_rows(&csv_path);
    assert_eq!(
        header[..6],
        [
            "EntryNumber",
            "SequenceNumber",
            "InUse",
            "ParentEntryNumber",
            "ParentSequenceNumber",
            "ParentPath"
        ]
    );
    assert_eq!(header.len(), 35);
    assert_eq!(rows.len(), 1014);
    let row = |entry: &str, name: &str| {
        rows.iter()
            .find(|r| r["EntryNumber"] == entry && r["FileName"] == name)
            .unwrap_or_else(|| panic!("{entry} {name}"))
    };
    assert_eq!(row("30", "config")["ParentPath"], r".\WINDOWS\system32");
    // $STANDARD_INFORMATION created before $FILE_NAME created, on a whole second
    let bootvid = row("178", "bootvid.dll");
    for (column, value) in [
        ("Extension", ".dll"),
        ("FileSize", "12288"),
        ("SI<FN", "True"),
        ("uSecZeros", "True"),
        ("Copied", "False"),
        ("SiFlags", "Archive"),
        ("NameType", "DosWindows"),
        ("Created0x10", "2006-02-28T12:00:00.0000000Z"),
        ("Created0x30", "2007-06-30T12:51:00.8147072Z"),
    ] {
        assert_eq!(bootvid[column], value, "{column}");
    }
    let ads = row("8", "$BadClus:$Bad");
    assert_eq!(ads["IsAds"], "True");
    assert_eq!(ads["FileSize"], "1261821952");
    assert_eq!(row("8", "$BadClus")["HasAds"], "True");

    // ys-mft-parser's columns: one row per entry (`mft-dump-csv`, upstream's name, still works)
    let mut texts = Vec::new();
    for output_type in ["ys-mft-parser-csv", "mft-dump-csv"] {
        let r = run(&[
            "parse-mft",
            "-f",
            MFT,
            "-o",
            csv_path.to_str().unwrap(),
            "-t",
            output_type,
            "-C",
            "-K",
        ]);
        assert_eq!(r.code, 0, "{output_type}: {}", r.stderr);
        texts.push(std::fs::read_to_string(&csv_path).unwrap());
    }
    assert_eq!(texts[0], texts[1]);
    let text = &texts[0];
    assert!(text.starts_with(
        "Signature,EntryId,Sequence,BaseEntryId,BaseEntrySequence,HardLinkCount,Flags,"
    ));
    let paths = full_paths(text);
    assert_eq!(paths.len(), 1016);
    for (id, path) in [
        ("0", "$MFT"),
        ("5", "."),
        ("30", r"WINDOWS\system32\config"),
    ] {
        assert!(
            paths.contains(&(id.to_string(), path.to_string())),
            "{id} {path}"
        );
    }

    let json_path = dir.path().join("mft.json");
    let r = run(&[
        "parse-mft",
        "-f",
        MFT,
        "-o",
        json_path.to_str().unwrap(),
        "-t",
        "json",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let docs = json_documents(&std::fs::read_to_string(&json_path).unwrap());
    assert_eq!(docs.len(), 1016);
    assert_eq!(docs[0]["header"]["record_number"], 0);
    assert_eq!(docs[0]["full_path"], "$MFT");
    assert!(docs[0]["attributes"].as_array().unwrap().len() > 2);
    let config = docs
        .iter()
        .find(|d| d["header"]["record_number"] == 30)
        .unwrap();
    assert_eq!(config["full_path"], r"WINDOWS\system32\config");

    // -t without -o: only the entries on stdout
    let r = run(&["parse-mft", "-f", MFT, "-t", "jsonl", "-r", "0-5,30"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let ids: Vec<u64> = r
        .stdout
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["header"]["record_number"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(ids, [0, 1, 2, 3, 4, 5, 30]);
}

#[test]
fn mft_csv_options() {
    let help = run(&["parse-mft", "-h", "-K"]);
    assert_eq!(help.code, 0, "{}", help.stderr);
    assert!(help.stdout.contains("-a, --all-times"), "{}", help.stdout);
    assert!(help.stdout.contains("-s, --short-names"), "{}", help.stdout);
    assert!(
        help.stdout
            .contains("Output type: csv (default), ys-mft-parser-csv, json, jsonl"),
        "{}",
        help.stdout
    );
    assert!(!help.stdout.contains("MFTECmd's --at"), "{}", help.stdout);
    assert!(!help.stdout.contains("MFTECmd's --sn"), "{}", help.stdout);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("mft.csv");
    let csv = |extra: &[&str]| {
        let mut args = vec![
            "parse-mft",
            "-f",
            MFT,
            "-o",
            out.to_str().unwrap(),
            "-C",
            "-K",
        ];
        args.extend_from_slice(extra);
        let r = run(&args);
        assert_eq!(r.code, 0, "{}", r.stdout);
        csv_rows(&out).1
    };
    // $FILE_NAME times only where they differ from $STANDARD_INFORMATION, unless -a/--all-times
    let mft = |rows: &[std::collections::HashMap<String, String>]| {
        rows.iter()
            .find(|r| r["FileName"] == "$MFT")
            .unwrap()
            .clone()
    };
    assert_eq!(mft(&csv(&[]))["Created0x30"], "");
    assert_eq!(
        mft(&csv(&["-a"]))["Created0x30"],
        "2007-06-30T12:50:52.2523952Z"
    );
    // DOS (8.3) names get rows of their own with -s/--short-names
    let rows = csv(&["-s"]);
    assert_eq!(rows.len(), 1041);
    assert_eq!(rows.iter().filter(|r| r["NameType"] == "Dos").count(), 27);
    // only records created or modified on or after the cutoff (MFTECmd gives the same 8 rows)
    let rows = csv(&["--cutoff", "2007-07-01"]);
    assert_eq!(rows.len(), 8);
    assert_eq!(rows[0]["LastModified0x10"], "2009-01-19T04:17:44.7268320Z");
    assert_eq!(csv(&["--cutoff", "2007-07-01T09:00:00+09:00"]).len(), 8);

    let r = run(&["parse-mft", "-f", MFT, "-t", "jsonl", "--short-names"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("options of the CSV output"),
        "{}",
        r.stderr
    );
    let r = run(&["parse-mft", "-f", MFT, "--cutoff", "yesterday", "-K"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("is not a date or time"), "{}", r.stderr);
    // a year chrono accepts but a FILETIME can't hold: an error, not an overflow
    let r = run(&[
        "parse-mft",
        "-f",
        MFT,
        "--cutoff",
        "+262142-12-31T23:59:59",
        "-K",
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("outside the times NTFS can hold"),
        "{}",
        r.stderr
    );
}

#[test]
fn mft_csv_reports_damaged_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(repo(MFT)).unwrap();
    // entry 62: the value of its first $FILE_NAME (at 0x98) starts past the end of the record
    data[62 * 1024 + 0xAC] = 0xF0;
    // entry 209: so does the value of its resident $DATA (at 0x108)
    data[209 * 1024 + 0x108 + 0x14..][..2].copy_from_slice(&0x3F0u16.to_le_bytes());
    let damaged = dir.path().join("damaged_$MFT");
    std::fs::write(&damaged, &data).unwrap();
    let out = dir.path().join("mft.csv");
    let r = run(&[
        "parse-mft",
        "-f",
        damaged.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-r",
        "62,209",
        "--short-names",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (_, rows) = csv_rows(&out);
    // the damaged attributes are left out and said so, as MFTECmd does
    let names: Vec<&str> = rows.iter().map(|r| r["FileName"].as_str()).collect();
    assert_eq!(
        names,
        ["Repository", "system.ini"],
        "REPOSI~1 was in the damaged $FILE_NAME"
    );
    assert_eq!(
        rows[0]["ParseErrors"],
        "$FILE_NAME attribute at 0x98 left out: its value (0x52 bytes at 0xF0) runs past the end of the attribute"
    );
    assert!(
        rows[1]["ParseErrors"].starts_with("$DATA attribute at 0x108 left out: "),
        "{}",
        rows[1]["ParseErrors"]
    );
    // without its $DATA, the size is the $FILE_NAME's (it was 231)
    assert_eq!(rows[1]["FileSize"], "219");
}

#[test]
fn mft_csv_reports_damaged_extension_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(repo(MFT)).unwrap();
    // entry 226 (a small file with a resident $DATA at 0x100) becomes an extension record of
    // entry 209 (system.ini, sequence 1), and the value of its $DATA runs past the end
    let extension = 226 * 1024;
    data[extension + 0x20..][..8].copy_from_slice(&(209u64 | (1 << 48)).to_le_bytes());
    data[extension + 0x100 + 0x14..][..2].copy_from_slice(&0x3F0u16.to_le_bytes());
    let damaged = dir.path().join("damaged_$MFT");
    std::fs::write(&damaged, &data).unwrap();
    let out = dir.path().join("mft.csv");
    let r = run(&[
        "parse-mft",
        "-f",
        damaged.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-r",
        "209,226",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (_, rows) = csv_rows(&out);
    // the extension record has no rows of its own; its name is a name of entry 209
    assert!(rows.iter().all(|r| r["EntryNumber"] == "209"), "{rows:?}");
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(
            row["ParseErrors"],
            "extension record 226: $DATA attribute at 0x100 left out: its value (0x1DD bytes at 0x3F0) runs past the end of the attribute",
            "{}",
            row["FileName"]
        );
        // the base record's own $DATA gives the size
        assert_eq!(row["FileSize"], "231");
    }
}

#[test]
fn mft_resident_streams_and_directory_mode() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("HOST1/C")).unwrap();
    std::fs::create_dir_all(tree.path().join("HOST2")).unwrap();
    std::fs::copy(repo(MFT), tree.path().join("HOST1/C/$MFT")).unwrap();
    std::fs::copy(repo(MFT), tree.path().join("HOST2/$MFT")).unwrap();
    std::fs::copy(repo(MFT), tree.path().join("HOST2/$MFTMirr")).unwrap();
    let out = tempfile::tempdir().unwrap();
    let csv_dir = out.path().join("csv");
    let streams = out.path().join("streams");
    let r = run(&[
        "parse-mft",
        "-d",
        tree.path().to_str().unwrap(),
        "-o",
        csv_dir.to_str().unwrap(),
        "-e",
        streams.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("$MFT files: 2"),
        "$MFTMirr is not an $MFT: {}",
        r.stdout
    );
    assert!(r.stdout.contains("(2 files)"));
    assert!(
        // 24 resident streams in each, of which 2 are empty and not written
        r.stdout.contains("Resident streams extracted: 44"),
        "{}",
        r.stdout
    );
    for name in ["HOST1_C__MFT", "HOST2__MFT"] {
        let text = std::fs::read_to_string(csv_dir.join(format!("{name}.csv"))).unwrap();
        assert!(
            text.starts_with("EntryNumber,SequenceNumber,InUse,"),
            "{name}"
        );
        assert_eq!(
            csv_rows(&csv_dir.join(format!("{name}.csv"))).1.len(),
            1014,
            "{name}"
        );
        assert_eq!(
            std::fs::read_dir(streams.join(name)).unwrap().count(),
            22,
            "{name}"
        );
    }
    // stream files are named after the entry and its path
    let names: Vec<String> = std::fs::read_dir(streams.join("HOST2__MFT"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(names.iter().all(|n| n.ends_with(".dontrun")), "{names:?}");
    // the entries of several $MFT files cannot share stdout
    let r = run(&[
        "parse-mft",
        "-d",
        tree.path().to_str().unwrap(),
        "-t",
        "csv",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("With -d, save the entries with -o <DIR>"),
        "{}",
        r.stderr
    );
}

#[test]
fn mft_damaged_inputs_do_not_stop_the_run() {
    let dir = tempfile::tempdir().unwrap();
    // two directories that name each other as parent (the upstream crate overflows the stack)
    let mut data = std::fs::read(repo(MFT)).unwrap();
    let mut dirs: Vec<(usize, Vec<usize>)> = Vec::new();
    for i in 16..data.len() / 1024 {
        let base = i * 1024;
        if &data[base..base + 4] != b"FILE" || data[base + 0x16] & 2 == 0 {
            continue;
        }
        let mut off = usize::from(u16::from_le_bytes([data[base + 0x14], data[base + 0x15]]));
        let mut fn_offsets = Vec::new();
        while off + 8 < 1024 {
            let t = u32::from_le_bytes(data[base + off..base + off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(data[base + off + 4..base + off + 8].try_into().unwrap());
            if t == 0xFFFF_FFFF || len == 0 {
                break;
            }
            if t == 0x30 && data[base + off + 8] == 0 {
                let content = usize::from(u16::from_le_bytes([
                    data[base + off + 0x14],
                    data[base + off + 0x15],
                ]));
                fn_offsets.push(base + off + content);
            }
            off += len as usize;
        }
        if !fn_offsets.is_empty() {
            dirs.push((i, fn_offsets));
        }
        if dirs.len() == 2 {
            break;
        }
    }
    let (a, b) = (dirs[0].0, dirs[1].0);
    for ((_, offsets), parent) in dirs.iter().zip([b, a]) {
        for &o in offsets {
            data[o..o + 6].copy_from_slice(&(parent as u64).to_le_bytes()[..6]);
            data[o + 6..o + 8].copy_from_slice(&[0, 0]);
        }
    }
    let cycle = dir.path().join("cycle_$MFT");
    std::fs::write(&cycle, &data).unwrap();
    let zero = dir.path().join("zero_$MFT");
    std::fs::write(&zero, vec![0u8; 4096]).unwrap();
    let r = run(&["parse-mft", "-d", dir.path().to_str().unwrap(), "-K", "-q"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains("$MFT files parsed: 1 (could not parse: 1)"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("no valid FILE record header was found"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("Entries: 1,016"), "{}", r.stdout);
    // the CSV's parent paths of the loop end in MFTECmd's PathUnknown
    let out = dir.path().join("cycle.csv");
    let r = run(&[
        "parse-mft",
        "-f",
        cycle.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-K",
        "-q",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (_, rows) = csv_rows(&out);
    let looped: Vec<_> = rows
        .iter()
        .filter(|r| r["EntryNumber"] == a.to_string() || r["EntryNumber"] == b.to_string())
        .collect();
    assert_eq!(looped.len(), 2);
    assert!(
        looped
            .iter()
            .all(|r| r["ParentPath"].starts_with(r".\PathUnknown\Directory with ID 0x")),
        "{looped:?}"
    );

    let r = run(&["parse-mft", "-f", "README.md", "-K", "-q"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout
            .contains("Could not parse README.md: Failed to determine the entry size"),
        "{}",
        r.stdout
    );
}

const PREFETCH_DIR: &str = "test_files/prefetch";
const PREFETCH_CMD10: &str = "test_files/prefetch/CMD.EXE-6D6290C5.pf";

#[test]
fn prefetch_summary_on_the_terminal() {
    let r = run(&["parse-prefetch", "-d", PREFETCH_DIR, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Prefetch files: 6"), "{}", r.stdout);
    assert!(r.stdout.contains("Parsing in progress. Please wait."));
    assert!(r.stdout.contains("Could not parse "));
    assert!(r.stdout.contains("SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf"));
    assert!(
        r.stdout
            .contains("Prefetch files parsed: 5 (could not parse: 1)")
    );
    assert!(r.stdout.contains(
        "Format versions: 30 (Windows 10/11) 2, 26 (Windows 8/8.1) 1, 23 (Windows Vista/7) 1, 17 (Windows XP/2003) 1"
    ));
    assert!(r.stdout.contains("Executables: 3"));
    assert!(r.stdout.contains("Executions (run counts): 11"));
    assert!(r.stdout.contains(
        "Run times recorded: 9 (2013-03-10T10:11:49.281250Z - 2024-02-05T06:17:41.144014200Z)"
    ));
    assert!(r.stdout.contains("Findings: 1 (medium: 1)"));
    assert!(r.stdout.contains("To save every record, add -o <FILE>"));
}

#[test]
fn prefetch_csv_json_and_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let csv_path = dir.path().join("prefetch.csv");
    let r = run(&[
        "parse-prefetch",
        "-f",
        PREFETCH_CMD10,
        "-o",
        csv_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Results saved: "));
    let mut csv = csv::Reader::from_path(&csv_path).unwrap();
    let header = csv.headers().unwrap().clone();
    let rows: Vec<csv::StringRecord> = csv.records().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 1);
    let field = |name: &str| rows[0][header.iter().position(|h| h == name).unwrap()].to_string();
    assert_eq!(field("ExecutableName"), "CMD.EXE");
    assert_eq!(field("PrefetchHash"), "6D6290C5");
    assert_eq!(field("FormatVersion"), "30");
    assert_eq!(field("RunCount"), "4");
    assert_eq!(field("LastRun"), "2024-02-05T06:17:41.144014200Z");
    assert_eq!(field("PreviousRun3"), "2024-02-04T04:15:17.060262400Z");
    assert_eq!(field("PreviousRun4"), "");
    assert!(field("ExecutablePath").ends_with(r"\WINDOWS\SYSWOW64\CMD.EXE"));
    assert_eq!(field("FileCount"), "25");
    assert_eq!(field("Findings"), "");

    // one pretty JSON document per file, with every field
    let json_path = dir.path().join("prefetch.json");
    let r = run(&[
        "parse-prefetch",
        "-d",
        PREFETCH_DIR,
        "-o",
        json_path.to_str().unwrap(),
        "-t",
        "json",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let docs = json_documents(&std::fs::read_to_string(&json_path).unwrap());
    assert_eq!(docs.len(), 5);
    let rust_out = docs
        .iter()
        .find(|d| d["executable_name"] == "RUST_OUT.EXE")
        .unwrap();
    assert_eq!(rust_out["findings"][0]["code"], "SuspiciousExecutionPath");
    assert_eq!(rust_out["findings"][0]["severity"], "medium");
    let notepad = docs
        .iter()
        .find(|d| d["executable_name"] == "NOTEPAD.EXE")
        .unwrap();
    assert_eq!(notepad["windows_version"], "Windows Vista/7");
    assert!(
        notepad["files"][0]["mft_entry"].is_u64(),
        "version 23 has file references"
    );
    assert!(
        !notepad["volumes"][0]["directories"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // JSON Lines on stdout: only the data
    let r = run(&["parse-prefetch", "-f", PREFETCH_CMD10, "-t", "jsonl"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{}", r.stdout);
    let doc: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(doc["last_run_times"].as_array().unwrap().len(), 4);
}

#[test]
fn prefetch_timeline_is_one_record_per_execution_sorted_by_time() {
    let r = run(&["parse-prefetch", "-d", PREFETCH_DIR, "-T", "-t", "csv"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("Could not parse "), "errors go to stderr");
    let mut csv = csv::Reader::from_reader(r.stdout.as_bytes());
    assert_eq!(
        csv.headers().unwrap().iter().collect::<Vec<_>>(),
        [
            "RunTime",
            "ExecutableName",
            "ExecutablePath",
            "PrefetchHash",
            "RunCount",
            "SourceFile"
        ]
    );
    let times: Vec<String> = csv.records().map(|r| r.unwrap()[0].to_string()).collect();
    assert_eq!(times.len(), 9);
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted);
    assert_eq!(times[0], "2013-03-10T10:11:49.281250Z");
}

/// A Windows 7 prefetch file of NOTEPAD.EXE turned into one of SVCHOST.EXE loaded from outside
/// System32 (the names have the same length, so every offset stays valid).
#[test]
fn prefetch_system_binary_outside_system32_is_a_high_finding() {
    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
    fn replace_all(data: &mut [u8], from: &[u8], to: &[u8]) {
        let mut i = 0;
        while i + from.len() <= data.len() {
            if &data[i..i + from.len()] == from {
                data[i..i + from.len()].copy_from_slice(to);
                i += from.len();
            } else {
                i += 1;
            }
        }
    }
    let mut data = std::fs::read(repo("test_files/prefetch/NOTEPAD.EXE-D8414F97.pf")).unwrap();
    replace_all(
        &mut data,
        &utf16(r"SYSTEM32\NOTEPAD.EXE"),
        &utf16(r"TEMPDIR1\SVCHOST.EXE"),
    );
    replace_all(&mut data, &utf16("NOTEPAD.EXE"), &utf16("SVCHOST.EXE"));
    let dir = tempfile::tempdir().unwrap();
    let pf = dir.path().join("SVCHOST.EXE-D8414F97.pf");
    std::fs::write(&pf, data).unwrap();

    let r = run(&["parse-prefetch", "-f", pf.to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Findings: 1 (high: 1)"), "{}", r.stdout);
    assert!(r.stdout.contains(
        r"[HIGH] SVCHOST.EXE is a Windows system binary but was loaded from \DEVICE\HARDDISKVOLUME2\WINDOWS\TEMPDIR1\SVCHOST.EXE"
    ), "{}", r.stdout);
    assert!(r.stdout.contains("(T1036.005)"));
}

#[test]
fn prefetch_input_and_output_errors() {
    let dir = tempfile::tempdir().unwrap();
    let r = run(&["parse-prefetch", "-d", dir.path().to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("No prefetch files (*.pf) were found"),
        "{}",
        r.stdout
    );

    let r = run(&[
        "parse-prefetch",
        "-f",
        "test_files/prefetch/corrupt/SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf",
        "-K",
    ]);
    assert_eq!(r.code, 1, "nothing was parsed");
    assert!(
        r.stdout
            .contains("Prefetch files parsed: 0 (could not parse: 1)")
    );

    let out = dir.path().join("exists.csv");
    std::fs::write(&out, b"x").unwrap();
    let r = run(&[
        "parse-prefetch",
        "-f",
        PREFETCH_CMD10,
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The output file already exists"));
    let r = run(&[
        "parse-prefetch",
        "-f",
        PREFETCH_CMD10,
        "-o",
        out.to_str().unwrap(),
        "-C",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
}

const USN_SLICE: &str = "test_files/usn/win11_rathbunvm_$J";

/// A `USN_RECORD_V2` at `usn` (also its offset), for MFT entry `file` in directory `parent`.
fn usn_v2(
    usn: u64,
    file: (u64, u16),
    parent: (u64, u16),
    reasons: u32,
    attributes: u32,
    name: &str,
) -> Vec<u8> {
    let reference =
        |(entry, sequence): (u64, u16)| (u64::from(sequence) << 48 | entry).to_le_bytes();
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut r = vec![0; 4];
    r.extend(2_u16.to_le_bytes());
    r.extend(0_u16.to_le_bytes());
    r.extend(reference(file));
    r.extend(reference(parent));
    r.extend(usn.to_le_bytes());
    r.extend(133_537_680_000_000_000_u64.to_le_bytes()); // 2024-03-01T12:00:00Z
    r.extend(reasons.to_le_bytes());
    r.extend(0_u32.to_le_bytes());
    r.extend(0_u32.to_le_bytes());
    r.extend(attributes.to_le_bytes());
    r.extend((name.len() as u16).to_le_bytes());
    r.extend(60_u16.to_le_bytes());
    r.extend(name);
    r.resize(r.len().next_multiple_of(8), 0);
    let length = (r.len() as u32).to_le_bytes();
    r[..4].copy_from_slice(&length);
    r
}

const DIRECTORY: u32 = 0x10;
const ARCHIVE: u32 = 0x20;
const CREATE: u32 = 0x100;
const DELETE: u32 = 0x200;
const OLD_NAME: u32 = 0x1000;
const NEW_NAME: u32 = 0x2000;
const CLOSE: u32 = 0x8000_0000;

/// A journal for the volume of `test_files/mft/MFT` (where entry 36 is
/// `WINDOWS/system32/spool/drivers/w32x86`, 37 its subdirectory `3`, 30
/// `WINDOWS/system32/config`): a file in a directory the MFT knows, a directory
/// renamed to the name the MFT has, a directory created and deleted, a parent nobody
/// knows, and a range-tracking (V4) record.
fn usn_journal() -> Vec<u8> {
    let mut j = Vec::new();
    let mut add = |r: &dyn Fn(u64) -> Vec<u8>| {
        let record = r(j.len() as u64);
        j.extend(record);
    };
    add(&|u| usn_v2(u, (900, 1), (36, 1), CREATE, ARCHIVE, "evil.dll"));
    add(&|u| usn_v2(u, (901, 1), (37, 1), CREATE | CLOSE, ARCHIVE, "before.txt"));
    add(&|u| usn_v2(u, (37, 1), (36, 1), OLD_NAME, DIRECTORY, "old3"));
    add(&|u| usn_v2(u, (37, 1), (36, 1), NEW_NAME, DIRECTORY, "3"));
    add(&|u| usn_v2(u, (902, 1), (37, 1), CREATE | CLOSE, ARCHIVE, "after.txt"));
    add(&|u| usn_v2(u, (950, 2), (30, 1), CREATE, DIRECTORY, "Temp1"));
    add(&|u| {
        usn_v2(
            u,
            (903, 1),
            (950, 2),
            CREATE | CLOSE,
            ARCHIVE,
            "dropped.exe",
        )
    });
    add(&|u| usn_v2(u, (950, 2), (30, 1), DELETE | CLOSE, DIRECTORY, "Temp1"));
    add(&|u| usn_v2(u, (904, 1), (999, 9), CREATE, ARCHIVE, "orphan.txt"));
    // USN_RECORD_V4: header, references, USN, reasons, source, remaining, 1 extent of 16 bytes
    let mut v4 = 80_u32.to_le_bytes().to_vec();
    v4.extend(4_u16.to_le_bytes());
    v4.extend(0_u16.to_le_bytes());
    v4.extend(u128::from(1_u64 << 48 | 900).to_le_bytes());
    v4.extend(u128::from(1_u64 << 48 | 36).to_le_bytes());
    v4.extend((j.len() as u64).to_le_bytes());
    v4.extend(2_u32.to_le_bytes());
    v4.extend(0_u32.to_le_bytes());
    v4.extend(0_u32.to_le_bytes());
    v4.extend(1_u16.to_le_bytes());
    v4.extend(16_u16.to_le_bytes());
    v4.extend(0_u64.to_le_bytes());
    v4.extend(4096_u64.to_le_bytes());
    j.extend(v4);
    j
}

/// A KAPE-like collection: the journal at `HOST1/C/$Extend/$J`, the volume's `$MFT` at `HOST1/C/$MFT`.
fn usn_triage() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let extend = dir.path().join("HOST1/C/$Extend");
    std::fs::create_dir_all(&extend).unwrap();
    std::fs::write(extend.join("$J"), usn_journal()).unwrap();
    std::fs::copy(repo(MFT), dir.path().join("HOST1/C/$MFT")).unwrap();
    dir
}

#[test]
fn usn_journal_paths_are_those_of_each_records_time() {
    let dir = usn_triage();
    let journal = dir.path().join("HOST1/C/$Extend/$J");
    let r = run(&[
        "parse-usn-journal",
        "-f",
        journal.to_str().unwrap(),
        "-t",
        "csv",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let mut csv = csv::Reader::from_reader(r.stdout.as_bytes());
    let header = csv.headers().unwrap().clone();
    assert_eq!(
        &header.iter().take(13).collect::<Vec<_>>(),
        &[
            "Name",
            "Extension",
            "EntryNumber",
            "SequenceNumber",
            "ParentEntryNumber",
            "ParentSequenceNumber",
            "ParentPath",
            "UpdateSequenceNumber",
            "UpdateTimestamp",
            "UpdateReasons",
            "FileAttributes",
            "OffsetToData",
            "SourceFile",
        ],
        "MFTECmd's columns first"
    );
    let col = |name: &str| header.iter().position(|h| h == name).unwrap();
    let rows: Vec<csv::StringRecord> = csv.records().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 9, "the V4 record is not a CSV row");
    let path = |name: &str| {
        let row = rows.iter().find(|r| &r[col("Name")] == name).unwrap();
        row[col("ParentPath")].to_string()
    };
    assert_eq!(path("evil.dll"), r".\WINDOWS\system32\spool\drivers\w32x86");
    assert_eq!(
        path("before.txt"),
        r".\WINDOWS\system32\spool\drivers\w32x86\old3",
        "before the rename"
    );
    assert_eq!(
        path("after.txt"),
        r".\WINDOWS\system32\spool\drivers\w32x86\3"
    );
    assert_eq!(
        path("dropped.exe"),
        r".\WINDOWS\system32\config\Temp1",
        "a directory the MFT no longer has"
    );
    assert_eq!(path("orphan.txt"), r".\[Unknown 999-9]");
    let evil = rows.iter().find(|r| &r[col("Name")] == "evil.dll").unwrap();
    assert_eq!(&evil[col("Extension")], ".dll");
    assert_eq!(&evil[col("EntryNumber")], "900");
    assert_eq!(&evil[col("UpdateTimestamp")], "2024-03-01T12:00:00Z");
    assert_eq!(&evil[col("UpdateReasons")], "FILE_CREATE");
    assert_eq!(&evil[col("FileAttributes")], "ARCHIVE");
    assert_eq!(&evil[col("Version")], "2.0");
}

#[test]
fn usn_journal_summary_and_directory_mode() {
    let dir = usn_triage();
    let out = dir.path().join("out");
    let r = run(&[
        "parse-usn-journal",
        "-d",
        dir.path().to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "USN journals: 1",
        "USN journals parsed: 1",
        "Records: 9 (V2: 9, V3: 0)",
        "Range-tracking records (V4): 1",
        "Files created / deleted / renamed: 6 / 1 / 1",
        "Paths: rewound from the journal, seeded from the $MFT",
        "Records with an unknown directory: 1",
        "Damaged data: 0 spans (0 B)",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    let saved = std::fs::read_to_string(out.join("HOST1_C__Extend__J.csv")).unwrap();
    assert_eq!(saved.lines().count(), 10);

    // JSON Lines: every field, and the range-tracking record with its extents
    let journal = dir.path().join("HOST1/C/$Extend/$J");
    let r = run(&[
        "parse-usn-journal",
        "-f",
        journal.to_str().unwrap(),
        "-t",
        "jsonl",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let docs: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(docs.len(), 10);
    assert_eq!(docs[0]["file"]["entry"], 900);
    assert_eq!(docs[0]["reasons"][0], "FILE_CREATE");
    assert_eq!(docs[9]["version"], "4.0");
    assert_eq!(docs[9]["extents"][0]["length"], 4096);
}

#[test]
fn usn_journal_without_an_mft_and_real_records() {
    let r = run(&["parse-usn-journal", "-f", USN_SLICE, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "Records: 199 (V2: 199, V3: 0)",
        "Time range: 2022-02-05T18:56:53.653148700Z",
        "Paths: rewound from the journal (no $MFT found)",
        "To save every record, add -o <FILE>",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn usn_records_are_carved_from_other_data() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.raw");
    let mut data: Vec<u8> = (0..20_000_u32)
        .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    data.extend(usn_journal());
    data.extend([0xA5; 4096]);
    std::fs::write(&image, &data).unwrap();
    let r = run(&[
        "parse-usn-journal",
        "-f",
        image.to_str().unwrap(),
        "--carve",
        "-m",
        MFT,
        "-t",
        "jsonl",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let docs: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        docs.len(),
        9,
        "every V2 record, nothing from the other data"
    );
    assert_eq!(docs[0]["offset"], 80_000);
    assert_eq!(
        docs[0]["parent_path"],
        r".\WINDOWS\system32\spool\drivers\w32x86"
    );

    let r = run(&[
        "parse-usn-journal",
        "-f",
        image.to_str().unwrap(),
        "--carve",
        "-K",
    ]);
    assert!(
        r.stdout.contains("Records carved: 9 (V2: 9, V3: 0)"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("Paths: none (no $MFT given)"));
}

// --- parse-srum --------------------------------------------------------------------------------

const SRUM_WIN10: &str = "test_files/srum/win10_rathbunvm_SRUDB.dat";
const SRUM_SERVER: &str = "test_files/srum/server2022_aptsimulatorvm_SRUDB.dat";
/// The account most of the Windows 10 database's entries are for.
const RATHBUN_SID: &str = "S-1-5-21-2290304894-658537038-505560459-1000";

/// A registry key of the hives the SRUM tests build: its name, values (name, type, data) and
/// subkeys.
struct RegKey {
    name: String,
    values: Vec<(String, u32, Vec<u8>)>,
    subkeys: Vec<RegKey>,
}

fn reg_key(name: &str, values: Vec<(&str, u32, Vec<u8>)>, subkeys: Vec<RegKey>) -> RegKey {
    RegKey {
        name: name.to_string(),
        values: values
            .into_iter()
            .map(|(n, t, d)| (n.to_string(), t, d))
            .collect(),
        subkeys,
    }
}

const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Append a cell (its size, negative: allocated) holding `data`; its offset in the hive bins.
fn alloc_cell(cells: &mut Vec<u8>, data: &[u8]) -> u32 {
    let at = cells.len();
    let size = (4 + data.len()).next_multiple_of(8);
    cells.extend_from_slice(&(-(size as i32)).to_le_bytes());
    cells.extend_from_slice(data);
    cells.resize(at + size, 0);
    at as u32
}

/// Write a key node with its values and subkeys (an `lf` list, sorted); its offset.
fn write_key(cells: &mut Vec<u8>, key: &RegKey, parent: u32, root: bool) -> u32 {
    let mut nk = vec![0u8; 76];
    nk[0..2].copy_from_slice(b"nk");
    // KEY_COMP_NAME (an ASCII name), and for the root KEY_HIVE_ENTRY | KEY_NO_DELETE
    nk[2..4].copy_from_slice(&(if root { 0x2cu16 } else { 0x20 }).to_le_bytes());
    put_u32(&mut nk, 16, parent);
    for unset in [28, 32, 40, 44, 48] {
        put_u32(&mut nk, unset, u32::MAX);
    }
    nk[72..74].copy_from_slice(&(key.name.len() as u16).to_le_bytes());
    nk.extend_from_slice(key.name.as_bytes());
    let at = alloc_cell(cells, &nk);
    let field = at as usize + 4;
    if !key.values.is_empty() {
        let mut list = Vec::new();
        for (name, kind, data) in &key.values {
            let mut vk = vec![0u8; 20];
            vk[0..2].copy_from_slice(b"vk");
            vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            if data.len() <= 4 {
                // resident: the data is in the offset field
                put_u32(&mut vk, 4, data.len() as u32 | 0x8000_0000);
                vk[8..8 + data.len()].copy_from_slice(data);
            } else {
                put_u32(&mut vk, 4, data.len() as u32);
                let data_at = alloc_cell(cells, data);
                put_u32(&mut vk, 8, data_at);
            }
            put_u32(&mut vk, 12, *kind);
            vk[16..18].copy_from_slice(&1u16.to_le_bytes()); // VALUE_COMP_NAME
            vk.extend_from_slice(name.as_bytes());
            list.extend_from_slice(&alloc_cell(cells, &vk).to_le_bytes());
        }
        let list_at = alloc_cell(cells, &list);
        put_u32(cells, field + 36, key.values.len() as u32);
        put_u32(cells, field + 40, list_at);
    }
    if !key.subkeys.is_empty() {
        let mut subkeys: Vec<&RegKey> = key.subkeys.iter().collect();
        subkeys.sort_by_key(|k| k.name.to_ascii_uppercase());
        let mut lf = b"lf".to_vec();
        lf.extend_from_slice(&(subkeys.len() as u16).to_le_bytes());
        for sub in subkeys {
            let sub_at = write_key(cells, sub, at, false);
            lf.extend_from_slice(&sub_at.to_le_bytes());
            let mut hint = [0u8; 4];
            for (h, b) in hint.iter_mut().zip(sub.name.bytes()) {
                *h = b;
            }
            lf.extend_from_slice(&hint);
        }
        let lf_at = alloc_cell(cells, &lf);
        put_u32(cells, field + 20, key.subkeys.len() as u32);
        put_u32(cells, field + 28, lf_at);
    }
    at
}

/// A registry hive (REGF 1.5, one hive bin) holding `root`.
fn regf(root: &RegKey) -> Vec<u8> {
    let mut cells = vec![0u8; 32]; // the hive bin's header
    let root_at = write_key(&mut cells, root, 0, true);
    let size = (cells.len() + 8).next_multiple_of(4096);
    let free = size - cells.len();
    cells.extend_from_slice(&(free as i32).to_le_bytes());
    cells.resize(size, 0);
    cells[0..4].copy_from_slice(b"hbin");
    put_u32(&mut cells, 8, size as u32);
    let mut base = vec![0u8; 4096];
    base[0..4].copy_from_slice(b"regf");
    for (at, v) in [(4, 1), (8, 1), (20, 1), (24, 5), (32, 1), (44, 1)] {
        put_u32(&mut base, at, v);
    }
    put_u32(&mut base, 36, root_at);
    put_u32(&mut base, 40, size as u32);
    let checksum = base[..508]
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |x, w| x ^ u32::from_le_bytes(*w));
    put_u32(&mut base, 508, checksum);
    base.extend_from_slice(&cells);
    base
}

/// A Wi-Fi profile key: its index and a `Channel Hints` value declaring `length` bytes of SSID.
fn wifi_profile(guid: &str, index: u32, length: i32, ssid: &[u8]) -> RegKey {
    let mut hints = length.to_le_bytes().to_vec();
    hints.extend_from_slice(ssid);
    hints.resize(hints.len().max(36), 0);
    reg_key(
        guid,
        vec![("ProfileIndex", REG_DWORD, index.to_le_bytes().to_vec())],
        vec![reg_key(
            "MetaData",
            vec![("Channel Hints", REG_BINARY, hints)],
            vec![],
        )],
    )
}

/// A SOFTWARE hive naming two accounts and two Wi-Fi networks, with a profile left without
/// metadata, one whose index another profile already took (the first one names it, as in
/// SrumECmd), and one whose `Channel Hints` is damaged. Index 0 is the `L2ProfileId` of the Windows
/// 10 database's network entries.
fn software_hive() -> Vec<u8> {
    let profile = |sid: &str, image: &str| {
        reg_key(
            sid,
            vec![("ProfileImagePath", REG_EXPAND_SZ, utf16z(image))],
            vec![],
        )
    };
    let profiles = reg_key(
        "ProfileList",
        vec![],
        vec![
            profile("S-1-5-19", r"%systemroot%\ServiceProfiles\LocalService"),
            profile(RATHBUN_SID, r"C:\Users\rathbun"),
        ],
    );
    let wlan_profiles = reg_key(
        "Profiles",
        vec![],
        vec![
            wifi_profile("{1A}", 0, 10, b"CoffeeShop"),
            wifi_profile("{1B}", 0, 6, b"Second"),
            wifi_profile("{1C}", 8, 4, b"Home"),
            wifi_profile("{1D}", 9, 40, b"Broken"),
            reg_key(
                "{1E}",
                vec![("ProfileIndex", REG_DWORD, 10u32.to_le_bytes().to_vec())],
                vec![],
            ),
        ],
    );
    let microsoft = reg_key(
        "Microsoft",
        vec![],
        vec![
            reg_key(
                "Windows NT",
                vec![],
                vec![reg_key("CurrentVersion", vec![], vec![profiles])],
            ),
            reg_key(
                "WlanSvc",
                vec![],
                vec![reg_key(
                    "Interfaces",
                    vec![],
                    vec![reg_key("{0F00}", vec![], vec![wlan_profiles])],
                )],
            ),
        ],
    );
    regf(&reg_key("ROOT", vec![], vec![microsoft]))
}

/// The rows of a CSV file, by column name.
fn csv_rows(path: &Path) -> (Vec<String>, Vec<std::collections::HashMap<String, String>>) {
    let mut reader = csv::Reader::from_path(path).unwrap();
    let header: Vec<String> = reader.headers().unwrap().iter().map(String::from).collect();
    let rows = reader
        .records()
        .map(|r| {
            header
                .iter()
                .cloned()
                .zip(r.unwrap().iter().map(String::from))
                .collect()
        })
        .collect();
    (header, rows)
}

#[test]
fn srum_summary_on_the_terminal() {
    let r = run(&["parse-srum", "-f", SRUM_WIN10, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "SRUM databases parsed: 1",
        "Entries: 309",
        "  AppResourceUseInfo: 118",
        "  AppTimelineProvider: 163",
        "  NetworkConnections: 1",
        "  NetworkUsages: 23",
        "  vfuprov: 4",
        "Time range: 2022-02-05T22:19:00Z - 2022-02-05T22:19:00Z",
        "Network: 1.8 MiB sent, 141.8 MiB received",
        "Top senders:",
        "   262.1 KiB  LicenseManager",
        "Account and Wi-Fi names: none (no SOFTWARE hive found; give one with -r)",
        "6 AppId / UserId values are not in SruDbIdMapTable",
        "To save every entry, add -o <DIR>",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    assert!(!r.stdout.contains("Left dirty"));
}

#[test]
fn srum_csv_tables_with_names_from_the_software_hive() {
    let dir = tempfile::tempdir().unwrap();
    let hive = dir.path().join("SOFTWARE");
    std::fs::write(&hive, software_hive()).unwrap();
    let out = dir.path().join("out");
    let hive_arg = hive.to_str().unwrap();
    let r = run(&[
        "parse-srum",
        "-f",
        SRUM_WIN10,
        "-r",
        hive_arg,
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.stdout.contains(
            "Account and Wi-Fi names: from the SOFTWARE hive (2 accounts, 2 Wi-Fi networks)"
        ),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains(r"Wi-Fi profile {0F00}\{1D}: Channel Hints says the name has 40 bytes"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("(6 CSV files)"), "{}", r.stdout);
    let mut files: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "AppResourceUseInfo.csv",
            "AppTimelineProvider.csv",
            "NetworkConnections.csv",
            "NetworkUsages.csv",
            "SruDbIdMapTable.csv",
            "vfuprov.csv"
        ]
    );

    let (header, rows) = csv_rows(&out.join("NetworkUsages.csv"));
    assert_eq!(
        header,
        [
            "Id",
            "Timestamp",
            "ExeInfo",
            "ExeInfoDescription",
            "ExeTimestamp",
            "AppType",
            "Sid",
            "UserName",
            "UserId",
            "AppId",
            "InterfaceLuid",
            "InterfaceType",
            "L2ProfileId",
            "ProfileName",
            "L2ProfileFlags",
            "BytesSent",
            "BytesRecvd"
        ]
    );
    assert_eq!(rows.len(), 23);
    let first = &rows[0];
    for (column, value) in [
        ("Id", "1"),
        ("Timestamp", "2022-02-05T22:19:00Z"),
        ("ExeInfo", "wlidsvc"),
        ("AppType", "Service"),
        ("Sid", "S-1-5-19"),
        ("UserName", "LocalService"),
        ("InterfaceType", "IF_TYPE_ETHERNET_CSMACD"),
        ("ProfileName", "CoffeeShop"),
        ("BytesSent", "11988"),
        ("BytesRecvd", "12755"),
    ] {
        assert_eq!(first[column], value, "{column}");
    }
    let rathbun: Vec<_> = rows.iter().filter(|r| r["Sid"] == RATHBUN_SID).collect();
    assert!(!rathbun.is_empty());
    assert!(rathbun.iter().all(|r| r["UserName"] == "rathbun"));

    // `!!name!time!x!description` names split; FILETIME columns as times
    let (_, timeline) = csv_rows(&out.join("AppTimelineProvider.csv"));
    let split = timeline
        .iter()
        .find(|r| r["ExeInfoDescription"] == "[LocalService] [WdiServiceHost]")
        .unwrap();
    assert_eq!(split["ExeInfo"], "svchost.exe");
    assert_eq!(split["ExeTimestamp"], "1972-12-14T16:22:50Z");
    assert_eq!(split["EndTime"], "2022-02-05T22:18:49.336199700Z");
    assert!(
        timeline
            .iter()
            .all(|r| r["EndTime"].starts_with("2022-02-"))
    );
    let (_, ids) = csv_rows(&out.join("SruDbIdMapTable.csv"));
    assert_eq!(ids.len(), 288);
    assert_eq!(ids[3]["IdBlob"], "S-1-5-19");

    // existing results are kept without -C
    let again = run(&["parse-srum", "-f", SRUM_WIN10, "-o", out.to_str().unwrap()]);
    assert_eq!(again.code, 1);
    assert!(again.stdout.contains("already exists"), "{}", again.stdout);
}

#[test]
fn srum_json_and_jsonl() {
    let r = run(&["parse-srum", "-f", SRUM_WIN10, "-t", "jsonl"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stdout.contains("Results Summary"));
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 309);
    // the columns keep their order
    assert!(
        lines[0]
            .starts_with(r#"{"SourceFile":"test_files/srum/win10_rathbunvm_SRUDB.dat","Table":"#)
    );
    let entries: Vec<Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let connection = entries
        .iter()
        .find(|e| e["Provider"] == "NetworkConnections")
        .unwrap();
    assert_eq!(
        connection["Table"],
        "{DD6636C4-8929-4683-974E-22C046A43763}"
    );
    assert!(
        connection["ConnectStartTime"]
            .as_str()
            .unwrap()
            .starts_with("20")
    );
    assert!(connection["ConnectedTime"].is_u64());
    assert!(connection["UserName"].is_null());

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("srum.json");
    let r = run(&[
        "parse-srum",
        "-f",
        SRUM_WIN10,
        "-t",
        "json",
        "-o",
        file.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let documents = json_documents(&std::fs::read_to_string(&file).unwrap());
    assert_eq!(documents.len(), 309);
    assert_eq!(documents, entries);
}

#[test]
fn srum_triage_directory_with_server_tables() {
    let dir = tempfile::tempdir().unwrap();
    let host1 = dir.path().join("HOST1/C/Windows/System32");
    std::fs::create_dir_all(host1.join("sru")).unwrap();
    std::fs::create_dir_all(host1.join("config")).unwrap();
    std::fs::copy(repo(SRUM_WIN10), host1.join("sru/SRUDB.dat")).unwrap();
    std::fs::write(host1.join("config/SOFTWARE"), software_hive()).unwrap();
    let host2 = dir.path().join("HOST2/C/Windows/System32/SRU");
    std::fs::create_dir_all(&host2).unwrap();
    std::fs::copy(repo(SRUM_SERVER), host2.join("SRUDB.dat")).unwrap();
    std::fs::write(dir.path().join("HOST3_SRUDB.dat"), b"not a database").unwrap();
    let triage = dir.path().to_str().unwrap();

    let out = tempfile::tempdir().unwrap();
    let r = run(&[
        "parse-srum",
        "-d",
        triage,
        "-o",
        out.path().to_str().unwrap(),
        "-C",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    for line in [
        "SRUM databases parsed: 2 (could not parse: 1)",
        "Entries: 476",
        "  ProcessorTime: 2",
        "  TotalUsed: 4",
        "Account and Wi-Fi names: from the SOFTWARE hive (2 accounts, 2 Wi-Fi networks)",
        "Databases without a SOFTWARE hive: 1",
        "Could not parse",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    let server = out.path().join("HOST2_C_Windows_System32_SRU_SRUDB");
    let mut files: Vec<String> = std::fs::read_dir(&server)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "AppResourceUseInfo.csv",
            "NetworkBytes.csv",
            "NetworkConnections.csv",
            "ProcessorTime.csv",
            "SizeInBytes.csv",
            "SruDbIdMapTable.csv",
            "TotalUsed.csv"
        ]
    );
    let (_, used) = csv_rows(&server.join("TotalUsed.csv"));
    assert_eq!(used.len(), 4);
    assert!(used.iter().all(|r| r["AppType"] == "Object"));
    let (_, network) = csv_rows(
        &out.path()
            .join("HOST1_C_Windows_System32_sru_SRUDB/NetworkUsages.csv"),
    );
    assert_eq!(network[0]["UserName"], "LocalService");

    // one JSONL file per database
    let jsonl = tempfile::tempdir().unwrap();
    let r = run(&[
        "parse-srum",
        "-d",
        triage,
        "-t",
        "jsonl",
        "-o",
        jsonl.path().to_str().unwrap(),
        "-C",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let server = std::fs::read_to_string(
        jsonl
            .path()
            .join("HOST2_C_Windows_System32_SRU_SRUDB.jsonl"),
    )
    .unwrap();
    assert_eq!(server.lines().count(), 167);
}

#[test]
fn srum_input_and_output_errors() {
    let r = run(&["parse-srum", "-f", "test_files/srum/missing.dat", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The file does not exist"), "{}", r.stdout);

    let r = run(&["parse-srum", "-f", "test_files/srum/README.md", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("Could not parse"), "{}", r.stdout);

    let r = run(&["parse-srum", "-d", "test_files/amcache", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("No SRUM databases"), "{}", r.stdout);

    let r = run(&["parse-srum", "-f", SRUM_WIN10, "-t", "csv"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("CSV output needs -o <DIR>"),
        "{}",
        r.stdout
    );

    let r = run(&["parse-srum", "-d", "test_files/srum", "-t", "jsonl"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("With -d, save the entries with -o"),
        "{}",
        r.stderr
    );

    // a SOFTWARE hive that can't be read: the entries are still written, without names
    let dir = tempfile::tempdir().unwrap();
    let hive = dir.path().join("SOFTWARE");
    std::fs::write(&hive, b"regf but not a hive").unwrap();
    let r = run(&[
        "parse-srum",
        "-f",
        SRUM_WIN10,
        "-r",
        hive.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.stdout.contains("Could not read the SOFTWARE hive"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("Entries: 309"), "{}", r.stdout);
}

// --- parse-lnk ---------------------------------------------------------------------------------

const LNK_DIR: &str = "test_files/lnk";

#[test]
fn lnk_summary_on_the_terminal() {
    let r = run(&["parse-lnk", "-d", LNK_DIR, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    // found under -d, so with the platform's separator
    let found = |name: &str| format!("  {} -> ", Path::new(LNK_DIR).join(name).display());
    for line in [
        "Shortcuts parsed: 6".to_owned(),
        "Targets: fixed drives 2, removable drives 1, CD/DVD 0, network shares 1".to_owned(),
        "Machines that made them: 1 (sagerez)".to_owned(),
        "With problems: 1".to_owned(),
        "Hidden command line (string data over 260 characters): 1".to_owned(),
        found("padded_cli_arguments.lnk") + r#"This PC\C:\Windows\System32\cmd.exe /c "set PATH="#,
        "Data after the end of the link: 1".to_owned(),
        found("appended_data.lnk") + r"This PC\All Control Panel Items\" + "\n",
        "Shell or script host started with arguments: 2".to_owned(),
        found("msbuild_prompt.lnk") + r"C:\Windows\System32\cmd.exe /k",
        "To save every record, add -o <FILE>".to_owned(),
    ] {
        assert!(r.stdout.contains(&line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn lnk_csv_has_lecmds_columns() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("lnk.csv");
    let r = run(&[
        "parse-lnk",
        "-d",
        LNK_DIR,
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (header, rows) = csv_rows(&out);
    assert_eq!(
        &header[..5],
        [
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "TargetCreated"
        ]
    );
    assert_eq!(header.len(), 46);
    assert_eq!(rows.len(), 6);
    let row = |name: &str| {
        rows.iter()
            .find(|r| r["SourceFile"].ends_with(name))
            .unwrap()
    };
    // Directory Opus's help, from Eric Zimmerman's test set: as LECmd reads it
    let opus = row("opus_help.lnk");
    for (column, value) in [
        ("TargetCreated", "2015-12-25T02:42:20.167694100Z"),
        ("TargetModified", "2015-12-17T17:36:56Z"),
        ("FileSize", "8705626"),
        (
            "LocalPath",
            r"C:\Program Files\GPSoftware\Directory Opus\Help\dopus.chm",
        ),
        (
            "TargetIDAbsolutePath",
            r"This PC\C:\Program Files\GPSoftware\Directory Opus\Help\dopus.chm",
        ),
        ("TargetMFTEntryNumber", "108088"),
        ("TargetMFTSequenceNumber", "1"),
        ("MachineID", "sagerez"),
        ("MachineMACAddress", "a4:34:d9:43:f3:63"),
        ("TrackerCreatedOn", "2015-12-25T02:28:38.498589100Z"),
        ("VolumeSerialNumber", "6A228FAA"),
        ("DriveType", "DRIVE_FIXED"),
        ("FileAttributes", "ARCHIVE"),
        (
            "ExtraBlocksPresent",
            "IconEnvironmentDataBlock|TrackerDataBlock|PropertyStoreDataBlock",
        ),
        ("ShowWindow", "SW_SHOWNORMAL"),
        ("VolumeDroid", "38648bd4-606f-459b-91e5-d8883d4b70b1"),
        ("FileDroid", "34b5a323-aaaf-11e5-b29b-a434d943f363"),
        ("Problems", ""),
        ("AppendedBytes", "0"),
    ] {
        assert_eq!(opus[column], value, "{column}");
    }
    assert!(opus["HeaderFlags"].starts_with("HasLinkTargetIDList|HasLinkInfo|"));
    assert_eq!(
        row("network_share_unicode.lnk")["NetworkPath"],
        r"\\127.0.0.1\TEST"
    );
    assert_eq!(row("removable_drive.lnk")["DriveType"], "DRIVE_REMOVABLE");
    assert_eq!(row("appended_data.lnk")["AppendedBytes"], "67649");
    let padded = row("padded_cli_arguments.lnk");
    assert_eq!(padded["Arguments"].chars().count(), 1431);
    assert!(padded["Problems"].starts_with("string data longer than 260 characters"));
}

#[test]
fn lnk_json_and_jsonl() {
    let r = run(&[
        "parse-lnk",
        "-f",
        "test_files/lnk/opus_help.lnk",
        "-t",
        "jsonl",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stdout.contains("Results Summary"));
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["tracker"]["machine_id"], "sagerez");
    assert_eq!(
        v["tracker"]["volume_droid_birth"],
        "38648bd4-606f-459b-91e5-d8883d4b70b1"
    );
    assert_eq!(v["target_mft_entry"], 108_088);
    assert_eq!(v["header"]["show_command"], "SW_SHOWNORMAL");
    let items = v["target_items"].as_array().unwrap();
    assert_eq!(items[0]["name"], "This PC");
    assert_eq!(items.last().unwrap()["name"], "dopus.chm");
    assert_eq!(v["extra_blocks"][0], "IconEnvironmentDataBlock");
    assert!(
        v["icon_environment"]
            .as_str()
            .unwrap()
            .starts_with("%SystemDrive%")
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("lnk.json");
    let r = run(&[
        "parse-lnk",
        "-d",
        LNK_DIR,
        "-t",
        "json",
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let docs = json_documents(&std::fs::read_to_string(&out).unwrap());
    assert_eq!(docs.len(), 6);
    let padded = docs
        .iter()
        .find(|d| {
            d["source_file"]
                .as_str()
                .unwrap()
                .ends_with("padded_cli_arguments.lnk")
        })
        .unwrap();
    assert_eq!(padded["problems"].as_array().unwrap().len(), 2);
}

#[test]
fn lnk_times_that_are_not_times() {
    // a link whose target creation time is 2^63 (100 ns units), past any time: empty, no panic
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(repo("test_files/lnk/opus_help.lnk")).unwrap();
    data[28..36].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
    let file = dir.path().join("opus_help.lnk");
    std::fs::write(&file, &data).unwrap();
    let r = run(&["parse-lnk", "-f", file.to_str().unwrap(), "-t", "jsonl"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["header"]["target_created"], "");
    assert_eq!(v["header"]["target_modified"], "2015-12-17T17:36:56Z");
}

#[test]
fn lnk_input_and_output_errors() {
    let r = run(&["parse-lnk", "-f", "test_files/lnk/missing.lnk", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The file does not exist"), "{}", r.stdout);

    let r = run(&[
        "parse-lnk",
        "-f",
        "test_files/lnk/../amcache/README.md",
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("Could not parse"), "{}", r.stdout);
    assert!(r.stdout.contains("not a shell link"), "{}", r.stdout);

    let r = run(&["parse-lnk", "-d", "test_files/amcache", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("No shortcuts (*.lnk)"), "{}", r.stdout);

    let r = run(&[
        "parse-lnk",
        "-f",
        "test_files/lnk/opus_help.lnk",
        "--code-page",
        "12345",
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("Code page 12345 is not supported"),
        "{}",
        r.stdout
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("x.csv");
    std::fs::write(&out, b"keep").unwrap();
    let r = run(&[
        "parse-lnk",
        "-f",
        "test_files/lnk/opus_help.lnk",
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("already exists"), "{}", r.stdout);
}

// --- parse-jump-lists --------------------------------------------------------------------------

const JUMP_LIST_DIR: &str = "test_files/jump_lists";
const EXPLORER_WIN10: &str = "test_files/jump_lists/f01b4d95cf55d32a.automaticDestinations-ms";
const CHROME_WIN11: &str = "test_files/jump_lists/5d696d521de238c3.customDestinations-ms";

#[test]
fn jump_list_summary_on_the_terminal() {
    let r = run(&["parse-jump-lists", "-d", JUMP_LIST_DIR, "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    // found under -d, so with the platform's separator
    let found = |name: &str| format!("  {} (", Path::new(JUMP_LIST_DIR).join(name).display());
    for line in [
        "Jump lists parsed: 4 (automatic 3, custom 1)".to_owned(),
        "Entries: 50 (pinned 4), custom list links 6".to_owned(),
        "Applications: 4 (4 named from their AppID)".to_owned(),
        "  Windows Explorer Windows 8.1 (f01b4d95cf55d32a): 9 links".to_owned(),
        "Machines in the entries: 3 (desktop-annfp9d, pc, win7x64)".to_owned(),
        "Targets: fixed drives 57, removable drives 0, CD/DVD 1, network shares 0".to_owned(),
        "With problems: 0".to_owned(),
        "Links left over from an earlier version of a custom list: 2".to_owned(),
        found("5d696d521de238c3.customDestinations-ms")
            + r"at 11472) -> C:\Program Files\Google\Chrome\Application\chrome.exe --win-jumplist-action=most-visited http://192.168.50.33:5000/",
        "Link streams no DestList entry names (removed or damaged entries): 0".to_owned(),
        "Items staged for a CD or DVD burn: 1".to_owned(),
        found("5f7b5f1e01b83767.automaticDestinations-ms") + r"entry 1) -> D:\autorun.inf",
        "Shell or script host started with arguments: 0".to_owned(),
        "To save every entry, add -o <DIR> (CSV tables)".to_owned(),
    ] {
        assert!(r.stdout.contains(&line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn jump_list_csv_has_jlecmds_columns() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("jl");
    let r = run(&[
        "parse-jump-lists",
        "-d",
        JUMP_LIST_DIR,
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("(2 CSV files)"), "{}", r.stdout);
    let (header, rows) = csv_rows(&out.join("AutomaticDestinations.csv"));
    assert_eq!(
        &header[..7],
        [
            "SourceFile",
            "SourceCreated",
            "SourceModified",
            "SourceAccessed",
            "AppId",
            "AppIdDescription",
            "HasSps"
        ]
    );
    assert_eq!(header[43], "Notes");
    assert_eq!(header.len(), 50);
    assert_eq!(rows.len(), 50);
    let row = |file: &str, mru: &str| {
        rows.iter()
            .find(|r| r["SourceFile"].ends_with(file) && r["MRU"] == mru)
            .unwrap()
    };
    // Windows 10 Explorer, from Eric Zimmerman's test set: as JLECmd reads it
    let temp = row("f01b4d95cf55d32a.automaticDestinations-ms", "0");
    for (column, value) in [
        ("AppId", "f01b4d95cf55d32a"),
        ("AppIdDescription", "Windows Explorer Windows 8.1"),
        ("DestListVersion", "3"),
        ("LastUsedEntryNumber", "9"),
        ("EntryNumber", "7"),
        ("CreationTime", "2015-11-24T18:39:02.491271400Z"),
        ("LastModified", "2015-11-24T20:31:34.447525300Z"),
        ("Hostname", "desktop-annfp9d"),
        ("MacAddress", "00:15:5d:01:6d:02"),
        ("Path", r"C:\Temp"),
        ("InteractionCount", "2"),
        ("PinStatus", "False"),
        ("FileDroid", "a21b9d4a-92da-11e5-88e1-00155d016d02"),
        ("VolumeBirthDroid", "4c01e77a-2661-40c9-b838-14ff153a26f5"),
        ("TargetCreated", "2015-11-24T20:30:53.363218400Z"),
        ("LocalPath", r"C:\Temp"),
        ("TargetIDAbsolutePath", r"This PC\C:\Temp"),
        ("TargetMFTEntryNumber", "192"),
        ("TargetMFTSequenceNumber", "5"),
        ("DriveType", "DRIVE_FIXED"),
        (
            "ExtraBlocksPresent",
            "TrackerDataBlock|PropertyStoreDataBlock",
        ),
        ("Notes", ""),
        ("Problems", ""),
    ] {
        assert_eq!(temp[column], value, "{column}");
    }
    // Windows 7 Explorer, a version 1 list: no interaction count is recorded, and JLECmd writes 0
    let videos = row("1b4dd67f29cb1962.automaticDestinations-ms", "0");
    for (column, value) in [
        ("DestListVersion", "1"),
        ("EntryNumber", "4"),
        ("InteractionCount", "0"),
        ("Hostname", "win7x64"),
        (
            "Path",
            r"::{031E4825-7B94-4DC3-B131-E946B44C8DD5}\Videos.library-ms",
        ),
        ("DisplayPath", r"UsersLibraries\Videos.library-ms"),
    ] {
        assert_eq!(videos[column], value, "{column}");
    }
    assert!(videos["LastModified"].starts_with("2016-01-16T20:23:24"));
    // A Windows 10 version 6 list that ends inside its last sector: entry 1 is a file staged
    // for a CD burn, named as JLECmd names it
    let burn = row("5f7b5f1e01b83767.automaticDestinations-ms", "36");
    assert_eq!(burn["DestListVersion"], "6");
    assert_eq!(burn["TargetIDAbsolutePath"], r"This PC\D:\autorun.inf");
    assert_eq!(burn["DriveType"], "DRIVE_CDROM");
    assert_eq!(
        rows.iter()
            .filter(|r| r["SourceFile"].ends_with("5f7b5f1e01b83767.automaticDestinations-ms"))
            .count(),
        37
    );

    let (header, rows) = csv_rows(&out.join("CustomDestinations.csv"));
    assert_eq!(header[6], "EntryName");
    assert_eq!(header.len(), 33);
    assert_eq!(rows.len(), 8);
    let chrome: Vec<_> = rows
        .iter()
        .filter(|r| r["SourceFile"].ends_with("5d696d521de238c3.customDestinations-ms"))
        .collect();
    let names: Vec<&str> = chrome.iter().map(|r| r["EntryName"].as_str()).collect();
    assert_eq!(
        names,
        [
            "Most visited",
            "Most visited",
            "Recently closed",
            "Recently closed",
            "Tasks",
            "Tasks",
            "",
            ""
        ]
    );
    assert_eq!(
        chrome[6]["Notes"],
        "Left over after the last category, at offset 11472"
    );
    assert_eq!(
        chrome[7]["Arguments"],
        "--win-jumplist-action=recently-closed http://192.168.50.33:3000/"
    );
    assert_eq!(chrome[5]["Arguments"], "--incognito");
}

#[test]
fn jump_list_json_and_jsonl() {
    let r = run(&["parse-jump-lists", "-f", EXPLORER_WIN10, "-t", "jsonl"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stdout.contains("Results Summary"));
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["type"], "automatic");
    assert_eq!(v["app_id"], "f01b4d95cf55d32a");
    assert_eq!(v["dest_list"]["version"], 3);
    assert_eq!(v["dest_list"]["last_entry_number"], 9);
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 9);
    assert_eq!(entries[0]["stream"], "7");
    assert_eq!(entries[0]["interaction_count"], 2);
    assert_eq!(entries[0]["link"]["target_path"], r"This PC\C:\Temp");
    assert_eq!(
        entries[0]["link"]["tracker"]["machine_id"],
        "desktop-annfp9d"
    );
    assert_eq!(v["streams"].as_array().unwrap().len(), 10);
    assert_eq!(v["problems"].as_array().unwrap().len(), 0);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("jl.json");
    let r = run(&[
        "parse-jump-lists",
        "-f",
        CHROME_WIN11,
        "-t",
        "json",
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let docs = json_documents(&std::fs::read_to_string(&out).unwrap());
    assert_eq!(docs.len(), 1);
    let chrome = &docs[0];
    assert_eq!(chrome["type"], "custom");
    assert_eq!(chrome["format_version"], 2);
    let categories = chrome["categories"].as_array().unwrap();
    assert_eq!(categories[0]["name"], "Most visited");
    assert_eq!(categories[2]["kind"], "tasks");
    assert_eq!(chrome["trailing_bytes"], 3250);
    assert_eq!(chrome["leftover"][0]["offset"], 11472);
    assert_eq!(
        chrome["leftover"][0]["link"]["arguments"],
        "--win-jumplist-action=most-visited http://192.168.50.33:5000/"
    );
}

/// `data` with the compound file directory entry of stream `from` renamed `to` (names of the
/// same length or longer, up to 31 characters).
fn rename_stream(data: &mut [u8], from: &str, to: &str) {
    let name = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let (from, to) = (name(from), name(to));
    // Directory entries are 128 bytes, sector-aligned: the name, its size in bytes at 64, the
    // type at 66 (2 = stream).
    let at = (0..data.len() - 128)
        .step_by(128)
        .find(|&o| {
            data[o..o + from.len()] == from[..]
                && data[o + 64..o + 66] == (from.len() as u16).to_le_bytes()
                && data[o + 66] == 2
        })
        .unwrap();
    data[at..at + 64].fill(0);
    data[at..at + to.len()].copy_from_slice(&to);
    data[at + 64..at + 66].copy_from_slice(&(to.len() as u16).to_le_bytes());
}

#[test]
fn jump_list_streams_no_entry_names() {
    // Explorer's list with entry 7's stream renamed: entry 7 has no link, stream 99 no entry.
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(repo(EXPLORER_WIN10)).unwrap();
    rename_stream(&mut data, "7", "99");
    let file = dir.path().join("f01b4d95cf55d32a.automaticDestinations-ms");
    std::fs::write(&file, &data).unwrap();
    let out = dir.path().join("jl");
    let r = run(&[
        "parse-jump-lists",
        "-f",
        file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    for line in [
        "entry 7 has no stream",
        "With problems: 1",
        "Link streams no DestList entry names (removed or damaged entries): 1",
        r"(stream 99) -> C:\Temp",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    let (_, rows) = csv_rows(&out.join("AutomaticDestinations.csv"));
    assert_eq!(rows.len(), 10);
    let entry = rows.iter().find(|r| r["EntryNumber"] == "7").unwrap();
    assert_eq!(entry["Path"], r"C:\Temp");
    assert_eq!(entry["LocalPath"], "");
    // as JLECmd writes it with --withDir
    let unlisted = rows.iter().find(|r| r["EntryNumber"] == "99").unwrap();
    assert_eq!(unlisted["MRU"], "");
    assert_eq!(unlisted["Notes"], "Found in Directory, not DestList");
    assert_eq!(unlisted["LocalPath"], r"C:\Temp");
    assert_eq!(unlisted["Path"], "");
}

/// `data` with the one occurrence of `from` (a little-endian u64) replaced with `to`.
fn replace_u64(data: &mut [u8], from: u64, to: u64) {
    let from = from.to_le_bytes();
    let found: Vec<usize> = (0..data.len() - 8)
        .filter(|&o| data[o..o + 8] == from)
        .collect();
    assert_eq!(found.len(), 1);
    data[found[0]..found[0] + 8].copy_from_slice(&to.to_le_bytes());
}

#[test]
fn jump_list_times_that_are_not_times() {
    // Explorer's most recent entry last used at 2^63 (100 ns units), past any time: empty, no
    // panic (it overflowed the conversion)
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(repo(EXPLORER_WIN10)).unwrap();
    // 2015-11-24T20:31:34.4475253Z
    replace_u64(&mut data, 0x01d1_26f7_1c53_a075, 0x8000_0000_0000_0000);
    let file = dir.path().join("f01b4d95cf55d32a.automaticDestinations-ms");
    std::fs::write(&file, &data).unwrap();
    let r = run(&[
        "parse-jump-lists",
        "-f",
        file.to_str().unwrap(),
        "-t",
        "jsonl",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["entries"][0]["last_used"], "");
    assert_eq!(
        v["entries"][1]["last_used"],
        "2015-11-24T20:31:34.433022100Z"
    );
    let out = dir.path().join("jl");
    let r = run(&[
        "parse-jump-lists",
        "-f",
        file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (_, rows) = csv_rows(&out.join("AutomaticDestinations.csv"));
    assert_eq!(rows[0]["LastModified"], "");
    assert_eq!(rows[0]["Path"], r"C:\Temp");
}

#[test]
fn jump_list_input_and_output_errors() {
    let r = run(&[
        "parse-jump-lists",
        "-f",
        "test_files/jump_lists/missing",
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The file does not exist"), "{}", r.stdout);

    let r = run(&["parse-jump-lists", "-f", "test_files/lnk/README.md", "-K"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("Could not parse") && r.stdout.contains("not a custom jump list"),
        "{}",
        r.stdout
    );

    let r = run(&["parse-jump-lists", "-d", "test_files/lnk", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("No jump lists"), "{}", r.stdout);

    let r = run(&[
        "parse-jump-lists",
        "-f",
        EXPLORER_WIN10,
        "--code-page",
        "12345",
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("Code page 12345 is not supported"),
        "{}",
        r.stdout
    );

    // CSV tables need an empty directory (or -C); JSON a new file
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keep"), b"keep").unwrap();
    let r = run(&[
        "parse-jump-lists",
        "-f",
        EXPLORER_WIN10,
        "-o",
        dir.path().to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("already exists"), "{}", r.stdout);
    let file = dir.path().join("keep");
    let r = run(&[
        "parse-jump-lists",
        "-f",
        EXPLORER_WIN10,
        "-o",
        file.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("is a file, not a directory"),
        "{}",
        r.stdout
    );
}

const SHIMCACHE_DIR: &str = "test_files/shimcache";

/// The Windows 11 SYSTEM hive of `test_files/shimcache/` and its transaction logs, unpacked
/// where a collection has them.
fn system_hive() -> tempfile::TempDir {
    use std::io::Read as _;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("HOST/C/Windows/System32/config");
    std::fs::create_dir_all(&config).unwrap();
    for name in ["SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2"] {
        let gz = std::fs::File::open(repo(&format!("{SHIMCACHE_DIR}/{name}.gz"))).unwrap();
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_end(&mut bytes)
            .unwrap();
        std::fs::write(config.join(name), bytes).unwrap();
    }
    dir
}

#[test]
fn shimcache_summary_on_the_terminal() {
    let hive = system_hive();
    let r = run(&["parse-shimcache", "-d", hive.path().to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "SYSTEM hives: 1",
        "SYSTEM hives parsed: 1",
        "Dirty hives recovered with their transaction logs: 1",
        "Caches: 1 (Windows10C_11 1)",
        "Entries: 359 (executed 30, not executed 329, no execution flag 0)",
        "Duplicates (in an earlier control set): 0",
        "Recovered from slack: 0",
        "Last-modified times: 2021-05-20T08:51:57.791182Z - 2022-02-07T07:37:13.434150800Z",
        "Damaged entries: 0",
        "Findings: 27 (medium: 27)",
        r"  [MEDIUM] SHIMCACHE-SUSPICIOUS-PATH C:\Users\ANDREW~1\AppData\Local\Temp\DA15D340-2806-4EF5-BB3C-C787E4CD384B\dismhost.exe",
        "  … 17 more in the Findings column",
        "To save every entry, add -o <FILE>",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    assert!(!r.stdout.contains("were not applied"), "{}", r.stdout);

    // the hive as it is: dirty, its logs not applied (they don't change this cache)
    let r = run(&[
        "parse-shimcache",
        "-d",
        hive.path().to_str().unwrap(),
        "--no-logs",
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "Dirty hives recovered with their transaction logs: 0",
        "Dirty hives whose transaction logs were not applied (entries may be missing): 1",
        "Entries: 359 (executed 30",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
}

/// Changes one byte of a file in place.
fn flip_byte(path: &Path, at: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[at] ^= 0xFF;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn shimcache_hive_with_a_damaged_base_block_is_recovered_from_its_logs() {
    let hive = system_hive();
    let config = hive.path().join("HOST/C/Windows/System32/config");
    // no `regf` signature: the base block comes from the log with the latest entries
    flip_byte(&config.join("SYSTEM"), 0);
    let r = run(&["parse-shimcache", "-d", hive.path().to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    for line in [
        "SYSTEM hives parsed: 1",
        "Dirty hives recovered with their transaction logs: 1",
        "Entries: 359 (executed 30, not executed 329, no execution flag 0)",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn shimcache_logs_whose_entries_are_damaged_are_not_applied() {
    let hive = system_hive();
    let config = hive.path().join("HOST/C/Windows/System32/config");
    // a byte of each log's first entry: its hashes no longer match, so nothing can be applied
    for log in ["SYSTEM.LOG1", "SYSTEM.LOG2"] {
        flip_byte(&config.join(log), 512 + 100);
    }
    let r = run(&["parse-shimcache", "-d", hive.path().to_str().unwrap(), "-K"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    for line in [
        "Dirty hives recovered with their transaction logs: 0",
        "Dirty hives whose transaction logs were not applied (entries may be missing): 1",
        "Entries: 359",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn shimcache_csv_has_appcompatcacheparsers_columns() {
    let hive = system_hive();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("shimcache.csv");
    let r = run(&[
        "parse-shimcache",
        "-d",
        hive.path().to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let (header, rows) = csv_rows(&out);
    let ez_columns = [
        "ControlSet",
        "CacheEntryPosition",
        "Path",
        "LastModifiedTimeUTC",
        "Executed",
        "Duplicate",
        "SourceFile",
        "FromSlack",
    ];
    assert_eq!(&header[..8], ez_columns);
    assert_eq!(header.len(), 20);
    // every entry as Eric Zimmerman's AppCompatCacheParser writes it (its times to the second)
    let (_, ez) = csv_rows(&repo(&format!(
        "{SHIMCACHE_DIR}/AppCompatCacheParser_SYSTEM.csv"
    )));
    assert_eq!(rows.len(), 359);
    assert_eq!(rows.len(), ez.len());
    for (ours, theirs) in rows.iter().zip(&ez) {
        for column in ez_columns {
            let value = match column {
                "LastModifiedTimeUTC" => {
                    ours[column].get(..19).unwrap_or_default().replace('T', " ")
                }
                "SourceFile" => {
                    assert!(ours[column].ends_with("SYSTEM"));
                    continue;
                }
                _ => ours[column].clone(),
            };
            assert_eq!(value, theirs[column], "{column}: {ours:?}");
        }
    }
    let first = &rows[0];
    for (column, value) in [
        ("CacheFormat", "Windows10C_11"),
        ("CacheLastWrittenUTC", "2022-02-07T07:37:59.317450900Z"),
        ("LastModifiedTimeUTC", "2022-02-07T07:37:13.434150800Z"),
        ("DataSize", "72"),
        ("Machine", "x64"),
        ("InsertFlags", ""),
        ("Findings", ""),
    ] {
        assert_eq!(first[column], value, "{column}");
    }
    let flagged: Vec<_> = rows
        .iter()
        .filter(|r| r["Findings"] == "SHIMCACHE-SUSPICIOUS-PATH")
        .collect();
    assert_eq!(flagged.len(), 27);
}

#[test]
fn shimcache_values_as_json() {
    // AppCompatCache values saved on their own: Windows XP, 7 (32-bit), 8.0 and 11
    let r = run(&[
        "parse-shimcache",
        "-f",
        &format!("{SHIMCACHE_DIR}/WinXPx86.bin"),
        "-t",
        "jsonl",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.stdout.contains("Results Summary"));
    let entries: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.len(), 17);
    let xp = &entries[0];
    assert_eq!(xp["cache_format"], "WindowsXP");
    assert_eq!(xp["control_set"], Value::Null);
    assert_eq!(xp["path"], r"C:\WINDOWS\system32\wscntfy.exe");
    assert_eq!(xp["last_modified"], "2008-04-14T12:00:00Z");
    assert_eq!(xp["executed"], Value::Null);
    assert_eq!(xp["file_size"], 13824);
    assert_eq!(xp["last_update"], "2016-01-13T22:20:03.265625Z");

    for (file, count, executed, format, path) in [
        (
            "win7x86.bin",
            91,
            75,
            "Windows7x86",
            r"C:\Windows\system32\LogonUI.exe",
        ),
        (
            "Win80.bin",
            104,
            88,
            "Windows80_Windows2012",
            r"SYSVOL\Windows\System32\LogonUI.exe",
        ),
        (
            "win11shim.raw",
            2,
            0,
            "Windows10C_11",
            r"C:\WINDOWS\system32\wbem\WmiApSrv.exe",
        ),
    ] {
        let r = run(&[
            "parse-shimcache",
            "-f",
            &format!("{SHIMCACHE_DIR}/{file}"),
            "-t",
            "json",
        ]);
        assert_eq!(r.code, 0, "{}", r.stderr);
        let entries = json_documents(&r.stdout);
        assert_eq!(entries.len(), count, "{file}");
        let ran = entries.iter().filter(|e| e["executed"] == true).count();
        assert_eq!(ran, executed, "{file}");
        assert_eq!(entries[0]["cache_format"], format, "{file}");
        assert_eq!(entries[0]["path"], path, "{file}");
    }
    let r = run(&[
        "parse-shimcache",
        "-f",
        &format!("{SHIMCACHE_DIR}/win11shim.raw"),
        "-t",
        "jsonl",
    ]);
    let w11: Value = serde_json::from_str(r.stdout.lines().next().unwrap()).unwrap();
    assert_eq!(w11["executed"], false);
    assert_eq!(w11["machine"], "x64");
    assert_eq!(w11["data_size"], 136);
    assert_eq!(w11["last_modified"], "2022-06-18T22:26:50.670515700Z");

    // the summary of a value
    let r = run(&[
        "parse-shimcache",
        "-f",
        &format!("{SHIMCACHE_DIR}/WinXPx86.bin"),
        "-K",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for line in [
        "AppCompatCache values parsed: 1",
        "Caches: 1 (WindowsXP 1)",
        "Entries: 17 (executed 0, not executed 0, no execution flag 17)",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    assert!(!r.stdout.contains("SYSTEM hives parsed"), "{}", r.stdout);
}

#[test]
fn shimcache_input_and_output_errors() {
    let r = run(&[
        "parse-shimcache",
        "-f",
        "test_files/shimcache/missing",
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("The file does not exist"), "{}", r.stdout);

    let r = run(&["parse-shimcache", "-f", "test_files/lnk/README.md", "-K"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("Could not parse")
            && r.stdout
                .contains("neither a registry hive nor an AppCompatCache value"),
        "{}",
        r.stdout
    );

    let r = run(&["parse-shimcache", "-d", "test_files/lnk", "-K"]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("No SYSTEM hives"), "{}", r.stdout);

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("keep.csv");
    std::fs::write(&file, b"keep").unwrap();
    let value = format!("{SHIMCACHE_DIR}/win7x86.bin");
    let r = run(&[
        "parse-shimcache",
        "-f",
        &value,
        "-o",
        file.to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("already exists"), "{}", r.stdout);
    let r = run(&[
        "parse-shimcache",
        "-f",
        &value,
        "-o",
        dir.path().to_str().unwrap(),
        "-K",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("is a directory"), "{}", r.stdout);
}
