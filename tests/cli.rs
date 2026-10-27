//! End-to-end tests: run the built binary against the test hives in `test_files/amcache/`.
//!
//! The expected counts are those of ys-amcache-parser's `amcache4n6`, which was cross-validated
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

/// (EntryId, FullPath) of every CSV row (paths use `/` on every OS).
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
    let text = std::fs::read_to_string(&csv_path).unwrap();
    assert!(text.starts_with(
        "Signature,EntryId,Sequence,BaseEntryId,BaseEntrySequence,HardLinkCount,Flags,"
    ));
    let paths = full_paths(&text);
    assert_eq!(paths.len(), 1016);
    for (id, path) in [("0", "$MFT"), ("5", "."), ("30", "WINDOWS/system32/config")] {
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
    assert!(docs[0]["attributes"].as_array().unwrap().len() > 2);

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
        r.stdout.contains("Resident streams extracted: 48"),
        "{}",
        r.stdout
    );
    for name in ["HOST1_C__MFT", "HOST2__MFT"] {
        let text = std::fs::read_to_string(csv_dir.join(format!("{name}.csv"))).unwrap();
        assert_eq!(full_paths(&text).len(), 1016, "{name}");
        assert_eq!(
            std::fs::read_dir(streams.join(name)).unwrap().count(),
            24,
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
