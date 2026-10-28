//! `parse-shimcache`: the ShimCache (AppCompatCache) of `SYSTEM` hives with Yamato Security's
//! ys-shimcache-parser (a fork of shimcache-forensic that reads every format from Windows XP to
//! 11 as Eric Zimmerman's AppCompatCacheParser reads it): the hive's transaction logs replayed
//! when it is dirty, every control set's cache and the entries left in the slack of its value,
//! one record per entry with AppCompatCacheParser's CSV columns and more, or every field as JSON /
//! JSONL, with Hayabusa's input options, progress bar and results summary. The summary flags
//! system binaries outside `System32` and executables in staging directories.

use crate::cli::{ShimcacheOptions, ShimcacheOutputType};
use crate::color::JunteiColor;
use crate::lnk::filetime;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use forensicnomicon::report::Observation;
use indicatif::ProgressBar;
use serde_json::{Value, json};
use shimcache_forensic::{
    ControlSetCache, PackageRecord, Recovery, Row, ShimcacheAnomaly, ShimcacheEntry, SystemCaches,
    audit, decode, find_logs, read_system,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Parse errors printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// Findings listed in the summary.
const MAX_PRINTED_FINDINGS: usize = 10;
/// Larger files are not registry hives (Windows limits a hive to 2 GiB).
const MAX_HIVE_SIZE: u64 = 2 * 1024 * 1024 * 1024 + 4096;

/// Run the command; returns the exit status.
pub fn run(opts: &ShimcacheOptions) -> i32 {
    let no_color = opts.common.no_color;
    let data_on_stdout = opts.data_on_stdout();
    let report_error = |bar: Option<&ProgressBar>, msg: &str| {
        if data_on_stdout {
            eprintln!("{msg}");
        } else {
            progress::suspended(bar, || error_msg(no_color, msg));
        }
    };

    // --- inputs ---------------------------------------------------------------------------
    let files = match (&opts.filepath, &opts.directory) {
        (Some(f), _) => {
            if !f.is_file() {
                report_error(None, &format!("The file does not exist: {}", f.display()));
                return 1;
            }
            vec![f.clone()]
        }
        (None, Some(d)) => {
            if !d.is_dir() {
                report_error(
                    None,
                    &format!("The directory does not exist: {}", d.display()),
                );
                return 1;
            }
            let found = find_hives(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!("No SYSTEM hives were found in {}", d.display()),
                );
                return 1;
            }
            found
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, false, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }
    if !data_on_stdout {
        let total: u64 = files
            .iter()
            .map(|p| p.metadata().map_or(0, |m| m.len()))
            .sum();
        p_label(no_color, "SYSTEM hives: ", &fmt_num(files.len()));
        p_label(no_color, "Total file size: ", &util::size_display(total));
        p(None, "", true);
    }
    let bar = (!data_on_stdout).then(|| {
        p(
            JunteiColor::Orange.rdg(no_color),
            "Parsing in progress. Please wait.",
            true,
        );
        p(None, "", true);
        progress::progress_bar(files.len(), no_color)
    });

    // --- parse -----------------------------------------------------------------------------
    let mut parsed = Vec::new();
    let mut failed = 0usize;
    for path in &files {
        if let Some(b) = &bar {
            b.set_message(progress::message(path));
        }
        match parse_file(path, opts.no_logs) {
            Ok(record) => parsed.push(record),
            Err(e) => {
                failed += 1;
                if failed <= MAX_PRINTED_ERRORS {
                    report_error(
                        bar.as_ref(),
                        &format!("Could not parse {}: {e}", path.display()),
                    );
                }
            }
        }
        if let Some(b) = &bar {
            b.inc(1);
        }
    }
    if failed > MAX_PRINTED_ERRORS {
        report_error(
            bar.as_ref(),
            &format!(
                "{} more files could not be parsed",
                fmt_num(failed - MAX_PRINTED_ERRORS)
            ),
        );
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- write -----------------------------------------------------------------------------
    let sink: Option<Box<dyn Write>> = match (&opts.output, data_on_stdout) {
        (Some(path), _) => {
            if let Some(parent) = path.parent().filter(|d| !d.as_os_str().is_empty())
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                report_error(None, &format!("Could not create {}: {e}", parent.display()));
                return 1;
            }
            match File::create(path) {
                Ok(f) => Some(Box::new(BufWriter::new(f))),
                Err(e) => {
                    report_error(None, &format!("Could not create {}: {e}", path.display()));
                    return 1;
                }
            }
        }
        (None, true) => Some(Box::new(BufWriter::new(io::stdout()))),
        (None, false) => None,
    };
    if let Some(sink) = sink
        && let Err(e) = write_records(sink, opts.output_type(), &parsed)
    {
        report_error(None, &format!("Could not write the entries: {e}"));
        return 1;
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&parsed, failed, no_color);
        if let Some(out) = &opts.output {
            p_label(
                no_color,
                "Results saved: ",
                &format!("{} ({})", out.display(), util::file_size_display(out)),
            );
        } else {
            p(
                None,
                "To save every entry, add -o <FILE> (-t csv, json or jsonl).",
                true,
            );
        }
    }
    i32::from(parsed.is_empty())
}

/// One parsed file: a `SYSTEM` hive, or an AppCompatCache value saved on its own.
struct Parsed {
    source: String,
    /// A value file, not a hive: one cache, no control set.
    is_value: bool,
    caches: SystemCaches,
}

fn parse_file(path: &Path, no_logs: bool) -> Result<Parsed, String> {
    let size = path.metadata().map_err(|e| e.to_string())?.len();
    if size > MAX_HIVE_SIZE {
        return Err(format!("too large for a registry hive ({size} bytes)"));
    }
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let source = path.to_string_lossy().to_string();
    let logs = if no_logs { Vec::new() } else { find_logs(path) };
    // A hive, or one whose base block is damaged (no `regf`) but has transaction logs: they
    // give it a base block. Otherwise, an AppCompatCache value on its own.
    let mut hive_error = None;
    if data.starts_with(b"regf") || !logs.is_empty() {
        match read_system(data.clone(), &logs) {
            Ok(caches) => {
                return Ok(Parsed {
                    source,
                    is_value: false,
                    caches,
                });
            }
            Err(e) if data.starts_with(b"regf") => return Err(e.to_string()),
            Err(e) => hive_error = Some(e.to_string()),
        }
    }
    // the AppCompatCache value's bytes (exported from the registry, or carved)
    let cache = decode(&data, None).map_err(|e| match &hive_error {
        Some(h) => format!("neither a registry hive ({h}) nor an AppCompatCache value ({e})"),
        None => format!("neither a registry hive nor an AppCompatCache value ({e})"),
    })?;
    Ok(Parsed {
        source,
        is_value: true,
        caches: SystemCaches {
            recovery: Recovery::default(),
            current_control_set: None,
            is_32bit: None,
            control_sets: vec![ControlSetCache {
                control_set: 0,
                key_path: String::new(),
                key_last_written: 0,
                cache: Some(cache),
                error: None,
                slack: Vec::new(),
            }],
        },
    })
}

/// One entry to write, with what it was read from.
struct Record<'a> {
    file: &'a Parsed,
    set: &'a ControlSetCache,
    row: Row<'a>,
    findings: Vec<ShimcacheAnomaly>,
}

impl Record<'_> {
    fn entry(&self) -> &ShimcacheEntry {
        self.row.entry
    }

    /// The control set, unless the entry comes from a value file.
    fn control_set(&self) -> Option<u32> {
        (!self.file.is_value).then_some(self.row.control_set)
    }

    fn format(&self) -> &'static str {
        self.set.cache.as_ref().map_or("", |c| c.format.name())
    }
}

/// Every entry of every file: each control set's cache, then its slack (AppCompatCacheParser's
/// order).
fn records(parsed: &[Parsed]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    for file in parsed {
        for row in file.caches.rows() {
            let Some(set) = file
                .caches
                .control_sets
                .iter()
                .find(|s| s.control_set == row.control_set)
            else {
                continue;
            };
            let findings = audit(std::slice::from_ref(row.entry));
            out.push(Record {
                file,
                set,
                row,
                findings,
            });
        }
    }
    out
}

/// A PE machine type as a name.
fn machine_name(machine: u16) -> String {
    match machine {
        0x14c => "x86".into(),
        0x8664 => "x64".into(),
        0xaa64 => "ARM64".into(),
        0x1c4 => "ARM".into(),
        0x200 => "IA64".into(),
        other => format!("0x{other:04x}"),
    }
}

fn executed(e: &ShimcacheEntry) -> &'static str {
    match e.executed {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "NA",
    }
}

fn hex32(v: Option<u32>) -> String {
    v.map_or_else(String::new, |v| format!("0x{v:08x}"))
}

fn finding_codes(findings: &[ShimcacheAnomaly]) -> String {
    findings
        .iter()
        .map(|f| f.code())
        .collect::<Vec<_>>()
        .join("|")
}

/// AppCompatCacheParser's columns, in its order, then the fields it doesn't write.
const CSV_HEADER: &[&str] = &[
    "ControlSet",
    "CacheEntryPosition",
    "Path",
    "LastModifiedTimeUTC",
    "Executed",
    "Duplicate",
    "SourceFile",
    "FromSlack",
    "CacheFormat",
    "CacheLastWrittenUTC",
    "InsertFlags",
    "ShimFlags",
    "DataSize",
    "Machine",
    "FileSize",
    "LastUpdateTimeUTC",
    "PackageName",
    "PackageVersion",
    "PackagePublisherId",
    "Findings",
];

fn csv_row(r: &Record) -> Vec<String> {
    let e = r.entry();
    let package = e.package_record();
    let bool_text = |b: bool| if b { "True" } else { "False" }.to_owned();
    vec![
        r.control_set().map_or_else(String::new, |n| n.to_string()),
        e.position.to_string(),
        e.path.clone(),
        e.last_modified().map_or_else(String::new, filetime),
        executed(e).to_owned(),
        bool_text(r.row.duplicate),
        r.file.source.clone(),
        bool_text(e.from_slack),
        r.format().to_owned(),
        filetime(r.set.key_last_written),
        hex32(e.insert_flags),
        hex32(e.shim_flags),
        e.data.len().to_string(),
        e.machine().map_or_else(String::new, machine_name),
        e.file_size.map_or_else(String::new, |s| s.to_string()),
        e.last_update().map_or_else(String::new, filetime),
        package
            .as_ref()
            .map_or_else(|| e.package.clone(), |p| p.name.to_owned()),
        package
            .as_ref()
            .and_then(|p| PackageRecord::dotted(p.version))
            .unwrap_or_default(),
        package
            .as_ref()
            .map_or_else(String::new, |p| p.publisher_id.to_owned()),
        finding_codes(&r.findings),
    ]
}

fn json_record(r: &Record) -> Value {
    let e = r.entry();
    let time = |t: Option<u64>| t.map_or(Value::Null, |t| json!(filetime(t)));
    let tags: Vec<Value> = e
        .data_tags()
        .iter()
        .map(|(tag, value)| json!({"tag": format!("0x{tag:x}"), "value": hex(value)}))
        .collect();
    let findings: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            json!({
                "code": f.code(),
                "severity": f.severity().map_or_else(|| "INFO".to_owned(), |s| s.to_string()),
                "note": f.note(),
            })
        })
        .collect();
    let package = e.package_record().map(|p| {
        json!({
            "name": p.name,
            "version": PackageRecord::dotted(p.version),
            "sdk_version": PackageRecord::dotted(p.sdk_version),
            "architecture": p.architecture,
            "publisher_id": p.publisher_id,
            "neutral": p.neutral,
            "flags": p.flags,
        })
    });
    json!({
        "source_file": r.file.source,
        "control_set": r.control_set(),
        "cache_format": r.format(),
        "cache_last_written": time(Some(r.set.key_last_written).filter(|&t| t != 0)),
        "position": e.position,
        "path": e.path,
        "last_modified": time(e.last_modified()),
        "last_modified_filetime": e.last_modified_filetime,
        "executed": e.executed,
        "duplicate": r.row.duplicate,
        "from_slack": e.from_slack,
        "insert_flags": e.insert_flags,
        "shim_flags": e.shim_flags,
        "file_size": e.file_size,
        "last_update": time(e.last_update()),
        "package": package,
        "package_data": (!e.package.is_empty()).then(|| e.package.clone()),
        "machine": e.machine().map(machine_name),
        "data_size": e.data.len(),
        "data_tags": tags,
        "data": hex(&e.data),
        "findings": findings,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_records(
    mut w: Box<dyn Write>,
    output_type: ShimcacheOutputType,
    parsed: &[Parsed],
) -> io::Result<()> {
    let records = records(parsed);
    if output_type == ShimcacheOutputType::Csv {
        let mut csv = csv::Writer::from_writer(w);
        csv.write_record(CSV_HEADER)?;
        for r in &records {
            csv.write_record(csv_row(r))?;
        }
        return csv.flush();
    }
    for r in &records {
        let v = json_record(r);
        // JSON: pretty objects separated by newlines, like parse-mft; JSONL: one per line
        if output_type == ShimcacheOutputType::Json {
            serde_json::to_writer_pretty(&mut w, &v)?;
        } else {
            serde_json::to_writer(&mut w, &v)?;
        }
        w.write_all(b"\n")?;
    }
    w.flush()
}

fn print_summary(parsed: &[Parsed], failed: usize, no_color: bool) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    let hives = parsed.iter().filter(|f| !f.is_value).count();
    let values = parsed.len() - hives;
    if hives > 0 || values == 0 {
        p_label(no_color, "SYSTEM hives parsed: ", &fmt_num(hives));
    }
    if values > 0 {
        p_label(no_color, "AppCompatCache values parsed: ", &fmt_num(values));
    }
    if failed > 0 {
        p_label(no_color, "Could not parse: ", &fmt_num(failed));
    }
    let recovered = parsed
        .iter()
        .filter(|f| f.caches.recovery.recovered)
        .count();
    let dirty: Vec<&Parsed> = parsed
        .iter()
        .filter(|f| f.caches.recovery.dirty && !f.caches.recovery.recovered)
        .collect();
    if hives > 0 {
        p_label(
            no_color,
            "Dirty hives recovered with their transaction logs: ",
            &fmt_num(recovered),
        );
    }
    if !dirty.is_empty() {
        p_label(
            no_color,
            "Dirty hives whose transaction logs were not applied (entries may be missing): ",
            &fmt_num(dirty.len()),
        );
        for f in dirty.iter().take(MAX_PRINTED_FINDINGS) {
            p(None, &format!("  {}", f.source), true);
        }
    }
    let mut formats: BTreeMap<&str, usize> = BTreeMap::new();
    let mut without_cache = 0usize;
    let mut problems = 0usize;
    for f in parsed {
        for set in &f.caches.control_sets {
            match &set.cache {
                Some(c) => {
                    *formats.entry(c.format.name()).or_default() += 1;
                    problems += c.problems.len();
                }
                None => without_cache += 1,
            }
        }
    }
    let sets = formats.values().sum::<usize>();
    let mut caches = fmt_num(sets);
    if sets > 0 {
        let list: Vec<String> = formats
            .iter()
            .map(|(name, n)| format!("{name} {}", fmt_num(*n)))
            .collect();
        caches.push_str(&format!(" ({})", list.join(", ")));
    }
    if without_cache > 0 {
        caches.push_str(&format!(
            "; control sets without one: {}",
            fmt_num(without_cache)
        ));
    }
    p_label(no_color, "Caches: ", &caches);
    let records = records(parsed);
    let flag = |x: Option<bool>| records.iter().filter(|r| r.entry().executed == x).count();
    p_label(
        no_color,
        "Entries: ",
        &format!(
            "{} (executed {}, not executed {}, no execution flag {})",
            fmt_num(records.len()),
            fmt_num(flag(Some(true))),
            fmt_num(flag(Some(false))),
            fmt_num(flag(None))
        ),
    );
    p_label(
        no_color,
        "Duplicates (in an earlier control set): ",
        &fmt_num(records.iter().filter(|r| r.row.duplicate).count()),
    );
    p_label(
        no_color,
        "Recovered from slack: ",
        &fmt_num(records.iter().filter(|r| r.entry().from_slack).count()),
    );
    let times: Vec<u64> = records
        .iter()
        .filter_map(|r| r.entry().last_modified())
        .collect();
    if let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) {
        p_label(
            no_color,
            "Last-modified times: ",
            &format!("{} - {}", filetime(*first), filetime(*last)),
        );
    }
    p_label(no_color, "Damaged entries: ", &fmt_num(problems));

    // findings, once per entry (not again for its duplicates)
    let found: Vec<(&Record, &ShimcacheAnomaly)> = records
        .iter()
        .filter(|r| !r.row.duplicate)
        .flat_map(|r| r.findings.iter().map(move |f| (r, f)))
        .collect();
    let severity = |f: &ShimcacheAnomaly| {
        f.severity()
            .map_or_else(|| "INFO".to_owned(), |s| s.to_string())
    };
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for (_, f) in &found {
        *by_severity.entry(severity(f)).or_default() += 1;
    }
    p(JunteiColor::Green.rdg(no_color), "Findings: ", false);
    p(None, &fmt_num(found.len()), false);
    // most severe first, each in its color
    let mut first = true;
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let Some(n) = by_severity.get(level) else {
            continue;
        };
        p(None, if first { " (" } else { ", " }, false);
        first = false;
        p(
            JunteiColor::for_severity(level).and_then(|c| c.rdg(no_color)),
            &format!("{}: {}", level.to_ascii_lowercase(), fmt_num(*n)),
            false,
        );
    }
    p(None, if first { "" } else { ")" }, true);
    let mut shown = found.clone();
    // the most severe first (a stable sort keeps the cache's order within a severity)
    shown.sort_by_key(|(_, f)| {
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            .iter()
            .position(|l| *l == severity(f))
    });
    for (r, f) in shown.iter().take(MAX_PRINTED_FINDINGS) {
        let executed = match r.entry().executed {
            Some(true) => " (executed)",
            _ => "",
        };
        p(
            None,
            &format!(
                "  [{}] {} {}{executed}",
                severity(f),
                f.code(),
                r.entry().path
            ),
            true,
        );
    }
    if found.len() > MAX_PRINTED_FINDINGS {
        p(
            None,
            &format!(
                "  … {} more in the Findings column (-o <FILE>)",
                fmt_num(found.len() - MAX_PRINTED_FINDINGS)
            ),
            true,
        );
    }
    p(None, "", true);
}

/// Whether a file name is a `SYSTEM` hive's (in any case; its logs are not hives).
pub fn is_system_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("SYSTEM")
}

/// The `SYSTEM` hives under `dir`, recursively, in path order.
pub fn find_hives(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_system_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_hive_names() {
        assert!(is_system_name("SYSTEM"));
        assert!(is_system_name("system"));
        assert!(!is_system_name("SYSTEM.LOG1"));
        assert!(!is_system_name("SYSTEM.LOG"));
        assert!(!is_system_name("SOFTWARE"));
        assert!(!is_system_name("SYSTEM.sav"));
    }

    #[test]
    fn machine_names() {
        assert_eq!(machine_name(0x8664), "x64");
        assert_eq!(machine_name(0x14c), "x86");
        assert_eq!(machine_name(0xaa64), "ARM64");
        assert_eq!(machine_name(0x1234), "0x1234");
    }

    #[test]
    fn a_file_that_is_neither_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("SYSTEM");
        std::fs::write(&path, b"not a hive, not a cache").unwrap();
        let e = parse_file(&path, false).err().unwrap();
        assert!(e.starts_with("neither a registry hive"), "{e}");
    }
}
