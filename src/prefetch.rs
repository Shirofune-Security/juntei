//! `parse-prefetch`: Windows Prefetch parsing with Yamato Security's ys-prefetch-parser (a fork of
//! Samuel Garcés Marín's frnsc-prefetch that matches libscca and does not crash on damaged files):
//! one record per prefetch file, or per execution with `-T`, as CSV, JSON or JSONL, with
//! Hayabusa's input options, progress bar and results summary. The findings follow
//! prefetch-forensic's audit: a Windows system binary loaded from outside `System32`, and an
//! executable run from a staging directory.

use crate::cli::{PrefetchOptions, PrefetchOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use chrono::{DateTime, SecondsFormat, Utc};
use frnsc_prefetch::prelude::{PrefetchFile, read_prefetch_bytes};
use indicatif::ProgressBar;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Parse errors printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// High findings listed in the summary; the rest (and every medium finding, which installers in
/// Temp and ProgramData raise often) are only counted.
const MAX_PRINTED_FINDINGS: usize = 20;
/// Larger files are not prefetch files (the parser's own limit).
const MAX_PREFETCH_SIZE: u64 = 64 * 1024 * 1024;
/// Prefetch keeps the last eight run times.
const RUN_TIMES: usize = 8;

/// Run the command; returns the exit status.
pub fn run(opts: &PrefetchOptions) -> i32 {
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
            let found = find_prefetch_files(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!("No prefetch files (*.pf) were found in {}", d.display()),
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
        p_label(no_color, "Prefetch files: ", &fmt_num(files.len()));
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
        match parse_file(path) {
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
        && let Err(e) = write_records(sink, opts.output_type(), opts.timeline, &parsed)
    {
        report_error(None, &format!("Could not write the records: {e}"));
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
                "To save every record, add -o <FILE> (-t csv, json or jsonl; -T for one record per execution).",
                true,
            );
        }
    }
    i32::from(parsed.is_empty())
}

/// One parsed prefetch file.
struct Parsed {
    source: String,
    pf: PrefetchFile,
    findings: Vec<Finding>,
}

fn parse_file(path: &Path) -> Result<Parsed, String> {
    let size = path.metadata().map_err(|e| e.to_string())?.len();
    if size > MAX_PREFETCH_SIZE {
        return Err(format!(
            "{} is too large to be a prefetch file",
            util::size_display(size)
        ));
    }
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string());
    let mut pf = read_prefetch_bytes(name.as_deref().unwrap_or_default(), &data)
        .map_err(|e| e.to_string())?;
    // The block traces are not written; they are the bulk of the parsed data.
    for metric in &mut pf.metrics {
        metric.traces = Vec::new();
    }
    let findings = findings(&pf);
    Ok(Parsed {
        source: path.to_string_lossy().to_string(),
        pf,
        findings,
    })
}

/// A triage observation about one prefetch file.
struct Finding {
    /// `high` or `medium`
    severity: &'static str,
    code: &'static str,
    mitre: &'static str,
    description: String,
}

/// prefetch-forensic's two high-precision checks on the executable's own path.
fn findings(pf: &PrefetchFile) -> Vec<Finding> {
    let mut out = Vec::new();
    let path = pf.executable_path();
    if path == pf.name {
        // the path of the executable is not among the loaded files
        return out;
    }
    let upper = path.to_ascii_uppercase();
    let in_system32 = upper.contains(r"\SYSTEM32\") || upper.contains(r"\SYSWOW64\");
    if forensicnomicon::processes::is_system32_binary(&pf.name) && !in_system32 {
        out.push(Finding {
            severity: "high",
            code: "SystemBinaryRelocated",
            mitre: "T1036.005",
            description: format!(
                "{} is a Windows system binary but was loaded from {path} (masquerading?)",
                pf.name
            ),
        });
    }
    if forensicnomicon::heuristics::paths::is_suspicious_exec_path(path) {
        out.push(Finding {
            severity: "medium",
            code: "SuspiciousExecutionPath",
            mitre: "T1204",
            description: format!(
                "{} was run from {path}, a directory commonly used to stage malware",
                pf.name
            ),
        });
    }
    out
}

/// A FILETIME as an RFC 3339 UTC time, like the timestamps of `parse-mft`; empty when it is 0.
fn filetime(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .map(|t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .unwrap_or_default()
}

/// The Windows versions that write a prefetch format version.
fn windows_version(version: u32) -> &'static str {
    match version {
        17 => "Windows XP/2003",
        23 => "Windows Vista/7",
        26 => "Windows 8/8.1",
        30 => "Windows 10/11",
        31 => "Windows 11",
        _ => "unknown",
    }
}

fn run_times(pf: &PrefetchFile) -> Vec<u64> {
    pf.last_run_times.iter().map(|t| t.filetime()).collect()
}

const CSV_HEADER: &[&str] = &[
    "SourceFile",
    "ExecutableName",
    "ExecutablePath",
    "PrefetchHash",
    "FormatVersion",
    "RunCount",
    "LastRun",
    "PreviousRun1",
    "PreviousRun2",
    "PreviousRun3",
    "PreviousRun4",
    "PreviousRun5",
    "PreviousRun6",
    "PreviousRun7",
    "VolumeCount",
    "VolumeDevicePaths",
    "VolumeSerialNumbers",
    "VolumeCreated",
    "DirectoryCount",
    "FileCount",
    "Findings",
    "Files",
    "Directories",
];

const TIMELINE_CSV_HEADER: &[&str] = &[
    "RunTime",
    "ExecutableName",
    "ExecutablePath",
    "PrefetchHash",
    "RunCount",
    "SourceFile",
];

/// One CSV row per prefetch file, in the order of [`CSV_HEADER`]. Lists are joined with `, `.
fn csv_row(r: &Parsed) -> Vec<String> {
    let pf = &r.pf;
    let mut times: Vec<String> = run_times(pf).into_iter().map(filetime).collect();
    times.resize(RUN_TIMES, String::new());
    let join = |items: Vec<String>| items.join(", ");
    let directories: Vec<String> = pf
        .volume
        .iter()
        .flat_map(|v| v.directory_strings.iter().cloned())
        .collect();
    let mut row = vec![
        r.source.clone(),
        pf.name.clone(),
        pf.executable_path().to_string(),
        format!("{:08X}", pf.hash),
        pf.version.to_string(),
        pf.run_count.to_string(),
    ];
    row.extend(times);
    row.extend([
        pf.volume.len().to_string(),
        join(pf.volume.iter().map(|v| v.device_path.clone()).collect()),
        join(
            pf.volume
                .iter()
                .map(|v| format!("{:08X}", v.serial_number))
                .collect(),
        ),
        join(
            pf.volume
                .iter()
                .map(|v| filetime(v.creation_time))
                .collect(),
        ),
        directories.len().to_string(),
        pf.metrics.len().to_string(),
        join(r.findings.iter().map(|f| f.code.to_string()).collect()),
        join(pf.metrics.iter().map(|m| m.file.clone()).collect()),
        join(directories),
    ]);
    row
}

/// Every field of one prefetch file except the block traces.
fn json_record(r: &Parsed) -> Value {
    let pf = &r.pf;
    let reference = |f: &frnsc_prefetch::common::NtfsFile| json!({"mft_entry": f.mft_entry, "sequence": f.seq_number});
    json!({
        "source_file": r.source,
        "executable_name": pf.name,
        "executable_path": pf.executable_path(),
        "prefetch_hash": format!("{:08X}", pf.hash),
        "format_version": pf.version,
        "windows_version": windows_version(pf.version),
        "file_size": pf.file_size,
        "run_count": pf.run_count,
        "last_run_times": run_times(pf).into_iter().map(filetime).collect::<Vec<_>>(),
        "volumes": pf.volume.iter().map(|v| json!({
            "device_path": v.device_path,
            "serial_number": format!("{:08X}", v.serial_number),
            "creation_time": filetime(v.creation_time),
            "directories": v.directory_strings,
            "file_references": v.file_references.iter().map(reference).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "files": pf.metrics.iter().map(|m| {
            let mut file = json!({"path": m.file});
            if let Some(f) = &m.file_reference {
                file["mft_entry"] = json!(f.mft_entry);
                file["sequence"] = json!(f.seq_number);
            }
            file
        }).collect::<Vec<_>>(),
        "findings": r.findings.iter().map(|f| json!({
            "severity": f.severity,
            "code": f.code,
            "mitre": f.mitre,
            "description": f.description,
        })).collect::<Vec<_>>(),
    })
}

/// Every execution: (run time, record), sorted by time and then by source file.
fn timeline(parsed: &[Parsed]) -> Vec<(u64, &Parsed)> {
    let mut runs: Vec<(u64, &Parsed)> = parsed
        .iter()
        .flat_map(|r| run_times(&r.pf).into_iter().map(move |t| (t, r)))
        .collect();
    runs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.source.cmp(&b.1.source)));
    runs
}

fn timeline_csv_row(time: u64, r: &Parsed) -> Vec<String> {
    vec![
        filetime(time),
        r.pf.name.clone(),
        r.pf.executable_path().to_string(),
        format!("{:08X}", r.pf.hash),
        r.pf.run_count.to_string(),
        r.source.clone(),
    ]
}

fn timeline_json_record(time: u64, r: &Parsed) -> Value {
    json!({
        "run_time": filetime(time),
        "executable_name": r.pf.name,
        "executable_path": r.pf.executable_path(),
        "prefetch_hash": format!("{:08X}", r.pf.hash),
        "run_count": r.pf.run_count,
        "source_file": r.source,
    })
}

fn write_records(
    mut w: Box<dyn Write>,
    output_type: PrefetchOutputType,
    timeline_mode: bool,
    parsed: &[Parsed],
) -> io::Result<()> {
    if output_type == PrefetchOutputType::Csv {
        let mut csv = csv::Writer::from_writer(w);
        if timeline_mode {
            csv.write_record(TIMELINE_CSV_HEADER)?;
            for (t, r) in timeline(parsed) {
                csv.write_record(timeline_csv_row(t, r))?;
            }
        } else {
            csv.write_record(CSV_HEADER)?;
            for r in parsed {
                csv.write_record(csv_row(r))?;
            }
        }
        return csv.flush();
    }
    let values: Vec<Value> = if timeline_mode {
        timeline(parsed)
            .into_iter()
            .map(|(t, r)| timeline_json_record(t, r))
            .collect()
    } else {
        parsed.iter().map(json_record).collect()
    };
    for v in values {
        // JSON: pretty objects separated by newlines, like parse-mft; JSONL: one per line
        if output_type == PrefetchOutputType::Json {
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
    let mut count = fmt_num(parsed.len());
    if failed > 0 {
        count.push_str(&format!(" (could not parse: {})", fmt_num(failed)));
    }
    p_label(no_color, "Prefetch files parsed: ", &count);
    let mut versions: BTreeMap<u32, usize> = BTreeMap::new();
    for r in parsed {
        *versions.entry(r.pf.version).or_default() += 1;
    }
    let versions: Vec<String> = versions
        .iter()
        .rev()
        .map(|(v, n)| format!("{v} ({}) {}", windows_version(*v), fmt_num(*n)))
        .collect();
    p_label(no_color, "Format versions: ", &versions.join(", "));
    let executables: BTreeSet<&str> = parsed.iter().map(|r| r.pf.name.as_str()).collect();
    p_label(no_color, "Executables: ", &fmt_num(executables.len()));
    let executions: u64 = parsed.iter().map(|r| u64::from(r.pf.run_count)).sum();
    p_label(
        no_color,
        "Executions (run counts): ",
        &fmt_num(executions as usize),
    );
    let times: Vec<u64> = parsed.iter().flat_map(|r| run_times(&r.pf)).collect();
    if let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) {
        p_label(
            no_color,
            "Run times recorded: ",
            &format!(
                "{} ({} - {})",
                fmt_num(times.len()),
                filetime(*first),
                filetime(*last)
            ),
        );
    }

    let findings: Vec<(&Parsed, &Finding)> = parsed
        .iter()
        .flat_map(|r| r.findings.iter().map(move |f| (r, f)))
        .collect();
    p(JunteiColor::Green.rdg(no_color), "Findings: ", false);
    p(None, &fmt_num(findings.len()), false);
    let mut first = true;
    for severity in ["high", "medium"] {
        let n = findings
            .iter()
            .filter(|(_, f)| f.severity == severity)
            .count();
        if n == 0 {
            continue;
        }
        p(None, if first { " (" } else { ", " }, false);
        first = false;
        p(
            JunteiColor::for_severity(severity).and_then(|c| c.rdg(no_color)),
            &format!("{severity}: {}", fmt_num(n)),
            false,
        );
    }
    p(None, if first { "" } else { ")" }, true);
    let high: Vec<_> = findings
        .iter()
        .filter(|(_, f)| f.severity == "high")
        .collect();
    for (r, f) in high.iter().take(MAX_PRINTED_FINDINGS) {
        p(None, "  ", false);
        p(
            JunteiColor::for_severity(f.severity).and_then(|c| c.rdg(no_color)),
            &format!("[{}]", f.severity.to_ascii_uppercase()),
            false,
        );
        p(
            None,
            &format!(" {} ({}) - {}", f.description, f.mitre, r.source),
            true,
        );
    }
    if high.len() > MAX_PRINTED_FINDINGS {
        p(
            None,
            &format!(
                "  ... {} more (saved with -o)",
                fmt_num(high.len() - MAX_PRINTED_FINDINGS)
            ),
            true,
        );
    }
    p(None, "", true);
}

/// Whether a file name is a prefetch file: `*.pf`.
pub fn is_prefetch_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".pf")
}

/// The prefetch files under `dir`, recursively, in path order.
pub fn find_prefetch_files(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_prefetch_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_names() {
        assert!(is_prefetch_name("CMD.EXE-087B4001.pf"));
        assert!(is_prefetch_name("cmd.exe-087b4001.PF"));
        assert!(!is_prefetch_name("Layout.ini"));
        assert!(!is_prefetch_name("Ag.db"));
    }

    #[test]
    fn filetimes_are_rfc3339_utc() {
        assert_eq!(filetime(0), "");
        assert_eq!(filetime(116_444_736_000_000_000), "1970-01-01T00:00:00Z");
        assert_eq!(
            filetime(133_515_874_611_440_142),
            "2024-02-05T06:17:41.144014200Z"
        );
        // every u64 is within chrono's range: a garbage time is still written as a time
        assert!(filetime(u64::MAX).contains("60056-"));
    }
}
