//! `parse-amcache`: Amcache.hve parsing with Yamato Security's ys-amcache-parser library (the
//! parser and the text / JSON / JSONL / CSV writers of its `amcache4n6` command), with Hayabusa's
//! input options, progress bar and results summary around it.

use crate::cli::{AmcacheOptions, OutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, error_msg, fmt_num, p, p_label};
use amcache_forensic::output::{
    OutputOptions, write_csv_directory, write_json, write_jsonl, write_text,
};
use amcache_forensic::{AmcacheReport, AmcacheSchema, analyze_bytes};
use forensicnomicon::report::Observation;
use indicatif::ProgressBar;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Run the command; returns the exit status.
pub fn run(opts: &AmcacheOptions) -> i32 {
    let no_color = opts.common.no_color;
    let data_on_stdout = opts.data_on_stdout();
    let report_error = |bar: Option<&ProgressBar>, msg: &str| {
        if data_on_stdout {
            eprintln!("{msg}");
        } else {
            progress::suspended(bar, || error_msg(no_color, msg));
        }
    };
    let output_type = opts.output_type();
    if output_type == OutputType::Csv && opts.output.is_none() {
        report_error(
            None,
            "CSV output needs -o <DIR>: the summary, findings, files and devices are separate tables.",
        );
        return 1;
    }

    // --- inputs ---------------------------------------------------------------------------
    let (hives, root) = match (&opts.filepath, &opts.directory) {
        (Some(f), _) => {
            if !f.is_file() {
                report_error(None, &format!("The file does not exist: {}", f.display()));
                return 1;
            }
            (vec![f.clone()], None)
        }
        (None, Some(d)) => {
            if !d.is_dir() {
                report_error(
                    None,
                    &format!("The directory does not exist: {}", d.display()),
                );
                return 1;
            }
            let hives = find_hives(d);
            if hives.is_empty() {
                report_error(
                    None,
                    &format!(
                        "No Amcache hives (Amcache.hve) were found in {}",
                        d.display()
                    ),
                );
                return 1;
            }
            (hives, Some(d.as_path()))
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, output_type, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }

    if !data_on_stdout {
        let total: u64 = hives
            .iter()
            .filter_map(|h| h.metadata().ok())
            .map(|m| m.len())
            .sum();
        p_label(no_color, "Amcache hives: ", &fmt_num(hives.len()));
        p_label(no_color, "Total file size: ", &util::size_display(total));
        p(None, "", true);
    }

    // --- parse and write -------------------------------------------------------------------
    let (files, devices) = opts.records();
    let options = OutputOptions { files, devices };
    let bar = opts.output.is_some().then(|| {
        p(
            JunteiColor::Orange.rdg(no_color),
            "Parsing in progress. Please wait.",
            true,
        );
        p(None, "", true);
        progress::progress_bar(hives.len(), no_color)
    });
    let mut writer: Option<Box<dyn Write>> = match (&opts.output, output_type) {
        (_, OutputType::Csv) => None,
        (Some(out), _) => match File::create(out) {
            Ok(f) => Some(Box::new(BufWriter::new(f))),
            Err(e) => {
                report_error(None, &format!("Could not create {}: {e}", out.display()));
                return 1;
            }
        },
        (None, OutputType::Text) => None,
        (None, _) => Some(Box::new(BufWriter::new(io::stdout()))),
    };
    let mut totals = Totals::default();
    let mut used_dirs = HashSet::new();
    let mut saved: Vec<PathBuf> = Vec::new();
    for (i, hive) in hives.iter().enumerate() {
        if let Some(b) = &bar {
            b.set_message(progress::message(hive));
        }
        let source = hive.to_string_lossy().to_string();
        let report = match std::fs::read(hive)
            .map_err(|e| e.to_string())
            .and_then(|bytes| analyze_bytes(&bytes).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                totals.failed += 1;
                report_error(bar.as_ref(), &format!("Could not parse {source}: {e}"));
                if let Some(b) = &bar {
                    b.inc(1);
                }
                continue;
            }
        };
        totals.add(&report);
        let written = match (output_type, &mut writer) {
            (OutputType::Csv, _) => {
                let out = opts.output.as_deref().unwrap_or(Path::new("."));
                let dir = match root {
                    Some(root) => out.join(util::unique_name(root, hive, &mut used_dirs)),
                    None => out.to_path_buf(),
                };
                write_csv_directory(&dir, &source, &report, options).map(|mut paths| {
                    saved.append(&mut paths);
                })
            }
            (OutputType::Json, Some(w)) => write_json(w, &source, &report, options),
            (OutputType::Jsonl, Some(w)) => write_jsonl(w, &source, &report, options),
            (OutputType::Text, Some(w)) => {
                let header = if i == 0 {
                    format!("Amcache hive: {source}")
                } else {
                    format!("\nAmcache hive: {source}")
                };
                writeln!(w, "{header}")
                    .map_err(Into::into)
                    .and_then(|()| write_text(&mut *w, &report, options))
            }
            (_, None) => {
                // the text report on the terminal
                p_label(no_color, "Amcache hive: ", &source);
                let mut out = io::stdout().lock();
                let res = write_text(&mut out, &report, options);
                out.flush().ok();
                p(None, "", true);
                res
            }
        };
        if let Err(e) = written {
            report_error(
                bar.as_ref(),
                &format!("Could not write the results of {source}: {e}"),
            );
            return 1;
        }
        if let Some(b) = &bar {
            b.inc(1);
        }
    }
    if let Some(w) = &mut writer
        && let Err(e) = w.flush()
    {
        report_error(bar.as_ref(), &format!("Could not write the results: {e}"));
        return 1;
    }
    drop(writer);
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&totals, no_color);
        if let Some(out) = &opts.output {
            if output_type == OutputType::Csv {
                p_label(
                    no_color,
                    "Results saved: ",
                    &format!("{} ({} CSV files)", out.display(), fmt_num(saved.len())),
                );
            } else {
                p_label(
                    no_color,
                    "Results saved: ",
                    &format!("{} ({})", out.display(), util::file_size_display(out)),
                );
            }
        }
    }
    i32::from(totals.parsed == 0)
}

/// Counts for the results summary.
#[derive(Default)]
struct Totals {
    parsed: usize,
    failed: usize,
    modern: usize,
    legacy: usize,
    files: usize,
    devices: usize,
    /// severity (`HIGH`, `MEDIUM`, …) → findings
    findings: BTreeMap<String, usize>,
}

impl Totals {
    fn add(&mut self, report: &AmcacheReport) {
        self.parsed += 1;
        match report.amcache.schema {
            AmcacheSchema::Modern => self.modern += 1,
            AmcacheSchema::Legacy => self.legacy += 1,
        }
        self.files += report.amcache.file_entries.len();
        self.devices += report.amcache.device_entries.len();
        for anomaly in &report.anomalies {
            let severity = anomaly
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| s.to_string());
            *self.findings.entry(severity).or_default() += 1;
        }
    }

    fn finding_count(&self) -> usize {
        self.findings.values().sum()
    }
}

fn print_summary(t: &Totals, no_color: bool) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    let mut parsed = fmt_num(t.parsed);
    if t.failed > 0 {
        parsed.push_str(&format!(" (could not parse: {})", fmt_num(t.failed)));
    }
    p_label(no_color, "Amcache hives parsed: ", &parsed);
    p_label(
        no_color,
        "Schemas: ",
        &format!(
            "modern (Windows 10/11) {}, legacy (Windows 8/8.1/2012 R2) {}",
            fmt_num(t.modern),
            fmt_num(t.legacy)
        ),
    );
    p_label(no_color, "Inventoried executables: ", &fmt_num(t.files));
    p_label(no_color, "Inventoried devices: ", &fmt_num(t.devices));
    p(JunteiColor::Green.rdg(no_color), "Findings: ", false);
    p(None, &fmt_num(t.finding_count()), false);
    // most severe first, each in its color
    let order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    let mut first = true;
    for severity in order {
        let Some(n) = t.findings.get(severity) else {
            continue;
        };
        p(None, if first { " (" } else { ", " }, false);
        first = false;
        p(
            JunteiColor::for_severity(severity).and_then(|c| c.rdg(no_color)),
            &format!("{}: {}", severity.to_ascii_lowercase(), fmt_num(*n)),
            false,
        );
    }
    p(None, if first { "" } else { ")" }, true);
    p(None, "", true);
}

/// Refuse to overwrite existing results without `-C`, and a CSV directory that is a file.
fn check_output(out: &Path, output_type: OutputType, clobber: bool) -> Result<(), String> {
    let exists_msg = || {
        format!(
            "The output file already exists: {}. Please specify a different filename or add the -C, --clobber option to overwrite.",
            out.display()
        )
    };
    if output_type == OutputType::Csv {
        if out.is_file() {
            return Err(format!(
                "CSV output is a directory, but {} is a file.",
                out.display()
            ));
        }
        let non_empty = out
            .read_dir()
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if non_empty && !clobber {
            return Err(exists_msg());
        }
    } else if out.is_dir() {
        return Err(format!("{} is a directory.", out.display()));
    } else if out.exists() && !clobber {
        return Err(exists_msg());
    }
    Ok(())
}

/// Whether a file name is an Amcache hive: `Amcache.hve`, or any `*.hve` with `amcache` in its
/// name (`HOST_Amcache.hve`). Transaction logs (`Amcache.hve.LOG1`) are not hives.
pub fn is_amcache_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".hve") && lower.contains("amcache")
}

/// The Amcache hives under `dir`, recursively, in path order. Symlinked directories are not
/// followed (a link loop would never end).
pub fn find_hives(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = d.read_dir() else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                stack.push(path);
            } else if (kind.is_file() || (kind.is_symlink() && path.is_file()))
                && is_amcache_name(&entry.file_name().to_string_lossy())
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amcache_hive_names() {
        assert!(is_amcache_name("Amcache.hve"));
        assert!(is_amcache_name("AMCACHE.HVE"));
        assert!(is_amcache_name("HOST01_Amcache.hve"));
        assert!(!is_amcache_name("Amcache.hve.LOG1"));
        assert!(!is_amcache_name("NTUSER.DAT"));
        assert!(!is_amcache_name("SYSTEM.hve"));
    }

    #[test]
    fn hives_are_found_recursively_in_path_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for p in [
            "b/C/Windows/AppCompat/Programs/Amcache.hve",
            "b/C/Windows/AppCompat/Programs/Amcache.hve.LOG1",
            "a/Amcache.hve",
            "notes.txt",
        ] {
            let path = root.join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
        }
        let found = find_hives(root);
        let rel: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            rel,
            [
                "a/Amcache.hve",
                "b/C/Windows/AppCompat/Programs/Amcache.hve"
            ]
        );
    }

    #[test]
    fn existing_output_needs_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out.json");
        assert!(check_output(&file, OutputType::Json, false).is_ok());
        std::fs::write(&file, b"{}").unwrap();
        assert!(check_output(&file, OutputType::Json, false).is_err());
        assert!(check_output(&file, OutputType::Json, true).is_ok());
        assert!(
            check_output(&file, OutputType::Csv, true).is_err(),
            "a file is not a CSV directory"
        );
        assert!(check_output(dir.path(), OutputType::Jsonl, true).is_err());
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(check_output(&empty, OutputType::Csv, false).is_ok());
        assert!(check_output(dir.path(), OutputType::Csv, false).is_err());
        assert!(check_output(dir.path(), OutputType::Csv, true).is_ok());
    }
}
