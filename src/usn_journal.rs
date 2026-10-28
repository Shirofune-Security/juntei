//! `parse-usn-journal`: NTFS USN change journal ($UsnJrnl:$J) parsing with Yamato Security's
//! ys-usn-journal-parser (a fork of sootmark-usn): every record with the path its directory had
//! when the record was written (the journal rewound, seeded from the volume's $MFT when one is
//! found), as MFTECmd's CSV columns or every field as JSON / JSONL. `--carve` finds records in
//! disk images and other data that is not a journal. Hayabusa's input options, progress bar and
//! results summary around it.

use crate::cli::{UsnJournalOptions, UsnOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use chrono::{DateTime, SecondsFormat, Utc};
use indicatif::ProgressBar;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use usn::{Attributes, Entry, PathBuilder, Paths, RangeRecord, Reasons, Record, Reference};

/// Damaged spans printed per journal; the rest are only counted.
const MAX_PRINTED_PROBLEMS: usize = 10;

/// Run the command; returns the exit status.
pub fn run(opts: &UsnJournalOptions) -> i32 {
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
    let (journals, root) = match (&opts.filepath, &opts.directory) {
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
            let found = find_journals(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!("No USN journals ($J) were found in {}", d.display()),
                );
                return 1;
            }
            (found, Some(d.as_path()))
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if let Some(m) = &opts.mft
        && !m.is_file()
    {
        report_error(None, &format!("The file does not exist: {}", m.display()));
        return 1;
    }
    if root.is_some() && data_on_stdout {
        report_error(
            None,
            "With -d, save the records with -o <DIR> (one file per journal): the records of several journals cannot be told apart on stdout.",
        );
        return 1;
    }
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, root.is_some(), opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }

    // Each journal with the $MFT its paths are seeded from.
    let inputs: Vec<(PathBuf, Option<PathBuf>)> = journals
        .into_iter()
        .map(|j| {
            let mft = opts.mft.clone().or_else(|| volume_mft(&j));
            (j, mft)
        })
        .collect();
    // A journal is read twice (to rewind the paths, then to write); carving reads once.
    let passes = if opts.carve { 1 } else { 2 };
    let total: u64 = inputs.iter().map(|(j, _)| file_len(j)).sum();
    if !data_on_stdout {
        p_label(
            no_color,
            if opts.carve {
                "Files to carve: "
            } else {
                "USN journals: "
            },
            &fmt_num(inputs.len()),
        );
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
        progress::progress_bar_bytes(total.saturating_mul(passes), no_color)
    });

    // --- parse and write -------------------------------------------------------------------
    let output_type = opts.output_type();
    let mut stats = Stats::default();
    let mut used_names = HashSet::new();
    let mut saved: Vec<PathBuf> = Vec::new();
    for (journal, mft) in &inputs {
        let source = journal.to_string_lossy().to_string();
        if let Some(b) = &bar {
            b.set_message(progress::message(journal));
        }
        let name = root.map(|r| util::unique_name(r, journal, &mut used_names));
        let out_path = opts.output.as_ref().map(|out| match &name {
            Some(n) => out.join(format!("{n}.{}", output_type.extension())),
            None => out.clone(),
        });
        let sink: Option<Box<dyn Write>> = match (&out_path, data_on_stdout) {
            (Some(p), _) => {
                if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty())
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    report_error(
                        bar.as_ref(),
                        &format!("Could not create {}: {e}", parent.display()),
                    );
                    return 1;
                }
                match File::create(p) {
                    Ok(f) => Some(Box::new(BufWriter::new(f))),
                    Err(e) => {
                        report_error(
                            bar.as_ref(),
                            &format!("Could not create {}: {e}", p.display()),
                        );
                        return 1;
                    }
                }
            }
            (None, true) => Some(Box::new(BufWriter::new(io::stdout()))),
            (None, false) => None,
        };
        let mut writer = sink.map(|w| RecordWriter::new(w, output_type));
        let result = if opts.carve {
            carve_one(
                journal,
                mft.as_deref(),
                writer.as_mut(),
                &mut stats,
                bar.as_ref(),
            )
        } else {
            parse_one(
                journal,
                mft.as_deref(),
                writer.as_mut(),
                &mut stats,
                bar.as_ref(),
                &report_error,
            )
        };
        let finished = writer.map_or(Ok(()), RecordWriter::finish);
        match (result, finished) {
            (Ok(()), Ok(())) => {
                stats.journals += 1;
                if let Some(p) = out_path {
                    saved.push(p);
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                stats.failed += 1;
                report_error(bar.as_ref(), &format!("Could not parse {source}: {e}"));
            }
        }
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&stats, opts.carve, no_color);
        if let Some(out) = &opts.output {
            let value = if root.is_some() {
                format!("{} ({} files)", out.display(), fmt_num(saved.len()))
            } else {
                format!("{} ({})", out.display(), util::file_size_display(out))
            };
            p_label(no_color, "Results saved: ", &value);
        } else {
            p(
                None,
                "To save every record, add -o <FILE> (-t csv, json or jsonl).",
                true,
            );
        }
    }
    i32::from(stats.journals == 0)
}

/// A reader that advances the progress bar.
struct Counted<'a, R> {
    inner: R,
    bar: Option<&'a ProgressBar>,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(b) = self.bar {
            b.inc(n as u64);
        }
        Ok(n)
    }
}

fn open<'a>(path: &Path, bar: Option<&'a ProgressBar>) -> io::Result<Counted<'a, BufReader<File>>> {
    Ok(Counted {
        inner: BufReader::with_capacity(1 << 20, File::open(path)?),
        bar,
    })
}

/// The paths at the start of the journal, seeded from `mft` when there is one.
fn seed(mft: Option<&Path>, stats: &mut Stats) -> io::Result<PathBuilder> {
    let mut builder = PathBuilder::new();
    if let Some(mft) = mft {
        let mut parser = mft::MftParser::from_path(mft).map_err(io::Error::other)?;
        builder.seed_from_mft(&mut parser);
        stats.with_mft += 1;
    }
    Ok(builder)
}

/// Read one journal twice: to rewind the paths, then to resolve and write every record.
fn parse_one(
    journal: &Path,
    mft: Option<&Path>,
    mut writer: Option<&mut RecordWriter>,
    stats: &mut Stats,
    bar: Option<&ProgressBar>,
    report_error: &dyn Fn(Option<&ProgressBar>, &str),
) -> io::Result<()> {
    let source = journal.to_string_lossy().to_string();
    let mut builder = match seed(mft, stats) {
        Ok(b) => b,
        Err(e) => {
            report_error(
                bar,
                &format!(
                    "Could not read the $MFT {} (paths from the journal only): {e}",
                    mft.map(Path::display)
                        .map(|d| d.to_string())
                        .unwrap_or_default()
                ),
            );
            PathBuilder::new()
        }
    };
    for entry in usn::read(open(journal, bar)?) {
        if let Entry::Record(record) = entry? {
            builder.observe(&record);
        }
    }
    let mut paths = builder.finish();
    let mut printed = 0usize;
    for entry in usn::read(open(journal, bar)?) {
        match entry? {
            Entry::Record(record) => {
                let parent_path = paths.parent_path(&record);
                stats.add(&record, &parent_path);
                if let Some(w) = writer.as_deref_mut() {
                    w.record(&record, &parent_path, &source)?;
                }
            }
            Entry::Ranges(ranges) => {
                stats.ranges += 1;
                if let Some(w) = writer.as_deref_mut() {
                    w.ranges(&ranges, &source)?;
                }
            }
            Entry::Problem(problem) => {
                stats.problems += 1;
                stats.damaged_bytes += problem.length;
                if printed < MAX_PRINTED_PROBLEMS {
                    printed += 1;
                    report_error(bar, &format!("{source}: {problem}"));
                }
            }
        }
    }
    Ok(())
}

/// Carve records out of any file; paths from the $MFT as it is now, when one is given.
fn carve_one(
    file: &Path,
    mft: Option<&Path>,
    mut writer: Option<&mut RecordWriter>,
    stats: &mut Stats,
    bar: Option<&ProgressBar>,
) -> io::Result<()> {
    let source = file.to_string_lossy().to_string();
    let paths: Option<Paths> = match mft {
        Some(_) => Some(seed(mft, stats)?.finish()),
        None => None,
    };
    for record in usn::carve(open(file, bar)?) {
        let record = record?;
        let parent_path = paths
            .as_ref()
            .map(|p| p.resolve(record.parent))
            .unwrap_or_default();
        stats.add(&record, &parent_path);
        if let Some(w) = writer.as_deref_mut() {
            w.record(&record, &parent_path, &source)?;
        }
    }
    Ok(())
}

/// A FILETIME as an RFC 3339 UTC time, like the timestamps of `parse-mft` and `parse-prefetch`;
/// empty when it is not a time.
fn filetime(record_time: usn::Filetime) -> String {
    let Some(ticks) = record_time.unix_ticks() else {
        return String::new();
    };
    DateTime::<Utc>::from_timestamp(
        ticks.div_euclid(10_000_000),
        (ticks.rem_euclid(10_000_000) * 100) as u32,
    )
    .map(|t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    .unwrap_or_default()
}

/// Flag names joined with `|`, then any unnamed bits in hex (MFTECmd's style).
fn flag_names<'a>(names: impl Iterator<Item = &'a str>, unknown: u32) -> String {
    let mut out: Vec<String> = names.map(str::to_string).collect();
    if unknown != 0 {
        out.push(format!("0x{unknown:08x}"));
    }
    out.join("|")
}

fn reasons(r: Reasons) -> String {
    flag_names(r.names(), r.unknown())
}

fn attributes(a: Attributes) -> String {
    flag_names(a.names(), a.unknown())
}

/// An NTFS reference as (entry, sequence); a ReFS identifier whole, in hex, as the entry.
fn entry_and_sequence(r: Reference) -> (String, String) {
    if r.is_ntfs() {
        (r.entry().to_string(), r.sequence().to_string())
    } else {
        (format!("0x{:032x}", r.raw()), String::new())
    }
}

fn reference_json(r: Reference) -> Value {
    if r.is_ntfs() {
        json!({"entry": r.entry(), "sequence": r.sequence()})
    } else {
        json!({"id": format!("0x{:032x}", r.raw())})
    }
}

const CSV_HEADER: &[&str] = &[
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
    "SourceInfo",
    "SecurityId",
    "Version",
];

/// The CSV / JSON / JSONL writer of one output.
enum RecordWriter {
    Csv(Box<csv::Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
    Jsonl(Box<dyn Write>),
}

impl RecordWriter {
    fn new(w: Box<dyn Write>, output_type: UsnOutputType) -> Self {
        match output_type {
            UsnOutputType::Csv => {
                let mut csv = csv::Writer::from_writer(w);
                // the header is written even when there are no records
                let _ = csv.write_record(CSV_HEADER);
                RecordWriter::Csv(Box::new(csv))
            }
            UsnOutputType::Json => RecordWriter::Json(w),
            UsnOutputType::Jsonl => RecordWriter::Jsonl(w),
        }
    }

    fn record(&mut self, r: &Record, parent_path: &str, source: &str) -> io::Result<()> {
        match self {
            RecordWriter::Csv(w) => {
                let (entry, sequence) = entry_and_sequence(r.file);
                let (parent_entry, parent_sequence) = entry_and_sequence(r.parent);
                w.write_record([
                    r.name.as_str(),
                    util::dotnet_extension(&r.name),
                    &entry,
                    &sequence,
                    &parent_entry,
                    &parent_sequence,
                    parent_path,
                    &r.usn.to_string(),
                    &filetime(r.time),
                    &reasons(r.reasons),
                    &attributes(r.attributes),
                    &r.offset.to_string(),
                    source,
                    &flag_names(r.source_info.names(), r.source_info.unknown()),
                    &r.security_id.to_string(),
                    &r.version.to_string(),
                ])?;
                Ok(())
            }
            RecordWriter::Json(_) | RecordWriter::Jsonl(_) => {
                let mut v = json!({
                    "source_file": source,
                    "offset": r.offset,
                    "usn": r.usn,
                    "timestamp": filetime(r.time),
                    "version": r.version.to_string(),
                    "name": r.name,
                    "parent_path": parent_path,
                    "file": reference_json(r.file),
                    "parent": reference_json(r.parent),
                    "reasons": r.reasons.names().collect::<Vec<_>>(),
                    "source_info": r.source_info.names().collect::<Vec<_>>(),
                    "security_id": r.security_id,
                    "attributes": r.attributes.names().collect::<Vec<_>>(),
                });
                if r.reasons.unknown() != 0 {
                    v["unknown_reasons"] = json!(format!("0x{:08x}", r.reasons.unknown()));
                }
                if r.attributes.unknown() != 0 {
                    v["unknown_attributes"] = json!(format!("0x{:08x}", r.attributes.unknown()));
                }
                if r.name_escaped {
                    v["name_escaped"] = json!(true);
                }
                write_json(self, &v)
            }
        }
    }

    /// A range-tracking (V4) record: JSON and JSONL only, like MFTECmd's CSV leaves them out.
    fn ranges(&mut self, r: &RangeRecord, source: &str) -> io::Result<()> {
        if let RecordWriter::Csv(_) = self {
            return Ok(());
        }
        let v = json!({
            "source_file": source,
            "offset": r.offset,
            "usn": r.usn,
            "version": r.version.to_string(),
            "file": reference_json(r.file),
            "parent": reference_json(r.parent),
            "reasons": r.reasons.names().collect::<Vec<_>>(),
            "source_info": r.source_info.names().collect::<Vec<_>>(),
            "remaining_extents": r.remaining_extents,
            "extents": r.extents.iter().map(|e| json!({"offset": e.offset, "length": e.length})).collect::<Vec<_>>(),
        });
        write_json(self, &v)
    }

    fn finish(self) -> io::Result<()> {
        match self {
            RecordWriter::Csv(mut w) => w.flush(),
            RecordWriter::Json(mut w) | RecordWriter::Jsonl(mut w) => w.flush(),
        }
    }
}

/// JSON: a pretty object and a newline, like parse-mft; JSONL: one object per line.
fn write_json(writer: &mut RecordWriter, v: &Value) -> io::Result<()> {
    match writer {
        RecordWriter::Json(w) => {
            serde_json::to_writer_pretty(&mut *w, v)?;
            w.write_all(b"\n")
        }
        RecordWriter::Jsonl(w) => {
            serde_json::to_writer(&mut *w, v)?;
            w.write_all(b"\n")
        }
        RecordWriter::Csv(_) => Ok(()),
    }
}

/// Counts for the results summary.
#[derive(Default)]
struct Stats {
    journals: usize,
    failed: usize,
    with_mft: usize,
    records: usize,
    v2: usize,
    v3: usize,
    ranges: usize,
    created: usize,
    deleted: usize,
    renamed: usize,
    unknown_paths: usize,
    problems: usize,
    damaged_bytes: u64,
    first: Option<u64>,
    last: Option<u64>,
}

impl Stats {
    fn add(&mut self, r: &Record, parent_path: &str) {
        self.records += 1;
        if r.version.major == 3 {
            self.v3 += 1;
        } else {
            self.v2 += 1;
        }
        if r.reasons.contains(Reasons::FILE_CREATE) {
            self.created += 1;
        }
        if r.reasons.contains(Reasons::FILE_DELETE) {
            self.deleted += 1;
        }
        if r.reasons.contains(Reasons::RENAME_NEW_NAME) {
            self.renamed += 1;
        }
        if parent_path.contains("[Unknown ") {
            self.unknown_paths += 1;
        }
        if r.time.unix_ticks().is_some() {
            let t = r.time.raw();
            self.first = Some(self.first.map_or(t, |f| f.min(t)));
            self.last = Some(self.last.map_or(t, |l| l.max(t)));
        }
    }
}

fn print_summary(s: &Stats, carve: bool, no_color: bool) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    let mut parsed = fmt_num(s.journals);
    if s.failed > 0 {
        parsed.push_str(&format!(" (could not parse: {})", fmt_num(s.failed)));
    }
    p_label(
        no_color,
        if carve {
            "Files carved: "
        } else {
            "USN journals parsed: "
        },
        &parsed,
    );
    p_label(
        no_color,
        if carve {
            "Records carved: "
        } else {
            "Records: "
        },
        &format!(
            "{} (V2: {}, V3: {})",
            fmt_num(s.records),
            fmt_num(s.v2),
            fmt_num(s.v3)
        ),
    );
    if !carve {
        p_label(
            no_color,
            "Range-tracking records (V4): ",
            &fmt_num(s.ranges),
        );
    }
    if let (Some(first), Some(last)) = (s.first, s.last) {
        p_label(
            no_color,
            "Time range: ",
            &format!(
                "{} - {}",
                filetime(usn::Filetime::new(first)),
                filetime(usn::Filetime::new(last))
            ),
        );
    }
    p_label(
        no_color,
        "Files created / deleted / renamed: ",
        &format!(
            "{} / {} / {}",
            fmt_num(s.created),
            fmt_num(s.deleted),
            fmt_num(s.renamed)
        ),
    );
    let source = if carve {
        if s.with_mft > 0 {
            "from the $MFT as it is now"
        } else {
            "none (no $MFT given)"
        }
    } else if s.with_mft > 0 {
        "rewound from the journal, seeded from the $MFT"
    } else {
        "rewound from the journal (no $MFT found)"
    };
    p_label(no_color, "Paths: ", source);
    if carve && s.with_mft == 0 {
        // no paths were looked up
    } else {
        p_label(
            no_color,
            "Records with an unknown directory: ",
            &fmt_num(s.unknown_paths),
        );
    }
    if !carve {
        p_label(
            no_color,
            "Damaged data: ",
            &format!(
                "{} spans ({})",
                fmt_num(s.problems),
                util::size_display(s.damaged_bytes)
            ),
        );
    }
    p(None, "", true);
}

fn file_len(path: &Path) -> u64 {
    path.metadata().map_or(0, |m| m.len())
}

/// Whether a file name is a USN journal: `$J`, or a name ending in `$J` (`C_$J`,
/// `$UsnJrnl_$J`, `$UsnJrnl:$J`).
pub fn is_journal_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("$j")
}

/// The USN journals under `dir`, recursively, in path order.
pub fn find_journals(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_journal_name)
}

/// The volume's `$MFT` in a collection that keeps the volume's layout (KAPE:
/// `C/$Extend/$J` and `C/$MFT`).
fn volume_mft(journal: &Path) -> Option<PathBuf> {
    let extend = journal.parent()?;
    if !extend
        .file_name()?
        .to_string_lossy()
        .eq_ignore_ascii_case("$Extend")
    {
        return None;
    }
    let mft = extend.parent()?.join("$MFT");
    mft.is_file().then_some(mft)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_names() {
        assert!(is_journal_name("$J"));
        assert!(is_journal_name("C_$J"));
        assert!(is_journal_name("$UsnJrnl_$J"));
        assert!(is_journal_name("$UsnJrnl:$J"));
        assert!(!is_journal_name("$J.csv"));
        assert!(!is_journal_name("$MFT"));
    }

    #[test]
    fn the_volume_mft_is_next_to_extend() {
        let dir = tempfile::tempdir().unwrap();
        let extend = dir.path().join("C/$Extend");
        std::fs::create_dir_all(&extend).unwrap();
        std::fs::write(extend.join("$J"), b"").unwrap();
        assert_eq!(volume_mft(&extend.join("$J")), None);
        std::fs::write(dir.path().join("C/$MFT"), b"").unwrap();
        assert_eq!(
            volume_mft(&extend.join("$J")),
            Some(dir.path().join("C/$MFT"))
        );
        assert_eq!(volume_mft(&dir.path().join("C/$J")), None);
    }

    #[test]
    fn extensions_and_flags() {
        assert_eq!(util::dotnet_extension("psapi.dll"), ".dll");
        assert_eq!(util::dotnet_extension("archive.tar.gz"), ".gz");
        assert_eq!(util::dotnet_extension(".NET Framework"), ".NET Framework");
        assert_eq!(util::dotnet_extension("README"), "");
        assert_eq!(util::dotnet_extension("trailing."), "");
        assert_eq!(
            reasons(Reasons::from_bits(0x8000_0100)),
            "FILE_CREATE|CLOSE"
        );
        assert_eq!(
            reasons(Reasons::from_bits(0x0200_0100)),
            "FILE_CREATE|0x02000000"
        );
        assert_eq!(filetime(usn::Filetime::new(0)), "");
        assert_eq!(
            filetime(usn::Filetime::new(132_885_610_136_531_487)),
            "2022-02-05T18:56:53.653148700Z"
        );
    }
}
