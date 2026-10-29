//! `parse-mft`: $MFT parsing with Yamato Security's ys-mft-parser (a fork of Omer Ben-Amram's
//! `mft` crate that does not crash on damaged or crafted records): the same CSV rows and JSON
//! entries as its `ys-mft-parser` command, with Hayabusa's input options, progress bar and results
//! summary around it.

use crate::cli::{MftOptions, MftOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use indicatif::ProgressBar;
use mft::attribute::MftAttributeType;
use mft::csv::FlatMftEntryWithName;
use mft::entry::ZERO_HEADER;
use mft::{MftEntry, MftParser};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Errors printed per $MFT; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 10;

/// Run the command; returns the exit status.
pub fn run(opts: &MftOptions) -> i32 {
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
    let (mfts, root) = match (&opts.filepath, &opts.directory) {
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
            let found = find_mfts(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!("No $MFT files were found in {}", d.display()),
                );
                return 1;
            }
            (found, Some(d.as_path()))
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if root.is_some() && data_on_stdout {
        report_error(
            None,
            "With -d, save the entries with -o <DIR> (one file per $MFT): rows of several $MFT files cannot be told apart on stdout.",
        );
        return 1;
    }
    if opts.has_csv_options() && opts.output_type() != MftOutputType::Csv {
        report_error(
            None,
            "--all-times, --short-names and --cutoff are options of the CSV output (-t csv).",
        );
        return 1;
    }
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, root.is_some(), opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }
    if let Some(dir) = &opts.extract
        && let Err(msg) = check_output(dir, true, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }

    // Check every header first: the progress bar counts entries. The CSV
    // reads every entry twice more: once for the directories, once for the rows.
    let csv_passes =
        if opts.output_type() == MftOutputType::Csv && (opts.output.is_some() || data_on_stdout) {
            2
        } else {
            0
        };
    let mut inputs: Vec<(PathBuf, Result<u64, String>)> = Vec::new();
    for path in &mfts {
        let count = MftParser::from_path(path)
            .map(|parser| {
                let entries = parser.get_entry_count();
                let listed = match &opts.ranges {
                    Some(r) => r.len(),
                    None => entries,
                };
                listed.saturating_add(entries.saturating_mul(csv_passes))
            })
            .map_err(|e| e.to_string());
        inputs.push((path.clone(), count));
    }
    if !data_on_stdout {
        let total: u64 = mfts.iter().map(|p| file_len(p)).sum();
        p_label(no_color, "$MFT files: ", &fmt_num(mfts.len()));
        p_label(no_color, "Total file size: ", &util::size_display(total));
        p(None, "", true);
    }
    let total_entries: u64 = inputs
        .iter()
        .filter_map(|(_, c)| c.as_ref().ok())
        .fold(0, |a, b| a.saturating_add(*b));
    let bar = (!data_on_stdout).then(|| {
        p(
            JunteiColor::Orange.rdg(no_color),
            "Parsing in progress. Please wait.",
            true,
        );
        p(None, "", true);
        progress::progress_bar_with_len(total_entries, no_color)
    });

    // --- parse and write -------------------------------------------------------------------
    let output_type = opts.output_type();
    let mut stats = Stats::default();
    let mut used_names = HashSet::new();
    let mut saved: Vec<PathBuf> = Vec::new();
    for (path, count) in &inputs {
        let source = path.to_string_lossy().to_string();
        if let Some(b) = &bar {
            b.set_message(progress::message(path));
        }
        if let Err(e) = count {
            stats.files_failed += 1;
            report_error(bar.as_ref(), &format!("Could not parse {source}: {e}"));
            continue;
        }
        let name = root.map(|r| util::unique_name(r, path, &mut used_names));
        let out_path = opts.output.as_ref().map(|out| match &name {
            Some(n) => out.join(format!("{n}.{}", output_type.extension())),
            None => out.clone(),
        });
        let extract_dir = opts.extract.as_ref().map(|dir| match &name {
            Some(n) => dir.join(n),
            None => dir.clone(),
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
        let mut writer = match sink.map(|w| EntryWriter::new(w, output_type)).transpose() {
            Ok(w) => w,
            Err(e) => {
                report_error(bar.as_ref(), &format!("Could not write the header: {e}"));
                return 1;
            }
        };
        let parsed = parse_one(
            path,
            opts,
            writer.as_mut(),
            extract_dir.as_deref(),
            &mut stats,
            bar.as_ref(),
            &report_error,
        );
        let finished = writer.map_or(Ok(()), EntryWriter::finish);
        match (parsed, finished) {
            (Ok(()), Ok(())) => {
                stats.files_parsed += 1;
                if let Some(p) = out_path {
                    saved.push(p);
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                report_error(
                    bar.as_ref(),
                    &format!("Could not write the entries of {source}: {e}"),
                );
                return 1;
            }
        }
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&stats, no_color);
        if let Some(dir) = &opts.extract {
            p_label(
                no_color,
                "Resident streams extracted: ",
                &format!("{} to {}", fmt_num(stats.streams), dir.display()),
            );
        }
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
                "To save every entry, add -o <FILE> (-t csv, json or jsonl).",
                true,
            );
        }
    }
    i32::from(stats.files_parsed == 0)
}

/// Parse one $MFT: every entry (or the `-r` ranges) to the writer and the extraction directory.
fn parse_one(
    path: &Path,
    opts: &MftOptions,
    mut writer: Option<&mut EntryWriter>,
    extract_dir: Option<&Path>,
    stats: &mut Stats,
    bar: Option<&ProgressBar>,
    report_error: &dyn Fn(Option<&ProgressBar>, &str),
) -> io::Result<()> {
    let source = path.display();
    let mut parser = match MftParser::from_path(path) {
        Ok(p) => p,
        Err(e) => {
            stats.files_failed += 1;
            report_error(bar, &format!("Could not parse {source}: {e}"));
            return Ok(());
        }
    };
    if let Some(dir) = extract_dir {
        std::fs::create_dir_all(dir)?;
    }
    let count = parser.get_entry_count();
    let ids: Box<dyn Iterator<Item = u64>> = match &opts.ranges {
        Some(r) => Box::new(r.0.clone().into_iter().flatten()),
        None => Box::new(0..count),
    };
    let mut printed = 0usize;
    for id in ids {
        if let Some(b) = bar {
            b.inc(1);
        }
        let entry = match parser.get_entry(id) {
            Ok(e) if &e.header.signature == ZERO_HEADER => {
                stats.empty += 1;
                continue;
            }
            Ok(e) => e,
            Err(e) => {
                stats.unreadable += 1;
                if printed < MAX_PRINTED_ERRORS {
                    printed += 1;
                    report_error(bar, &format!("{source}: entry {id}: {e}"));
                }
                continue;
            }
        };
        let full_path = parser.get_full_path_for_entry(&entry).ok().flatten();
        // CSV rows and exported streams describe a file rather than one record, so they include
        // the attributes stored in its extension records.
        let extensions = parser.get_extension_entries(&entry);
        let row = FlatMftEntryWithName::from_entry_with_path(
            &entry,
            &extensions,
            full_path.clone().unwrap_or_default(),
        );
        stats.add(&entry, &row);
        // An extension record's streams are exported with its base entry, under the file's path.
        // Only an extension record that its base entry doesn't list exports its own.
        if let Some(dir) = extract_dir
            && (entry.header.is_base_record() || !is_listed_by_its_base(&mut parser, &entry))
            && let Some(path) = &full_path
        {
            stats.streams +=
                extract_resident_streams(&entry, &extensions, &path.to_string_lossy(), dir)?;
        }
        if let Some(w) = writer.as_deref_mut() {
            w.write(&entry, full_path, &row)?;
        }
    }
    if let Some(EntryWriter::Csv(w)) = writer {
        stats.csv_rows += crate::mft_csv::write(
            &mut parser,
            &path.to_string_lossy(),
            opts.csv_options(),
            opts.ranges.as_ref(),
            w,
            bar,
        )?;
    }
    if printed < stats.unreadable && stats.unreadable > MAX_PRINTED_ERRORS {
        report_error(
            bar,
            &format!(
                "{source}: {} more unreadable entries were not shown",
                fmt_num(stats.unreadable - printed)
            ),
        );
    }
    Ok(())
}

/// The CSV / JSON / JSONL writer of one output.
enum EntryWriter {
    /// The CSV, written after the entries are read (see [`crate::mft_csv`]).
    Csv(Box<csv::Writer<Box<dyn Write>>>),
    YsMftParserCsv(Box<csv::Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
    Jsonl(Box<dyn Write>),
}

impl EntryWriter {
    fn new(w: Box<dyn Write>, output_type: MftOutputType) -> io::Result<Self> {
        Ok(match output_type {
            MftOutputType::Csv => {
                let mut csv = csv::Writer::from_writer(w);
                csv.write_record(crate::mft_csv::CSV_HEADER)
                    .map_err(io::Error::other)?;
                EntryWriter::Csv(Box::new(csv))
            }
            MftOutputType::YsMftParserCsv => {
                EntryWriter::YsMftParserCsv(Box::new(csv::Writer::from_writer(w)))
            }
            MftOutputType::Json => EntryWriter::Json(w),
            MftOutputType::Jsonl => EntryWriter::Jsonl(w),
        })
    }

    /// ys-mft-parser's formats: a CSV row per entry, or the entry and its full path as JSON (pretty,
    /// newline-separated) or as one JSON line.
    fn write(
        &mut self,
        entry: &MftEntry,
        full_path: Option<PathBuf>,
        row: &FlatMftEntryWithName,
    ) -> io::Result<()> {
        match self {
            EntryWriter::Csv(_) => Ok(()),
            EntryWriter::YsMftParserCsv(w) => w.serialize(row).map_err(io::Error::other),
            EntryWriter::Json(w) => {
                serde_json::to_writer_pretty(&mut *w, &JsonEntry { full_path, entry })?;
                w.write_all(b"\n")
            }
            EntryWriter::Jsonl(w) => {
                serde_json::to_writer(&mut *w, &JsonEntry { full_path, entry })?;
                w.write_all(b"\n")
            }
        }
    }

    fn finish(self) -> io::Result<()> {
        match self {
            EntryWriter::Csv(mut w) | EntryWriter::YsMftParserCsv(mut w) => w.flush(),
            EntryWriter::Json(mut w) | EntryWriter::Jsonl(mut w) => w.flush(),
        }
    }
}

/// One JSON entry as `ys-mft-parser` writes it: the entry with its full path (`\` separators).
#[derive(Serialize)]
struct JsonEntry<'a> {
    #[serde(serialize_with = "mft::serialize_option_windows_path")]
    full_path: Option<PathBuf>,
    #[serde(flatten)]
    entry: &'a MftEntry,
}

/// Whether `entry` is one of the extension records that its base entry's `$ATTRIBUTE_LIST` leads
/// to.
fn is_listed_by_its_base(
    parser: &mut MftParser<impl io::Read + io::Seek>,
    entry: &MftEntry,
) -> bool {
    let record_number = entry.header.record_number;
    parser
        .get_entry(entry.header.base_reference.entry)
        .is_ok_and(|base| {
            parser
                .get_extension_entries(&base)
                .iter()
                .any(|e| e.header.record_number == record_number)
        })
}

/// Write the resident $DATA streams of an entry and its extension records to `dir` with the names
/// the `ys-mft-parser` command gives them:
/// `<full path>__<entry>-<sequence>_<stream number>_<stream name>.dontrun`. Empty streams are
/// skipped. The names come from the evidence, so every character that is not safe in a file name
/// (separators, `:`, control characters, …) becomes `_`; the entry number keeps the names unique.
fn extract_resident_streams(
    entry: &MftEntry,
    extensions: &[MftEntry],
    full_path: &str,
    dir: &Path,
) -> io::Result<usize> {
    let mut written = 0;
    let streams = std::iter::once(entry)
        .chain(extensions)
        .flat_map(MftEntry::iter_attributes)
        .filter_map(Result::ok)
        .filter(|a| a.header.type_code == MftAttributeType::DATA)
        .filter_map(|a| {
            let name = a.header.name.to_utf8_string();
            a.data
                .as_data()
                .filter(|d| !d.data().is_empty())
                .map(|d| (name, d.data().to_vec()))
        });
    for (i, (name, data)) in streams.enumerate() {
        let file_name = format!(
            "{}__{}-{}_{i}_{}.dontrun",
            safe_file_name(full_path, 150),
            entry.header.record_number,
            entry.header.sequence,
            safe_file_name(&name, 60),
        );
        std::fs::write(dir.join(file_name), data)?;
        written += 1;
    }
    Ok(written)
}

/// `s` as one file-name component of at most `max` characters.
fn safe_file_name(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .take(max)
        .collect()
}

/// Counts for the results summary.
#[derive(Default)]
struct Stats {
    /// Rows of the CSV: one per file name and per alternate data stream.
    csv_rows: u64,
    files_parsed: usize,
    files_failed: usize,
    entries: usize,
    in_use: usize,
    deleted: usize,
    directories: usize,
    with_ads: usize,
    baad: usize,
    fixup_mismatch: usize,
    empty: usize,
    unreadable: usize,
    streams: usize,
}

impl Stats {
    fn add(&mut self, entry: &MftEntry, row: &FlatMftEntryWithName) {
        self.entries += 1;
        if row.is_deleted {
            self.deleted += 1;
        } else {
            self.in_use += 1;
        }
        if row.is_a_directory {
            self.directories += 1;
        }
        if row.has_alternate_data_streams {
            self.with_ads += 1;
        }
        if row.signature == "BAAD" {
            self.baad += 1;
        }
        if entry.valid_fixup == Some(false) {
            self.fixup_mismatch += 1;
        }
    }
}

fn print_summary(s: &Stats, no_color: bool) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    let mut parsed = fmt_num(s.files_parsed);
    if s.files_failed > 0 {
        parsed.push_str(&format!(" (could not parse: {})", fmt_num(s.files_failed)));
    }
    p_label(no_color, "$MFT files parsed: ", &parsed);
    p_label(
        no_color,
        "Entries: ",
        &format!(
            "{} (in use: {}, deleted: {})",
            fmt_num(s.entries),
            fmt_num(s.in_use),
            fmt_num(s.deleted)
        ),
    );
    p_label(
        no_color,
        "Directories / files: ",
        &format!(
            "{} / {}",
            fmt_num(s.directories),
            fmt_num(s.entries - s.directories)
        ),
    );
    p_label(
        no_color,
        "Entries with alternate data streams: ",
        &fmt_num(s.with_ads),
    );
    p_label(
        no_color,
        "Damaged entries: ",
        &format!(
            "BAAD {}, fixup mismatch {}, unreadable {}",
            fmt_num(s.baad),
            fmt_num(s.fixup_mismatch),
            fmt_num(s.unreadable)
        ),
    );
    p_label(no_color, "Empty entries (skipped): ", &fmt_num(s.empty));
    if s.csv_rows > 0 {
        p_label(
            no_color,
            "CSV rows (file names and alternate data streams): ",
            &fmt_num(usize::try_from(s.csv_rows).unwrap_or(usize::MAX)),
        );
    }
    p(None, "", true);
}

fn file_len(path: &Path) -> u64 {
    path.metadata().map_or(0, |m| m.len())
}

/// Whether a file name is an $MFT: `$MFT`, or a name ending in `$MFT` (`C_$MFT`).
pub fn is_mft_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("$mft")
}

/// The $MFT files under `dir`, recursively, in path order (symlinked directories are not followed).
pub fn find_mfts(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_mft_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mft_names_and_safe_stream_file_names() {
        assert!(is_mft_name("$MFT"));
        assert!(is_mft_name("$mft"));
        assert!(is_mft_name("C_$MFT"));
        assert!(!is_mft_name("$MFTMirr"));
        assert!(!is_mft_name("MFT.csv"));
        assert_eq!(safe_file_name("a/b\\c:d*e?.", 100), "a_b_c_d_e_.");
        assert_eq!(safe_file_name("../../evil", 100), ".._.._evil");
        assert_eq!(safe_file_name("name\u{7}.txt", 100), "name_.txt");
        assert_eq!(safe_file_name("abcdef", 3), "abc");
        // the name goes on after the component, so a trailing dot or space is kept
        assert_eq!(safe_file_name("trail. ", 100), "trail. ");
    }
}
