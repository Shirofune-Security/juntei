//! `parse-mft`: $MFT parsing with Omer Ben-Amram's `mft` crate (github.com/omerbenamram/mft): the
//! same CSV rows and JSON entries as its `mft_dump` command, with Hayabusa's input options,
//! progress bar and results summary around it.
//!
//! Two parts are juntei's own so that a damaged or crafted $MFT cannot stop the run: full paths
//! are resolved with the crate's rules but with a guard against parent references that loop (the
//! crate recurses until the stack overflows), and the first record header is checked before the
//! crate sizes its reads with it (a zero entry size divides by zero, a huge one allocates it for
//! every entry).

use crate::cli::{MftOptions, MftOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, error_msg, fmt_num, p, p_label};
use indicatif::ProgressBar;
use mft::attribute::MftAttributeType;
use mft::attribute::header::ResidentialHeader;
use mft::csv::FlatMftEntryWithName;
use mft::entry::{EntryFlags, ZERO_HEADER};
use mft::{EntryHeader, MftAttribute, MftEntry, MftParser};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

/// Parent references followed at most when resolving one path (NTFS paths are far shallower).
const MAX_PATH_DEPTH: usize = 1024;
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

    // Check every header first: the progress bar counts entries.
    let mut inputs: Vec<(PathBuf, Result<u64, String>)> = Vec::new();
    for path in &mfts {
        let count = record_size(path).map(|size| match &opts.ranges {
            Some(r) => r.len(),
            None => file_len(path) / u64::from(size),
        });
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
        let mut writer = sink.map(|w| EntryWriter::new(w, output_type));
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
    let mut resolver = PathResolver::default();
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
        let full_path = resolver.full_path(&mut parser, &entry);
        let row = flat_entry(&entry, full_path.clone());
        stats.add(&entry, &row);
        if let (Some(dir), Some(full_path)) = (extract_dir, &full_path) {
            stats.streams += extract_resident_streams(&entry, full_path, dir)?;
        }
        if let Some(w) = writer.as_deref_mut() {
            w.write(&entry, &row)?;
        }
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
    Csv(Box<csv::Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
    Jsonl(Box<dyn Write>),
}

impl EntryWriter {
    fn new(w: Box<dyn Write>, output_type: MftOutputType) -> Self {
        match output_type {
            MftOutputType::Csv => EntryWriter::Csv(Box::new(csv::Writer::from_writer(w))),
            MftOutputType::Json => EntryWriter::Json(w),
            MftOutputType::Jsonl => EntryWriter::Jsonl(w),
        }
    }

    /// mft_dump's formats: a CSV row per entry, or the entry as JSON (pretty, newline-separated)
    /// or as one JSON line.
    fn write(&mut self, entry: &MftEntry, row: &FlatMftEntryWithName) -> io::Result<()> {
        match self {
            EntryWriter::Csv(w) => w.serialize(row).map_err(io::Error::other),
            EntryWriter::Json(w) => {
                serde_json::to_writer_pretty(&mut *w, entry)?;
                w.write_all(b"\n")
            }
            EntryWriter::Jsonl(w) => {
                serde_json::to_writer(&mut *w, entry)?;
                w.write_all(b"\n")
            }
        }
    }

    fn finish(self) -> io::Result<()> {
        match self {
            EntryWriter::Csv(mut w) => w.flush(),
            EntryWriter::Json(mut w) | EntryWriter::Jsonl(mut w) => w.flush(),
        }
    }
}

/// The CSV row of an entry: `mft::csv::FlatMftEntryWithName::from_entry` with the full path
/// resolved by [`PathResolver`].
fn flat_entry(entry: &MftEntry, full_path: Option<PathBuf>) -> FlatMftEntryWithName {
    let attributes: Vec<MftAttribute> = entry
        .iter_attributes_matching(Some(vec![
            MftAttributeType::FileName,
            MftAttributeType::StandardInformation,
            MftAttributeType::DATA,
        ]))
        .filter_map(Result::ok)
        .collect();
    let find = |t: MftAttributeType| attributes.iter().find(|a| a.header.type_code == t);
    let file_name = find(MftAttributeType::FileName).and_then(|a| a.data.clone().into_file_name());
    let standard_info = find(MftAttributeType::StandardInformation)
        .and_then(|a| a.data.clone().into_standard_info());
    let file_size = match find(MftAttributeType::DATA).map(|a| &a.header.residential_header) {
        Some(ResidentialHeader::Resident(r)) => u64::from(r.data_size),
        Some(ResidentialHeader::NonResident(nr)) => nr.file_size,
        None => 0,
    };
    let has_ads = attributes
        .iter()
        .any(|a| a.header.type_code == MftAttributeType::DATA && !a.header.name.is_empty());
    FlatMftEntryWithName {
        signature: String::from_utf8_lossy(&entry.header.signature.to_ascii_uppercase())
            .to_string(),
        entry_id: entry.header.record_number,
        sequence: entry.header.sequence,
        base_entry_id: entry.header.base_reference.entry,
        base_entry_sequence: entry.header.base_reference.sequence,
        hard_link_count: entry.header.hard_link_count,
        flags: entry.header.flags.clone(),
        used_entry_size: entry.header.used_entry_size,
        total_entry_size: entry.header.total_entry_size,
        file_size,
        is_a_directory: entry.is_dir(),
        is_deleted: !entry.header.flags.contains(EntryFlags::ALLOCATED),
        has_alternate_data_streams: has_ads,
        standard_info_flags: standard_info.as_ref().map(|i| i.file_flags.clone()),
        standard_info_last_modified: standard_info.as_ref().map(|i| i.modified),
        standard_info_last_access: standard_info.as_ref().map(|i| i.accessed),
        standard_info_created: standard_info.as_ref().map(|i| i.created),
        file_name_flags: file_name.as_ref().map(|i| i.flags.clone()),
        file_name_last_modified: file_name.as_ref().map(|i| i.modified),
        file_name_last_access: file_name.as_ref().map(|i| i.accessed),
        file_name_created: file_name.as_ref().map(|i| i.created),
        full_path: full_path.unwrap_or_default(),
    }
}

/// Full paths with the rules of `MftParser::get_full_path_for_entry` (root is entry 5,
/// `[Orphaned]` for a missing parent, `[Unknown]` for an unreadable or non-directory parent),
/// memoizing directory paths, but stopping at a parent reference that loops or a chain deeper
/// than [`MAX_PATH_DEPTH`] instead of recursing until the stack overflows.
#[derive(Default)]
struct PathResolver {
    dirs: HashMap<u64, PathBuf>,
}

impl PathResolver {
    fn full_path<T: Read + Seek>(
        &mut self,
        parser: &mut MftParser<T>,
        entry: &MftEntry,
    ) -> Option<PathBuf> {
        self.path_of(parser, entry, &mut Vec::new())
    }

    fn path_of<T: Read + Seek>(
        &mut self,
        parser: &mut MftParser<T>,
        entry: &MftEntry,
        chain: &mut Vec<u64>,
    ) -> Option<PathBuf> {
        let id = entry.header.record_number;
        match entry.find_best_name_attribute() {
            Some(name_attr) => {
                let parent = name_attr.parent.entry;
                let name = name_attr.name;
                if parent == 5 {
                    Some(PathBuf::from(name))
                } else if parent == id {
                    Some(PathBuf::from("[Orphaned]").join(name))
                } else if parent > 0 {
                    Some(self.dir_path(parser, parent, chain).join(name))
                } else {
                    let orphan = PathBuf::from("[Orphaned]").join(name);
                    // as the crate does: an orphan's own path serves its children
                    self.dirs.insert(id, orphan.clone());
                    Some(orphan)
                }
            }
            None => match entry.header.base_reference.entry {
                0 => None,
                base => Some(self.dir_path(parser, base, chain)),
            },
        }
    }

    fn dir_path<T: Read + Seek>(
        &mut self,
        parser: &mut MftParser<T>,
        id: u64,
        chain: &mut Vec<u64>,
    ) -> PathBuf {
        if let Some(path) = self.dirs.get(&id) {
            return path.clone();
        }
        if chain.contains(&id) || chain.len() >= MAX_PATH_DEPTH {
            return PathBuf::from("[Unknown]");
        }
        chain.push(id);
        let path = match parser.get_entry(id) {
            Ok(parent) => match self.path_of(parser, &parent, chain) {
                Some(path) if parent.is_dir() => path,
                Some(_) => PathBuf::from("[Unknown]"),
                // a parent without a name: the root
                None => PathBuf::new(),
            },
            // a corrupt or incomplete parent
            Err(_) => PathBuf::from("[Unknown]"),
        };
        chain.pop();
        self.dirs.insert(id, path.clone());
        path
    }
}

/// Write the resident $DATA streams of an entry to `dir` as
/// `<entry>-<sequence>_<full path>_<stream number>_<stream name>.dontrun`. The names come from the
/// evidence, so every character that is not safe in a file name (separators, `:`, control
/// characters, …) becomes `_`; the entry number keeps the names unique.
fn extract_resident_streams(entry: &MftEntry, full_path: &Path, dir: &Path) -> io::Result<usize> {
    let mut written = 0;
    let streams = entry
        .iter_attributes()
        .filter_map(Result::ok)
        .filter(|a| a.header.type_code == MftAttributeType::DATA)
        .filter_map(|a| {
            let name = a.header.name.clone();
            a.data.into_data().map(|d| (name, d))
        });
    for (i, (name, data)) in streams.enumerate() {
        let file_name = format!(
            "{}-{}_{}_{i}_{}.dontrun",
            entry.header.record_number,
            entry.header.sequence,
            safe_file_name(&full_path.to_string_lossy(), 120),
            safe_file_name(&name, 60),
        );
        std::fs::write(dir.join(file_name), data.data())?;
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
        .collect::<String>()
        .trim_end_matches(['.', ' '])
        .to_string()
}

/// Counts for the results summary.
#[derive(Default)]
struct Stats {
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
    p(None, "", true);
}

fn file_len(path: &Path) -> u64 {
    path.metadata().map_or(0, |m| m.len())
}

/// The record size from the first header, if it is a usable one: a `FILE` record whose size is a
/// power of two from 256 bytes to 64 KiB (NTFS uses 1024 or 4096).
fn record_size(path: &Path) -> Result<u32, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let header = EntryHeader::from_reader(&mut BufReader::new(file), 0)
        .map_err(|e| format!("not an $MFT: {e}"))?;
    if !header.is_valid() {
        return Err("not an $MFT: the first entry is not a FILE record".to_string());
    }
    let size = header.total_entry_size;
    if !(256..=65536).contains(&size) || !size.is_power_of_two() {
        return Err(format!("not an $MFT: unusable record size {size}"));
    }
    Ok(size)
}

/// Refuse to overwrite existing results without `-C`.
fn check_output(out: &Path, is_dir: bool, clobber: bool) -> Result<(), String> {
    let exists = || {
        format!(
            "The output file already exists: {}. Please specify a different filename or add the -C, --clobber option to overwrite.",
            out.display()
        )
    };
    if is_dir {
        if out.is_file() {
            return Err(format!("{} is a file, not a directory.", out.display()));
        }
        let non_empty = out
            .read_dir()
            .map(|mut e| e.next().is_some())
            .unwrap_or(false);
        if non_empty && !clobber {
            return Err(exists());
        }
    } else if out.is_dir() {
        return Err(format!("{} is a directory.", out.display()));
    } else if out.exists() && !clobber {
        return Err(exists());
    }
    Ok(())
}

/// Whether a file name is an $MFT: `$MFT`, or a name ending in `$MFT` (`C_$MFT`).
pub fn is_mft_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("$mft")
}

/// The $MFT files under `dir`, recursively, in path order (symlinked directories are not followed).
pub fn find_mfts(dir: &Path) -> Vec<PathBuf> {
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
                && is_mft_name(&entry.file_name().to_string_lossy())
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

    const TEST_MFT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_files/mft/MFT");

    /// The test $MFT with two directories naming each other as parent.
    fn mft_with_a_parent_cycle() -> (Vec<u8>, u64, u64) {
        let mut data = std::fs::read(TEST_MFT).unwrap();
        let size = 1024;
        let file_name_offsets = |data: &[u8], i: usize| -> Vec<usize> {
            let base = i * size;
            let mut off = usize::from(u16::from_le_bytes([data[base + 0x14], data[base + 0x15]]));
            let mut out = Vec::new();
            while off + 8 < size {
                let t = u32::from_le_bytes(data[base + off..base + off + 4].try_into().unwrap());
                let len =
                    u32::from_le_bytes(data[base + off + 4..base + off + 8].try_into().unwrap());
                if t == 0xFFFF_FFFF || len == 0 {
                    break;
                }
                if t == 0x30 && data[base + off + 8] == 0 {
                    let content = usize::from(u16::from_le_bytes([
                        data[base + off + 0x14],
                        data[base + off + 0x15],
                    ]));
                    out.push(base + off + content);
                }
                off += len as usize;
            }
            out
        };
        let is_dir = |data: &[u8], i: usize| data[i * size + 0x16] & 2 != 0;
        let dirs: Vec<usize> = (16..data.len() / size)
            .filter(|&i| &data[i * size..i * size + 4] == b"FILE" && is_dir(&data, i))
            .filter(|&i| !file_name_offsets(&data, i).is_empty())
            .take(2)
            .collect();
        let (a, b) = (dirs[0], dirs[1]);
        for (x, parent) in [(a, b), (b, a)] {
            for o in file_name_offsets(&data, x) {
                assert!(
                    o % 512 + 8 <= 510,
                    "the patch must not touch a fixup position"
                );
                data[o..o + 6].copy_from_slice(&(parent as u64).to_le_bytes()[..6]);
                data[o + 6..o + 8].copy_from_slice(&[0, 0]);
            }
        }
        (data, a as u64, b as u64)
    }

    #[test]
    fn paths_match_the_crate_on_an_intact_mft() {
        let mut ours = MftParser::from_path(TEST_MFT).unwrap();
        let mut theirs = MftParser::from_path(TEST_MFT).unwrap();
        let mut resolver = PathResolver::default();
        let mut compared = 0;
        for id in 0..ours.get_entry_count() {
            let entry = ours.get_entry(id).unwrap();
            if &entry.header.signature == ZERO_HEADER {
                continue;
            }
            let expected = theirs.get_full_path_for_entry(&entry).unwrap();
            assert_eq!(
                resolver.full_path(&mut ours, &entry),
                expected,
                "entry {id}"
            );
            compared += 1;
        }
        assert_eq!(compared, 1016);
    }

    #[test]
    fn a_parent_cycle_ends_in_unknown_instead_of_a_stack_overflow() {
        let (data, a, b) = mft_with_a_parent_cycle();
        let mut parser = MftParser::from_buffer(data).unwrap();
        let mut resolver = PathResolver::default();
        let entry = parser.get_entry(a).unwrap();
        let path = resolver.full_path(&mut parser, &entry).unwrap();
        assert!(path.starts_with("[Unknown]"), "{}", path.display());
        let entry = parser.get_entry(b).unwrap();
        assert!(
            resolver
                .full_path(&mut parser, &entry)
                .unwrap()
                .starts_with("[Unknown]")
        );
        // every entry still gets a row
        let entries: Vec<MftEntry> = (0..parser.get_entry_count())
            .filter_map(|id| parser.get_entry(id).ok())
            .filter(|e| &e.header.signature != ZERO_HEADER)
            .collect();
        let mut rows = 0;
        for e in &entries {
            let path = resolver.full_path(&mut parser, e);
            flat_entry(e, path);
            rows += 1;
        }
        assert_eq!(rows, 1016);
    }

    #[test]
    fn the_first_header_must_be_a_usable_file_record() {
        assert_eq!(record_size(Path::new(TEST_MFT)), Ok(1024));
        let dir = tempfile::tempdir().unwrap();
        let zero = dir.path().join("zero");
        std::fs::write(&zero, vec![0u8; 4096]).unwrap();
        assert!(
            record_size(&zero)
                .unwrap_err()
                .contains("not a FILE record")
        );
        let mut data = std::fs::read(TEST_MFT).unwrap();
        data[0x1C..0x20].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let huge = dir.path().join("huge");
        std::fs::write(&huge, &data[..4096]).unwrap();
        assert!(
            record_size(&huge)
                .unwrap_err()
                .contains("unusable record size")
        );
        let text = dir.path().join("text");
        std::fs::write(&text, b"hello world").unwrap();
        assert!(record_size(&text).unwrap_err().starts_with("not an $MFT"));
    }

    #[test]
    fn mft_names_and_safe_stream_file_names() {
        assert!(is_mft_name("$MFT"));
        assert!(is_mft_name("$mft"));
        assert!(is_mft_name("C_$MFT"));
        assert!(!is_mft_name("$MFTMirr"));
        assert!(!is_mft_name("MFT.csv"));
        assert_eq!(safe_file_name("a/b\\c:d*e?.", 100), "a_b_c_d_e_");
        assert_eq!(safe_file_name("../../evil", 100), ".._.._evil");
        assert_eq!(safe_file_name("name\u{7}.txt", 100), "name_.txt");
        assert_eq!(safe_file_name("abcdef", 3), "abc");
        assert_eq!(safe_file_name("trail. ", 100), "trail");
    }

    #[test]
    fn existing_outputs_need_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out.csv");
        assert!(check_output(&file, false, false).is_ok());
        std::fs::write(&file, b"x").unwrap();
        assert!(check_output(&file, false, false).is_err());
        assert!(check_output(&file, false, true).is_ok());
        assert!(
            check_output(&file, true, true).is_err(),
            "a file is not a directory"
        );
        assert!(check_output(dir.path(), false, true).is_err());
        assert!(check_output(dir.path(), true, false).is_err());
        assert!(check_output(dir.path(), true, true).is_ok());
    }
}
