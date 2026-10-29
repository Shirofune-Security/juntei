//! `parse-registry`: every key and value of registry hives (SYSTEM, SOFTWARE, SAM, SECURITY,
//! NTUSER.DAT, UsrClass.dat, Amcache.hve, …), with Hayabusa's input options, progress bar and
//! results summary. A dirty hive gets its transaction logs (`.LOG1`, `.LOG2` next to it, or given
//! with `--log`) replayed by ys-shimcache-parser, and each record says whether the replay changed
//! it. One record per value, and one per key without values or with damage, with the key's
//! last-write time, the value's type, its data decoded and, when it doesn't decode or
//! `--raw-data` asks, its bytes. Filters on the key path, value names and data (regular
//! expressions ignoring case, so that a GUID matches in any case) and last-write times keep a
//! targeted query from writing the whole hive.

use crate::cli::{RegistryOptions, RegistryOutputType};
use crate::color::JunteiColor;
use crate::hive::{self, Hive, Key};
use crate::lnk::filetime;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use indicatif::ProgressBar;
use regex::{Regex, RegexBuilder};
use serde_json::{Value, json};
use shimcache_forensic::{LogFile, Recovery, find_logs};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Parse errors printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// Problems listed in the summary.
const MAX_PRINTED_PROBLEMS: usize = 20;
/// Larger files are not registry hives (Windows limits a hive to 2 GiB).
const MAX_HIVE_SIZE: u64 = 2 * 1024 * 1024 * 1024 + 4096;
/// The hives Windows keeps, as their base blocks name them (in upper case).
const HIVE_TYPES: [&str; 14] = [
    "SYSTEM",
    "SOFTWARE",
    "SAM",
    "SECURITY",
    "DEFAULT",
    "COMPONENTS",
    "DRIVERS",
    "ELAM",
    "BBI",
    "BCD",
    "NTUSER.DAT",
    "USRCLASS.DAT",
    "AMCACHE.HVE",
    "SYSCACHE.HVE",
];

/// Run the command; returns the exit status.
pub fn run(opts: &RegistryOptions) -> i32 {
    let no_color = opts.common.no_color;
    let data_on_stdout = opts.data_on_stdout();
    let report_error = |bar: Option<&ProgressBar>, msg: &str| {
        if data_on_stdout {
            eprintln!("{msg}");
        } else {
            progress::suspended(bar, || error_msg(no_color, msg));
        }
    };
    let filters = match Filters::new(opts) {
        Ok(f) => f,
        Err(msg) => {
            report_error(None, &msg);
            return 1;
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
                    &format!("No registry hives were found in {}", d.display()),
                );
                return 1;
            }
            found
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    for log in &opts.logs {
        if !log.is_file() {
            report_error(None, &format!("The file does not exist: {}", log.display()));
            return 1;
        }
    }
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, false, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }
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
    let mut writer = match sink.map(|w| RecordWriter::new(w, opts.output_type(), opts.raw_data)) {
        Some(Ok(w)) => Some(w),
        Some(Err(e)) => {
            report_error(None, &format!("Could not write the records: {e}"));
            return 1;
        }
        None => None,
    };
    if !data_on_stdout {
        let total: u64 = files
            .iter()
            .map(|p| p.metadata().map_or(0, |m| m.len()))
            .sum();
        p_label(no_color, "Registry hives: ", &fmt_num(files.len()));
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

    // --- parse and write -------------------------------------------------------------------
    let mut stats = Stats::default();
    for path in &files {
        if let Some(b) = &bar {
            b.set_message(progress::message(path));
        }
        match open(path, opts) {
            Ok(opened) => {
                if let Err(e) = stats.hive(&opened, &filters, writer.as_mut()) {
                    report_error(
                        bar.as_ref(),
                        &format!("Could not write the records of {}: {e}", path.display()),
                    );
                    return 1;
                }
            }
            Err(e) => {
                stats.failed += 1;
                if stats.failed <= MAX_PRINTED_ERRORS {
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
    if stats.failed > MAX_PRINTED_ERRORS {
        report_error(
            bar.as_ref(),
            &format!(
                "{} more files could not be parsed",
                fmt_num(stats.failed - MAX_PRINTED_ERRORS)
            ),
        );
    }
    if let Some(w) = writer
        && let Err(e) = w.finish()
    {
        report_error(None, &format!("Could not write the records: {e}"));
        return 1;
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        stats.print(&filters, no_color);
        if let Some(out) = &opts.output {
            p_label(
                no_color,
                "Results saved: ",
                &format!("{} ({})", out.display(), util::file_size_display(out)),
            );
        } else {
            p(
                None,
                "To save every record, add -o <FILE> (-t csv, json or jsonl).",
                true,
            );
        }
    }
    i32::from(stats.hives == 0)
}

// --- hives ------------------------------------------------------------------------------------

/// Whether a file is a primary hive file: the `regf` signature and file type 0 (transaction logs
/// start with a base block too), and not named as a log.
fn is_hive_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_uppercase())
        .unwrap_or_default();
    if [".LOG", ".LOG1", ".LOG2"].iter().any(|x| name.ends_with(x)) {
        return false;
    }
    let mut head = [0u8; 32];
    File::open(path)
        .and_then(|mut f| io::Read::read_exact(&mut f, &mut head))
        .is_ok()
        && &head[..4] == b"regf"
        && head[28..32] == [0; 4]
}

/// The primary hive files under `dir`, recursively, in path order.
pub fn find_hives(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, |_| true)
        .into_iter()
        .filter(|p| is_hive_file(p))
        .collect()
}

/// A hive read for output.
struct Opened {
    source: String,
    /// `SYSTEM`, `NTUSER.DAT`, …: the name its base block records, when Windows keeps a hive of
    /// that name (else the file's, else empty).
    hive_type: String,
    recovery: Recovery,
    hive: Hive,
    /// The hive as it was, when its logs changed it.
    before: Option<Index>,
}

fn open(path: &Path, opts: &RegistryOptions) -> Result<Opened, String> {
    let size = path.metadata().map_err(|e| e.to_string())?.len();
    if size > MAX_HIVE_SIZE {
        return Err(format!("too large for a registry hive ({size} bytes)"));
    }
    let primary = std::fs::read(path).map_err(|e| e.to_string())?;
    let logs = if opts.no_logs {
        Vec::new()
    } else if opts.logs.is_empty() {
        find_logs(path)
    } else {
        opts.logs
            .iter()
            .map(|l| {
                Ok(LogFile {
                    name: l.file_name().map_or_else(
                        || l.to_string_lossy().to_string(),
                        |n| n.to_string_lossy().to_string(),
                    ),
                    data: std::fs::read(l).map_err(|e| format!("{}: {e}", l.display()))?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    };
    let (bytes, recovery, before) = if logs.is_empty() {
        let recovery = Recovery {
            dirty: primary.starts_with(b"regf") && hive::is_dirty(&primary),
            ..Recovery::default()
        };
        (primary, recovery, None)
    } else {
        let (replayed, recovery) =
            shimcache_forensic::Hive::open(primary.clone(), &logs).map_err(|e| e.0)?;
        let before = recovery
            .recovered
            .then(|| Hive::from_bytes(primary).ok())
            .flatten()
            .map(|h| Index::of(&h));
        (replayed.bytes().to_vec(), recovery, before)
    };
    let hive = Hive::from_bytes(bytes)?;
    let named = |name: String| {
        let upper = name.to_uppercase();
        HIVE_TYPES.contains(&upper.as_str()).then_some(upper)
    };
    let hive_type = named(hive.base_name())
        .or_else(|| named(path.file_name()?.to_string_lossy().to_string()))
        .unwrap_or_default();
    Ok(Opened {
        source: path.to_string_lossy().to_string(),
        hive_type,
        recovery,
        hive,
        before,
    })
}

/// Every key from `start` (at `path`) down, depth first in list order, each once: a list that
/// leads back to a key already read is a problem, not a loop. `visit` gets each key, its path
/// under the root (empty for the root) and the problems with its subkeys.
fn walk<'h>(
    start: Key<'h>,
    path: String,
    mut visit: impl FnMut(&Key<'h>, &str, Vec<String>) -> io::Result<()>,
) -> io::Result<()> {
    let mut seen = HashSet::from([start.offset()]);
    let mut stack = vec![(start, path)];
    while let Some((key, path)) = stack.pop() {
        let (subkeys, mut problems) = key.subkeys_and_problems();
        let mut children = Vec::new();
        for sub in subkeys {
            let name = sub.name();
            if !seen.insert(sub.offset()) {
                problems.push(format!("subkey {name} is listed again (a loop)"));
                continue;
            }
            let child = if path.is_empty() {
                name
            } else {
                format!("{path}\\{name}")
            };
            children.push((sub, child));
        }
        visit(&key, &path, problems)?;
        // pushed last first, so that they come out in list order
        stack.extend(children.into_iter().rev());
    }
    Ok(())
}

/// A hive as it was before its logs were replayed: each key's last-write time and a hash of each
/// value (its type and data), by path and name in upper case, to tell what the replay changed.
struct Index(HashMap<String, (u64, HashMap<String, u64>)>);

impl Index {
    fn of(hive: &Hive) -> Self {
        let mut keys = HashMap::new();
        if let Ok(root) = hive.root() {
            let _ = walk(root, String::new(), |key, path, _| {
                let values = key
                    .values_and_problems()
                    .0
                    .iter()
                    .map(|v| (v.name().to_uppercase(), digest(v.data_type(), &v.data())))
                    .collect();
                keys.insert(path.to_uppercase(), (key.last_written(), values));
                Ok(())
            });
        }
        Index(keys)
    }

    /// Whether the key at `path` wasn't in the hive, or was last written at another time.
    fn key_changed(&self, path: &str, written: u64) -> bool {
        self.0
            .get(&path.to_uppercase())
            .is_none_or(|(w, _)| *w != written)
    }

    /// Whether the value wasn't in the hive, or had another type or data.
    fn value_changed(&self, path: &str, name: &str, digest: u64) -> bool {
        self.0
            .get(&path.to_uppercase())
            .and_then(|(_, values)| values.get(&name.to_uppercase()))
            .is_none_or(|d| *d != digest)
    }
}

/// A value's type and data, hashed; data that can't be read hashes as none.
fn digest(kind: u32, data: &Result<Vec<u8>, String>) -> u64 {
    let mut h = DefaultHasher::new();
    kind.hash(&mut h);
    data.as_ref().ok().hash(&mut h);
    h.finish()
}

// --- values -----------------------------------------------------------------------------------

/// A value type's name; unknown ones in hex.
fn type_name(kind: u32) -> String {
    match kind {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        other => return format!("0x{other:x}"),
    }
    .to_string()
}

/// A value's data as written.
enum Data {
    /// Decoded: as JSON (a string, an array of strings, a number) and as CSV text.
    Decoded(Value, String),
    /// A type with no decoding: its bytes are the data.
    Bytes,
    /// Not what its type says (a `REG_DWORD` of 3 bytes): why.
    Malformed(String),
}

fn utf16_units(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>()
        .0
        .iter()
        .map(|u| u16::from_le_bytes(*u))
        .collect()
}

/// `data` of type `kind`: strings up to their NUL (UTF-16), multi-strings split at theirs,
/// numbers as numbers, the binary types in hex.
fn decode(kind: u32, data: &[u8]) -> Data {
    let sized = |n: usize| {
        (data.len() == n)
            .then_some(())
            .ok_or_else(|| Data::Malformed(format!("{} of {} bytes", type_name(kind), data.len())))
    };
    match kind {
        1 | 2 | 6 => {
            let units = utf16_units(data);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            let s = String::from_utf16_lossy(&units[..end]);
            Data::Decoded(json!(s), s)
        }
        7 => {
            let units = utf16_units(data);
            let mut items: Vec<String> = units
                .split(|&u| u == 0)
                .map(String::from_utf16_lossy)
                .collect();
            // the terminating NULs leave empty strings at the end
            while items.last().is_some_and(String::is_empty) {
                items.pop();
            }
            let text = serde_json::to_string(&items).unwrap_or_default();
            Data::Decoded(json!(items), text)
        }
        4 => match sized(4) {
            Ok(()) => {
                let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Data::Decoded(json!(n), n.to_string())
            }
            Err(e) => e,
        },
        5 => match sized(4) {
            Ok(()) => {
                let n = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Data::Decoded(json!(n), n.to_string())
            }
            Err(e) => e,
        },
        11 => match sized(8) {
            Ok(()) => {
                let n = u64::from_le_bytes(data.try_into().unwrap_or_default());
                Data::Decoded(json!(n), n.to_string())
            }
            Err(e) => e,
        },
        0 | 3 | 8..=10 => Data::Decoded(json!(hex(data)), hex(data)),
        _ => Data::Bytes,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- filters ----------------------------------------------------------------------------------

/// What to write.
struct Filters {
    /// `--key`: that key and the keys under it.
    key: Option<String>,
    key_regex: Option<Regex>,
    value_name: Option<Regex>,
    value_data: Option<Regex>,
    start: Option<u64>,
    end: Option<u64>,
}

impl Filters {
    fn new(opts: &RegistryOptions) -> Result<Self, String> {
        let regex = |option: &str, pattern: &Option<String>| {
            pattern
                .as_deref()
                .map(|p| {
                    RegexBuilder::new(p)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| format!("{option}: {e}"))
                })
                .transpose()
        };
        let time = |t: Option<i64>| t.and_then(|t| u64::try_from(t).ok());
        Ok(Filters {
            key: opts
                .key
                .as_deref()
                .map(|k| k.trim_matches('\\').to_string()),
            key_regex: regex("--key-regex", &opts.key_regex)?,
            value_name: regex("--value-name", &opts.value_name)?,
            value_data: regex("--value-data", &opts.value_data)?,
            start: time(opts.timeline_start),
            end: time(opts.timeline_end),
        })
    }

    /// Whether values are filtered: then keys without values aren't written.
    fn on_values(&self) -> bool {
        self.value_name.is_some() || self.value_data.is_some()
    }

    fn any(&self) -> bool {
        self.key.is_some()
            || self.key_regex.is_some()
            || self.on_values()
            || self.start.is_some()
            || self.end.is_some()
    }

    fn key_matches(&self, path: &str, written: u64) -> bool {
        self.key_regex.as_ref().is_none_or(|r| r.is_match(path))
            && self.start.is_none_or(|s| written >= s)
            && self.end.is_none_or(|e| written <= e)
    }

    fn value_matches(&self, name: &str, text: &str) -> bool {
        self.value_name.as_ref().is_none_or(|r| r.is_match(name))
            && self.value_data.as_ref().is_none_or(|r| r.is_match(text))
    }

    /// The key `--key` names in `hive` and its path, or the root; `None` when the hive hasn't
    /// it. A path may start with the hive's name (`SOFTWARE\Microsoft`).
    fn start<'h>(&self, opened: &'h Opened) -> Option<(Key<'h>, String)> {
        let hive = &opened.hive;
        let Some(path) = &self.key else {
            return hive.root().ok().map(|r| (r, String::new()));
        };
        let found = |path: &str| hive.find(path).map(|k| (k, path.to_string()));
        found(path).or_else(|| {
            let (first, rest) = path.split_once('\\')?;
            first
                .eq_ignore_ascii_case(&opened.hive_type)
                .then(|| found(rest))?
        })
    }
}

// --- records ----------------------------------------------------------------------------------

/// One record to write: a value, or a key (without values, or with damage).
struct Record<'a> {
    opened: &'a Opened,
    key_path: &'a str,
    key_written: u64,
    value: Option<ValueRecord>,
    /// Whether the logs' replay changed it; `None` when no log was applied.
    changed: Option<bool>,
    problems: Vec<String>,
}

struct ValueRecord {
    name: String,
    kind: u32,
    size: usize,
    data: Option<Data>,
    /// Its bytes, written when they don't decode or `--raw-data` asks.
    bytes: Vec<u8>,
}

const CSV_HEADER: [&str; 14] = [
    "SourceFile",
    "HiveType",
    "RecordType",
    "KeyPath",
    "KeyLastWrittenUTC",
    "ValueName",
    "ValueType",
    "ValueData",
    "DataSize",
    "ValueDataRaw",
    "HiveDirty",
    "LogsApplied",
    "ChangedByLogs",
    "Problems",
];

impl Record<'_> {
    fn record_type(&self) -> &'static str {
        if self.value.is_some() { "value" } else { "key" }
    }

    /// The bytes to write: when the data doesn't decode, or when asked for.
    fn raw(&self, always: bool) -> Option<String> {
        let v = self.value.as_ref()?;
        let undecoded = !matches!(v.data, Some(Data::Decoded(..)));
        (always || (undecoded && !v.bytes.is_empty())).then(|| hex(&v.bytes))
    }

    fn csv(&self, raw: bool) -> Vec<String> {
        let bool_text = |b: bool| if b { "True" } else { "False" }.to_string();
        let v = self.value.as_ref();
        let o = self.opened;
        vec![
            o.source.clone(),
            o.hive_type.clone(),
            self.record_type().to_string(),
            self.key_path.to_string(),
            filetime(self.key_written),
            v.map_or_else(String::new, |v| v.name.clone()),
            v.map_or_else(String::new, |v| type_name(v.kind)),
            v.and_then(|v| match &v.data {
                Some(Data::Decoded(_, text)) => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_default(),
            v.map_or_else(String::new, |v| v.size.to_string()),
            self.raw(raw).unwrap_or_default(),
            bool_text(o.recovery.dirty),
            o.recovery.logs_applied.join("|"),
            self.changed.map_or_else(String::new, bool_text),
            self.problems.join("; "),
        ]
    }

    fn json(&self, raw: bool) -> Value {
        let v = self.value.as_ref();
        let o = self.opened;
        let written = filetime(self.key_written);
        json!({
            "source_file": o.source,
            "hive_type": o.hive_type,
            "record_type": self.record_type(),
            "key_path": self.key_path,
            "key_last_written": (!written.is_empty()).then_some(written),
            "value_name": v.map(|v| &v.name),
            "value_type": v.map(|v| type_name(v.kind)),
            "value_data": v.and_then(|v| match &v.data {
                Some(Data::Decoded(value, _)) => Some(value.clone()),
                _ => None,
            }),
            "data_size": v.map(|v| v.size),
            "value_data_raw": self.raw(raw),
            "hive_dirty": o.recovery.dirty,
            "logs_applied": o.recovery.logs_applied,
            "changed_by_logs": self.changed,
            "problems": self.problems,
        })
    }
}

/// The CSV, JSON or JSONL writer of the output.
enum RecordWriter {
    Csv(Box<csv::Writer<Box<dyn Write>>>, bool),
    Json(Box<dyn Write>, bool, bool),
}

impl RecordWriter {
    /// A writer; a CSV gets its header now, so that it has one also without records.
    fn new(out: Box<dyn Write>, output_type: RegistryOutputType, raw: bool) -> io::Result<Self> {
        Ok(match output_type {
            RegistryOutputType::Csv => {
                let mut w = csv::Writer::from_writer(out);
                w.write_record(CSV_HEADER)?;
                RecordWriter::Csv(Box::new(w), raw)
            }
            RegistryOutputType::Json => RecordWriter::Json(out, true, raw),
            RegistryOutputType::Jsonl => RecordWriter::Json(out, false, raw),
        })
    }

    fn write(&mut self, r: &Record) -> io::Result<()> {
        match self {
            RecordWriter::Csv(w, raw) => w.write_record(r.csv(*raw))?,
            RecordWriter::Json(w, pretty, raw) => {
                // JSON: pretty objects separated by newlines, like the other commands; JSONL: one
                // per line
                if *pretty {
                    serde_json::to_writer_pretty(&mut *w, &r.json(*raw))?;
                } else {
                    serde_json::to_writer(&mut *w, &r.json(*raw))?;
                }
                w.write_all(b"\n")?;
            }
        }
        Ok(())
    }

    fn finish(self) -> io::Result<()> {
        match self {
            RecordWriter::Csv(mut w, _) => w.flush(),
            RecordWriter::Json(mut w, ..) => w.flush(),
        }
    }
}

// --- summary ----------------------------------------------------------------------------------

/// Counts for the results summary.
#[derive(Default)]
struct Stats {
    hives: usize,
    failed: usize,
    types: BTreeMap<String, usize>,
    recovered: usize,
    dirty: Vec<String>,
    without_key: usize,
    keys: usize,
    values: usize,
    records: usize,
    changed: usize,
    first: Option<u64>,
    last: Option<u64>,
    problems: Vec<String>,
    problem_count: usize,
}

impl Stats {
    /// Walk `opened`, writing the records that pass `filters` to `writer` (when there is one).
    fn hive(
        &mut self,
        opened: &Opened,
        filters: &Filters,
        mut writer: Option<&mut RecordWriter>,
    ) -> io::Result<()> {
        self.hives += 1;
        let kind = if opened.hive_type.is_empty() {
            "other"
        } else {
            opened.hive_type.as_str()
        };
        *self.types.entry(kind.to_string()).or_default() += 1;
        if opened.recovery.recovered {
            self.recovered += 1;
        } else if opened.recovery.dirty {
            self.dirty.push(opened.source.clone());
        }
        let Some((start, path)) = filters.start(opened) else {
            self.without_key += 1;
            return Ok(());
        };
        let before = opened.before.as_ref();
        walk(start, path, |key, path, mut problems| {
            self.keys += 1;
            let written = key.last_written();
            let (values, value_problems) = key.values_and_problems();
            problems.extend(value_problems);
            for problem in &problems {
                self.problem(&opened.source, path, problem);
            }
            if !filters.key_matches(path, written) {
                self.values += values.len();
                return Ok(());
            }
            let mut emit = |stats: &mut Self, r: Record| -> io::Result<()> {
                stats.records += 1;
                stats.changed += usize::from(r.changed == Some(true));
                stats.first = Some(stats.first.map_or(written, |f| f.min(written)));
                stats.last = Some(stats.last.map_or(written, |l| l.max(written)));
                match writer.as_deref_mut() {
                    Some(w) => w.write(&r),
                    None => Ok(()),
                }
            };
            if (values.is_empty() || !problems.is_empty()) && !filters.on_values() {
                emit(
                    self,
                    Record {
                        opened,
                        key_path: path,
                        key_written: written,
                        value: None,
                        changed: before.map(|b| b.key_changed(path, written)),
                        problems,
                    },
                )?;
            }
            for value in values {
                self.values += 1;
                let name = value.name();
                let kind = value.data_type();
                let read = value.data();
                let changed = before.map(|b| b.value_changed(path, &name, digest(kind, &read)));
                let (data, bytes, problems) = match read {
                    Ok(bytes) => {
                        let data = decode(kind, &bytes);
                        let problems = match &data {
                            Data::Malformed(why) => vec![why.clone()],
                            _ => Vec::new(),
                        };
                        (Some(data), bytes, problems)
                    }
                    Err(e) => (None, Vec::new(), vec![e]),
                };
                for problem in &problems {
                    self.problem(&opened.source, path, &format!("value {name}: {problem}"));
                }
                let text = match &data {
                    Some(Data::Decoded(_, text)) => text.clone(),
                    _ => hex(&bytes),
                };
                if !filters.value_matches(&name, &text) {
                    continue;
                }
                emit(
                    self,
                    Record {
                        opened,
                        key_path: path,
                        key_written: written,
                        value: Some(ValueRecord {
                            name,
                            kind,
                            size: bytes.len().max(value.size()),
                            data,
                            bytes,
                        }),
                        changed,
                        problems,
                    },
                )?;
            }
            Ok(())
        })
    }

    fn problem(&mut self, source: &str, path: &str, problem: &str) {
        self.problem_count += 1;
        if self.problems.len() < MAX_PRINTED_PROBLEMS {
            let key = if path.is_empty() { "(root)" } else { path };
            self.problems.push(format!("{source}: {key}: {problem}"));
        }
    }

    fn print(&self, filters: &Filters, no_color: bool) {
        p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
        p(None, "", true);
        p_label(no_color, "Registry hives parsed: ", &fmt_num(self.hives));
        if self.failed > 0 {
            p_label(no_color, "Could not parse: ", &fmt_num(self.failed));
        }
        if !self.types.is_empty() {
            let list: Vec<String> = self
                .types
                .iter()
                .map(|(t, n)| format!("{t} {}", fmt_num(*n)))
                .collect();
            p_label(no_color, "Hive types: ", &list.join(", "));
        }
        p_label(
            no_color,
            "Dirty hives recovered with their transaction logs: ",
            &fmt_num(self.recovered),
        );
        if !self.dirty.is_empty() {
            p_label(
                no_color,
                "Dirty hives whose transaction logs were not applied (keys or values may be missing): ",
                &fmt_num(self.dirty.len()),
            );
            for source in self.dirty.iter().take(MAX_PRINTED_PROBLEMS) {
                p(None, &format!("  {source}"), true);
            }
        }
        if self.without_key > 0 {
            p_label(
                no_color,
                "Hives without the key of --key: ",
                &fmt_num(self.without_key),
            );
        }
        p_label(
            no_color,
            "Keys: ",
            &format!("{}, values: {}", fmt_num(self.keys), fmt_num(self.values)),
        );
        let label = if filters.any() {
            "Records matching the filters: "
        } else {
            "Records: "
        };
        let mut records = fmt_num(self.records);
        if self.changed > 0 {
            records.push_str(&format!(
                " (changed by the transaction logs: {})",
                fmt_num(self.changed)
            ));
        }
        p_label(no_color, label, &records);
        if let (Some(first), Some(last)) = (self.first, self.last) {
            let (first, last) = (filetime(first), filetime(last));
            if !first.is_empty() && !last.is_empty() {
                p_label(
                    no_color,
                    "Key last-write times: ",
                    &format!("{first} - {last}"),
                );
            }
        }
        p_label(
            no_color,
            "Damaged keys and values: ",
            &fmt_num(self.problem_count),
        );
        for problem in &self.problems {
            p(None, &format!("  {problem}"), true);
        }
        if self.problem_count > self.problems.len() {
            p(
                None,
                &format!(
                    "  … {} more in the Problems column (-o <FILE>)",
                    fmt_num(self.problem_count - self.problems.len())
                ),
                true,
            );
        }
        p(None, "", true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn decoded(kind: u32, data: &[u8]) -> (Value, String) {
        match decode(kind, data) {
            Data::Decoded(v, t) => (v, t),
            _ => panic!("not decoded"),
        }
    }

    #[test]
    fn values_decode_by_type() {
        assert_eq!(
            decoded(1, &utf16("abc\0junk")),
            (json!("abc"), "abc".into())
        );
        assert_eq!(
            decoded(7, &utf16("a\0b c\0\0")),
            (json!(["a", "b c"]), r#"["a","b c"]"#.into())
        );
        assert_eq!(decoded(7, &utf16("\0")), (json!([]), "[]".into()));
        assert_eq!(decoded(4, &[1, 0, 0, 0]), (json!(1), "1".into()));
        assert_eq!(decoded(5, &[0, 0, 0, 1]), (json!(1), "1".into()));
        assert_eq!(
            decoded(11, &u64::MAX.to_le_bytes()),
            (json!(u64::MAX), "18446744073709551615".into())
        );
        assert_eq!(decoded(3, &[0xab, 1]), (json!("ab01"), "ab01".into()));
        assert!(matches!(decode(4, &[1, 2, 3]), Data::Malformed(m) if m == "REG_DWORD of 3 bytes"));
        assert!(matches!(decode(11, &[]), Data::Malformed(_)));
        assert!(matches!(decode(0x0020_0000, &[1]), Data::Bytes));
        assert_eq!(type_name(7), "REG_MULTI_SZ");
        assert_eq!(type_name(0x0020_0000), "0x200000");
    }

    #[test]
    fn hive_files_and_logs() {
        let dir = tempfile::tempdir().unwrap();
        let mut hive = vec![0u8; 4096];
        hive[..4].copy_from_slice(b"regf");
        std::fs::write(dir.path().join("NTUSER.DAT"), &hive).unwrap();
        std::fs::write(dir.path().join("NTUSER.DAT.LOG1"), &hive).unwrap();
        hive[28] = 1;
        std::fs::write(dir.path().join("renamed_log"), &hive).unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"not a hive").unwrap();
        let found = find_hives(dir.path());
        assert_eq!(found, [dir.path().join("NTUSER.DAT")]);
    }
}
