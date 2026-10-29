//! `parse-defender-quarantine`: Microsoft Defender's quarantine
//! (`ProgramData\Microsoft\Windows Defender\Quarantine`) with Yamato Security's
//! ys-defender-history-parser: every quarantine entry's threat, scan and time and every resource
//! it quarantined (files, registry keys, services, startup items, scheduled tasks), each matched
//! with its content (`ResourceData`) and resource record (`Resources`) and checked (sizes, CRCs,
//! the content's SHA-1), with the quarantined file's hashes, owner and download origin; contents
//! and records no entry holds are reported too. One record per resource, as CSV, JSON or JSONL,
//! with Hayabusa's input options, progress bar and results summary. With `--extract`, the
//! quarantined files are written out, named by their SHA-1, without execute permission. Nothing
//! is ever run.

use crate::cli::{DefenderQuarantineOptions, DefenderQuarantineOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use defender::quarantine::{
    Hashes, Resource, ResourceData, ResourceRecord, detect, hashes, read_entry, read_resource_data,
    read_resource_record,
};
use defender::{Time, Value};
use indicatif::ProgressBar;
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// Parse errors printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// Threats listed in the summary.
const MAX_PRINTED_THREATS: usize = 10;
/// Larger contents are not read: neither hashed nor extracted.
const MAX_CONTENT_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Larger files are not quarantine entries or resource records.
const MAX_METADATA_SIZE: u64 = 64 * 1024 * 1024;

/// What `--extract` warns before it writes anything.
const EXTRACT_WARNING: &str = "WARNING: --extract writes the files Defender quarantined to disk. \
They are likely malware: never run them, keep them on an isolated analysis system, and expect \
antivirus software to remove them. They are named by their SHA-1 and created without execute \
permission.";

/// Run the command; returns the exit status.
pub fn run(opts: &DefenderQuarantineOptions) -> i32 {
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
    let (folders, whole) = match (&opts.filepath, &opts.directory) {
        (Some(f), _) => {
            if !f.is_file() {
                report_error(None, &format!("The file does not exist: {}", f.display()));
                return 1;
            }
            (vec![folder_of_entry(f)], false)
        }
        (None, Some(d)) => {
            if !d.is_dir() {
                report_error(
                    None,
                    &format!("The directory does not exist: {}", d.display()),
                );
                return 1;
            }
            let found = find_folders(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!(
                        "No Defender quarantine folders were found in {}",
                        d.display()
                    ),
                );
                return 1;
            }
            (found, true)
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, false, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }
    let mut extractor = match &opts.extract {
        Some(dir) => {
            if dir.is_file() {
                report_error(
                    None,
                    &format!("{} is a file, not a directory.", dir.display()),
                );
                return 1;
            }
            if let Err(e) = std::fs::create_dir_all(dir) {
                report_error(None, &format!("Could not create {}: {e}", dir.display()));
                return 1;
            }
            if data_on_stdout {
                eprintln!("{EXTRACT_WARNING}");
            } else {
                p(JunteiColor::Red.rdg(no_color), EXTRACT_WARNING, true);
                p(None, "", true);
            }
            Some(Extractor::new(dir, opts.clobber))
        }
        None => None,
    };
    let entries: usize = folders.iter().map(|f| f.entries.len()).sum();
    if !data_on_stdout {
        p_label(no_color, "Quarantine folders: ", &fmt_num(folders.len()));
        p_label(no_color, "Quarantine entries: ", &fmt_num(entries));
        p(None, "", true);
    }
    let bar = (!data_on_stdout).then(|| {
        p(
            JunteiColor::Orange.rdg(no_color),
            "Parsing in progress. Please wait.",
            true,
        );
        p(None, "", true);
        progress::progress_bar(entries, no_color)
    });

    // --- parse -----------------------------------------------------------------------------
    let mut records = Vec::new();
    let mut read = 0usize;
    let mut failed = 0usize;
    for folder in &folders {
        let mut reader = Reader::new(folder, extractor.as_mut());
        for path in &folder.entries {
            if let Some(b) = &bar {
                b.set_message(progress::message(path));
            }
            match reader.entry(path) {
                Ok(mut found) => {
                    read += 1;
                    records.append(&mut found);
                }
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
        if whole {
            records.append(&mut reader.orphans());
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
        && let Err(e) = write_records(sink, opts.output_type(), &records)
    {
        report_error(None, &format!("Could not write the records: {e}"));
        return 1;
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(
            &folders,
            &records,
            read,
            failed,
            extractor.as_ref(),
            no_color,
        );
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
    i32::from(read == 0)
}

/// A quarantine folder: its entries, and its contents and resource records by name.
struct Folder {
    root: PathBuf,
    entries: Vec<PathBuf>,
    /// `ResourceData\<xx>\<ID>`, by ID (upper case).
    contents: BTreeMap<String, PathBuf>,
    /// `Resources\<xx>\<ID>`, by ID (upper case).
    records: BTreeMap<String, PathBuf>,
}

/// The child of `dir` named `name`, whatever its case.
fn child(dir: &Path, name: &str) -> Option<PathBuf> {
    dir.read_dir()
        .ok()?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|e| e.path())
}

fn is_dir_named(path: &Path, name: &str) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(name))
        && path.is_dir()
}

/// The files of `<root>\<sub>\<xx>\<ID>`, by ID.
fn by_name(root: &Path, sub: &str) -> BTreeMap<String, PathBuf> {
    let Some(dir) = child(root, sub) else {
        return BTreeMap::new();
    };
    util::find_files(&dir, |_| true)
        .into_iter()
        .filter_map(|p| Some((p.file_name()?.to_string_lossy().to_ascii_uppercase(), p)))
        .collect()
}

fn folder(root: &Path, entries: Vec<PathBuf>) -> Folder {
    Folder {
        root: root.to_path_buf(),
        entries,
        contents: by_name(root, "ResourceData"),
        records: by_name(root, "Resources"),
    }
}

/// The folder of one entry file: `<root>\Entries\{GUID}`.
fn folder_of_entry(file: &Path) -> Folder {
    let parent = file.parent().unwrap_or(Path::new("."));
    let root = if is_dir_named(parent, "Entries") {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };
    folder(root, vec![file.to_path_buf()])
}

/// Whether a file starts like a quarantine entry.
fn starts_like_entry(path: &Path) -> bool {
    let mut head = [0u8; 60];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| detect(&head))
}

/// The quarantine folders under `dir`: those holding an `Entries` folder with an entry in it.
fn find_folders(dir: &Path) -> Vec<Folder> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(children) = d.read_dir() else {
            continue;
        };
        for e in children.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(e.path());
            }
        }
        if let Some(entries) = child(&d, "Entries").filter(|p| p.is_dir()) {
            let files: Vec<PathBuf> = util::find_files(&entries, |_| true);
            if files.iter().any(|f| starts_like_entry(f)) {
                found.push(folder(&d, files));
            }
        }
    }
    found.sort_by(|a, b| a.root.cmp(&b.root));
    found
}

/// What a content holds, read once.
#[derive(Clone, Default)]
struct Content {
    file: String,
    id: Option<String>,
    hive: bool,
    /// Its streams: kind, name, size.
    streams: Vec<(String, String, usize)>,
    size: Option<usize>,
    hashes: Option<Hashes>,
    owner: Option<String>,
    zone: Vec<(String, String)>,
    /// The size of its file, as a resource record gives it.
    file_size: u64,
    extracted: Option<String>,
    problems: Vec<String>,
}

/// One record to write.
#[derive(Default)]
struct Record {
    /// `resource`, `entry` (one without resources), `orphan-content` or `orphan-record`.
    kind: &'static str,
    folder: String,
    entry_file: Option<String>,
    entry_id: Option<String>,
    scan_id: Option<String>,
    time: Option<Time>,
    threat_id: Option<u64>,
    threat_name: Option<String>,
    resource: Option<Resource>,
    content: Option<Content>,
    record_file: Option<String>,
    record_entries: Vec<String>,
    problems: Vec<String>,
}

/// Reads a folder's entries, matching each resource with its content and record.
struct Reader<'a> {
    folder: &'a Folder,
    extractor: Option<&'a mut Extractor>,
    contents: HashMap<String, Content>,
    records: HashMap<String, Result<ResourceRecord, String>>,
    /// Entries read (their identifiers), and the contents and records they hold.
    entry_ids: BTreeSet<String>,
    held: BTreeSet<String>,
}

impl<'a> Reader<'a> {
    fn new(folder: &'a Folder, extractor: Option<&'a mut Extractor>) -> Self {
        Self {
            folder,
            extractor,
            contents: HashMap::new(),
            records: HashMap::new(),
            entry_ids: BTreeSet::new(),
            held: BTreeSet::new(),
        }
    }

    /// An entry's records: one per resource, or one for the entry when it has none.
    fn entry(&mut self, path: &Path) -> Result<Vec<Record>, String> {
        let size = path.metadata().map_err(|e| e.to_string())?.len();
        if size > MAX_METADATA_SIZE {
            return Err(format!("too large for a quarantine entry ({size} bytes)"));
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let entry = read_entry(&data).map_err(|e| e.to_string())?;
        let mut problems = entry.problems.clone();
        let name = path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .trim_matches(['{', '}'])
                    .to_ascii_uppercase()
            })
            .unwrap_or_default();
        if let Some(id) = &entry.id {
            if *id != name {
                problems.push(format!("its identifier ({id}) isn't its file's name"));
            }
            self.entry_ids.insert(id.clone());
        }
        let base = Record {
            kind: "entry",
            folder: self.folder.root.display().to_string(),
            entry_file: Some(path.display().to_string()),
            entry_id: entry.id.clone(),
            scan_id: entry.scan_id.clone(),
            time: entry.time,
            threat_id: entry.threat_id,
            threat_name: entry.threat_name.clone(),
            problems,
            ..Record::default()
        };
        if entry.resources.is_empty() {
            return Ok(vec![base]);
        }
        let mut out = Vec::new();
        for resource in entry.resources {
            let mut record = Record {
                kind: "resource",
                folder: base.folder.clone(),
                entry_file: base.entry_file.clone(),
                entry_id: base.entry_id.clone(),
                scan_id: base.scan_id.clone(),
                time: base.time,
                threat_id: base.threat_id,
                threat_name: base.threat_name.clone(),
                problems: base.problems.clone(),
                ..Record::default()
            };
            if let Some(id) = resource.resource_id() {
                self.held.insert(id.clone());
                self.match_content(&id, &resource, entry.id.as_deref(), &mut record);
            }
            record.resource = Some(resource);
            out.push(record);
        }
        Ok(out)
    }

    /// Match a resource with its content and its record.
    fn match_content(
        &mut self,
        id: &str,
        resource: &Resource,
        entry_id: Option<&str>,
        record: &mut Record,
    ) {
        match self.content(id) {
            Some(content) => {
                record
                    .problems
                    .extend(content.problems.iter().map(|p| format!("content: {p}")));
                if let (Some(said), Some(size), false) =
                    (resource.size(), content.size, content.hive)
                    && said != size as u64
                {
                    record.problems.push(format!(
                        "content: {size} bytes of data, the entry says {said}"
                    ));
                }
                record.content = Some(content);
            }
            None => record.problems.push(format!(
                "its content isn't there (ResourceData\\{}\\{id})",
                &id[..2.min(id.len())]
            )),
        }
        if let Some(path) = self.folder.records.get(id).cloned() {
            record.record_file = Some(path.display().to_string());
            match self.record(id, &path) {
                Ok(read) => {
                    record.problems.extend(
                        read.problems
                            .iter()
                            .map(|p| format!("resource record: {p}")),
                    );
                    if let Some(entry_id) = entry_id
                        && !read.entries.iter().any(|e| e == entry_id)
                    {
                        record
                            .problems
                            .push("resource record: doesn't list this entry".to_owned());
                    }
                    if let (Some(said), Some(content)) = (read.data_size, &record.content)
                        && said != content.file_size
                    {
                        record.problems.push(format!(
                            "resource record: a content of {said} bytes, its file {}",
                            content.file_size
                        ));
                    }
                    record.record_entries.clone_from(&read.entries);
                }
                Err(e) => record.problems.push(format!("resource record: {e}")),
            }
        }
    }

    /// A content by its identifier, read (and extracted) once.
    fn content(&mut self, id: &str) -> Option<Content> {
        if let Some(found) = self.contents.get(id) {
            return Some(found.clone());
        }
        let path = self.folder.contents.get(id)?.clone();
        let content = read_content(&path, id, self.extractor.as_deref_mut());
        self.contents.insert(id.to_owned(), content.clone());
        Some(content)
    }

    fn record(&mut self, id: &str, path: &Path) -> Result<ResourceRecord, String> {
        self.records
            .entry(id.to_owned())
            .or_insert_with(|| {
                let size = path.metadata().map_err(|e| e.to_string())?.len();
                if size > MAX_METADATA_SIZE {
                    return Err(format!("too large for a resource record ({size} bytes)"));
                }
                let data = std::fs::read(path).map_err(|e| e.to_string())?;
                read_resource_record(&data).map_err(|e| e.to_string())
            })
            .clone()
    }

    /// The contents and records no entry holds, and records listing entries that aren't there.
    fn orphans(&mut self) -> Vec<Record> {
        let mut out = Vec::new();
        let folder = self.folder;
        for (id, path) in &folder.contents {
            if self.held.contains(id) {
                continue;
            }
            let mut record = Record {
                kind: "orphan-content",
                folder: folder.root.display().to_string(),
                problems: vec!["no entry holds this content".to_owned()],
                ..Record::default()
            };
            if let Some(content) = self.content(id) {
                record
                    .problems
                    .extend(content.problems.iter().map(|p| format!("content: {p}")));
                record.content = Some(content);
            }
            if let Some(record_path) = folder.records.get(id) {
                record.record_file = Some(record_path.display().to_string());
                if let Ok(read) = self.record(id, record_path) {
                    record.record_entries = read.entries;
                }
            }
            debug_assert!(!path.as_os_str().is_empty());
            out.push(record);
        }
        for (id, path) in &folder.records {
            if self.held.contains(id) || folder.contents.contains_key(id) {
                continue;
            }
            let mut record = Record {
                kind: "orphan-record",
                folder: folder.root.display().to_string(),
                record_file: Some(path.display().to_string()),
                problems: vec![
                    "no entry holds this resource record, nor is its content there".to_owned(),
                ],
                ..Record::default()
            };
            match self.record(id, path) {
                Ok(read) => {
                    record.problems.extend(
                        read.problems
                            .iter()
                            .map(|p| format!("resource record: {p}")),
                    );
                    record.record_entries = read.entries;
                }
                Err(e) => record.problems.push(format!("resource record: {e}")),
            }
            out.push(record);
        }
        // records naming entries that aren't in the folder
        for record in &mut out {
            let missing: Vec<&String> = record
                .record_entries
                .iter()
                .filter(|e| !self.entry_ids.contains(*e))
                .collect();
            if !missing.is_empty() {
                record.problems.push(format!(
                    "resource record: lists entries not there ({})",
                    join(missing)
                ));
            }
        }
        out
    }
}

fn join<T: AsRef<str>>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|s| s.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read a content (decrypted in memory, never run): its streams, hashes, owner and download
/// origin, its SHA-1 checked against its name; extracted when asked.
fn read_content(path: &Path, name: &str, extractor: Option<&mut Extractor>) -> Content {
    let mut content = Content {
        file: path.display().to_string(),
        ..Content::default()
    };
    let size = match path.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            content.problems.push(e.to_string());
            return content;
        }
    };
    content.file_size = size;
    if size > MAX_CONTENT_SIZE {
        content
            .problems
            .push(format!("too large to read ({size} bytes)"));
        return content;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            content.problems.push(e.to_string());
            return content;
        }
    };
    let read = read_resource_data(&data);
    drop(data);
    content.problems.clone_from(&read.problems);
    if read.id != name {
        content.problems.push(format!(
            "its SHA-1 ({}) isn't its file's name: changed or damaged",
            read.id
        ));
    }
    content.id = Some(read.id.clone());
    content.hive = read.hive;
    content.streams = read
        .streams
        .iter()
        .map(|s| {
            (
                s.kind_name().unwrap_or("Unknown").to_owned(),
                s.name.clone(),
                s.range.len(),
            )
        })
        .collect();
    if let Some(file) = read.file_data() {
        content.size = Some(file.len());
        content.hashes = Some(hashes(file));
    }
    content.owner = read.owner();
    content.zone = read.zone_identifier();
    if let Some(extractor) = extractor {
        let (written, problems) = extractor.extract(&read);
        content.extracted = written;
        content.problems.extend(problems);
    }
    content
}

/// Writes quarantined content: named by its SHA-1, without execute permission, never over a file
/// holding something else unless asked.
struct Extractor {
    dir: PathBuf,
    clobber: bool,
    written: usize,
    already: usize,
    refused: usize,
}

impl Extractor {
    fn new(dir: &Path, clobber: bool) -> Self {
        Self {
            dir: dir.to_path_buf(),
            clobber,
            written: 0,
            already: 0,
            refused: 0,
        }
    }

    /// Write a content's file (`<SHA-1>.bin`, or `<SHA-1>.hive`) and its other streams beside
    /// it (`<SHA-1>.security`, `<SHA-1>.Zone.Identifier`, …); the first's path, and problems.
    fn extract(&mut self, data: &ResourceData) -> (Option<String>, Vec<String>) {
        let mut problems = Vec::new();
        let mut first = None;
        let mut files: Vec<(String, &[u8])> = Vec::new();
        if data.hive {
            files.push((format!("{}.hive", data.id), &data.content));
        } else {
            for stream in &data.streams {
                let suffix = match stream.kind {
                    1 if !files.iter().any(|(n, _)| n.ends_with(".bin")) => "bin".to_owned(),
                    3 => "security".to_owned(),
                    4 => stream_name(&stream.name),
                    _ => stream.kind_name().unwrap_or("stream").to_ascii_lowercase(),
                };
                let mut name = format!("{}.{suffix}", data.id);
                let mut n = 1;
                while files.iter().any(|(f, _)| *f == name) {
                    n += 1;
                    name = format!("{}.{suffix}.{n}", data.id);
                }
                files.push((name, data.stream_data(stream)));
            }
        }
        for (name, bytes) in files {
            let path = self.dir.join(&name);
            match self.write(&path, bytes) {
                Ok(()) => {
                    if first.is_none() {
                        first = Some(path.display().to_string());
                    }
                }
                Err(e) => problems.push(e),
            }
        }
        (first, problems)
    }

    fn write(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        if path.exists() {
            if std::fs::read(path).is_ok_and(|have| have == bytes) {
                self.already += 1;
                return Ok(());
            }
            if !self.clobber {
                self.refused += 1;
                return Err(format!(
                    "{} holds something else: not overwritten (add -C to overwrite)",
                    path.display()
                ));
            }
        }
        write_private(path, bytes)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        self.written += 1;
        Ok(())
    }
}

/// Write a file readable and writable by its owner alone, never executable.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        // a file overwritten keeps its permissions: take execute away
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// An alternate data stream's name for a file name: `:Zone.Identifier:$DATA` → `Zone.Identifier`.
fn stream_name(name: &str) -> String {
    let name = name.strip_suffix("$DATA").unwrap_or(name).trim_matches(':');
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = safe.trim_matches('.');
    if safe.is_empty() {
        "stream".to_owned()
    } else {
        safe.to_owned()
    }
}

const CSV_HEADER: [&str; 30] = [
    "Record",
    "QuarantineTime",
    "ThreatName",
    "ThreatId",
    "ResourceType",
    "Path",
    "PhysicalPath",
    "FileSize",
    "CreationTime",
    "LastAccessTime",
    "LastWriteTime",
    "Attributes",
    "Owner",
    "ZoneId",
    "ReferrerUrl",
    "HostUrl",
    "ContentSize",
    "MD5",
    "SHA1",
    "SHA256",
    "Streams",
    "ResourceId",
    "EntryId",
    "ScanId",
    "QuarantineFolder",
    "EntryFile",
    "ContentFile",
    "ResourceRecordFile",
    "ExtractedFile",
    "Problems",
];

fn time(t: Option<Time>) -> String {
    t.map(Time::to_iso8601).unwrap_or_default()
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn zone(content: Option<&Content>, key: &str) -> String {
    content
        .and_then(|c| c.zone.iter().find(|(k, _)| k == key))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn streams_text(content: Option<&Content>) -> String {
    content.map_or_else(String::new, |c| {
        if c.hive {
            return "Hive".to_owned();
        }
        join(c.streams.iter().map(|(kind, name, _)| {
            if name.is_empty() {
                kind.clone()
            } else {
                format!("{kind} {name}")
            }
        }))
    })
}

fn csv_row(r: &Record) -> Vec<String> {
    let res = r.resource.as_ref();
    let c = r.content.as_ref();
    let times = res.map_or([None; 3], Resource::times);
    let h = c.and_then(|c| c.hashes.as_ref());
    vec![
        r.kind.to_owned(),
        time(r.time),
        r.threat_name.clone().unwrap_or_default(),
        opt(r.threat_id),
        res.map(|x| x.kind.clone()).unwrap_or_default(),
        res.map(|x| x.path.clone()).unwrap_or_default(),
        opt(res.and_then(Resource::physical_path)),
        opt(res.and_then(Resource::size)),
        time(times[0]),
        time(times[1]),
        time(times[2]),
        res.and_then(Resource::flags)
            .map_or_else(String::new, |f| format!("0x{f:x}")),
        opt(c.and_then(|c| c.owner.clone())),
        zone(c, "ZoneId"),
        zone(c, "ReferrerUrl"),
        zone(c, "HostUrl"),
        opt(c.and_then(|c| c.size)),
        opt(h.map(|h| h.md5.clone())),
        opt(h.map(|h| h.sha1.clone())),
        opt(h.map(|h| h.sha256.clone())),
        streams_text(c),
        res.and_then(Resource::resource_id)
            .or_else(|| c.and_then(|c| c.id.clone()))
            .unwrap_or_default(),
        r.entry_id.clone().unwrap_or_default(),
        r.scan_id.clone().unwrap_or_default(),
        r.folder.clone(),
        r.entry_file.clone().unwrap_or_default(),
        opt(c.map(|c| c.file.clone())),
        r.record_file.clone().unwrap_or_default(),
        opt(c.and_then(|c| c.extracted.clone())),
        r.problems.join("; "),
    ]
}

fn field_value(v: &Value) -> Json {
    match v {
        Value::Integer(n) => json!(n),
        Value::Signed(n) => json!(n),
        Value::Text(t) | Value::Guid(t) => json!(t),
        Value::Bool(b) => json!(b),
        Value::Time(_) | Value::Bytes(_) => json!(v.to_string()),
    }
}

fn json_record(r: &Record) -> Json {
    let res = r.resource.as_ref();
    let c = r.content.as_ref();
    let times = res.map_or([None; 3], Resource::times);
    let t = |x: Option<Time>| x.map_or(Json::Null, |x| json!(x.to_iso8601()));
    let fields: Vec<Json> = res.map_or_else(Vec::new, |x| {
        x.fields
            .iter()
            .map(|f| {
                json!({
                    "id": format!("0x{:x}", f.id),
                    "type": f.kind,
                    "name": f.name(),
                    "value": field_value(&f.value),
                })
            })
            .collect()
    });
    let content = c.map(|c| {
        json!({
            "file": c.file,
            "sha1_of_content": c.id,
            "hive": c.hive,
            "streams": c.streams.iter().map(|(kind, name, size)| json!({"kind": kind, "name": name, "size": size})).collect::<Vec<_>>(),
            "size": c.size,
            "md5": c.hashes.as_ref().map(|h| h.md5.clone()),
            "sha1": c.hashes.as_ref().map(|h| h.sha1.clone()),
            "sha256": c.hashes.as_ref().map(|h| h.sha256.clone()),
            "owner": c.owner,
            "zone_identifier": c.zone.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<serde_json::Map<_, _>>(),
            "extracted_file": c.extracted,
        })
    });
    json!({
        "record": r.kind,
        "quarantine_folder": r.folder,
        "entry_file": r.entry_file,
        "entry_id": r.entry_id,
        "scan_id": r.scan_id,
        "quarantine_time": t(r.time),
        "threat_id": r.threat_id,
        "threat_name": r.threat_name,
        "resource_type": res.map(|x| x.kind.clone()),
        "path": res.map(|x| x.path.clone()),
        "physical_path": res.and_then(Resource::physical_path),
        "resource_id": res.and_then(Resource::resource_id),
        "file_size": res.and_then(Resource::size),
        "creation_time": t(times[0]),
        "last_access_time": t(times[1]),
        "last_write_time": t(times[2]),
        "attributes": res.and_then(Resource::flags),
        "fields": fields,
        "content": content,
        "resource_record_file": r.record_file,
        "resource_record_entries": r.record_entries,
        "problems": r.problems,
    })
}

fn write_records(
    mut w: Box<dyn Write>,
    output_type: DefenderQuarantineOutputType,
    records: &[Record],
) -> io::Result<()> {
    if output_type == DefenderQuarantineOutputType::Csv {
        let mut csv = csv::Writer::from_writer(w);
        csv.write_record(CSV_HEADER)?;
        for r in records {
            csv.write_record(csv_row(r))?;
        }
        return csv.flush();
    }
    for r in records {
        let v = json_record(r);
        // JSON: pretty objects separated by newlines, like parse-mft; JSONL: one per line
        if output_type == DefenderQuarantineOutputType::Json {
            serde_json::to_writer_pretty(&mut w, &v)?;
        } else {
            serde_json::to_writer(&mut w, &v)?;
        }
        w.write_all(b"\n")?;
    }
    w.flush()
}

fn print_summary(
    folders: &[Folder],
    records: &[Record],
    read: usize,
    failed: usize,
    extractor: Option<&Extractor>,
    no_color: bool,
) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    p_label(no_color, "Quarantine folders: ", &fmt_num(folders.len()));
    p_label(no_color, "Quarantine entries parsed: ", &fmt_num(read));
    if failed > 0 {
        p_label(no_color, "Could not parse: ", &fmt_num(failed));
    }
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for r in records.iter().filter_map(|r| r.resource.as_ref()) {
        *kinds.entry(r.kind.as_str()).or_default() += 1;
    }
    let total: usize = kinds.values().sum();
    let detail = join(kinds.iter().map(|(k, n)| format!("{k}: {}", fmt_num(*n))));
    p_label(
        no_color,
        "Resources quarantined: ",
        &if total == 0 {
            "0".to_owned()
        } else {
            format!("{} ({detail})", fmt_num(total))
        },
    );
    let missing = records
        .iter()
        .filter(|r| {
            r.problems
                .iter()
                .any(|p| p.starts_with("its content isn't there"))
        })
        .count();
    let orphans = records
        .iter()
        .filter(|r| r.kind.starts_with("orphan"))
        .count();
    let with_problems = records.iter().filter(|r| !r.problems.is_empty()).count();
    if missing > 0 {
        p_label(no_color, "Contents missing: ", &fmt_num(missing));
    }
    if orphans > 0 {
        p_label(
            no_color,
            "Contents or records no entry holds: ",
            &fmt_num(orphans),
        );
    }
    if with_problems > 0 {
        p_label(no_color, "Records with problems: ", &fmt_num(with_problems));
    }
    if let Some(x) = extractor {
        let mut text = format!("{} to {}", fmt_num(x.written), x.dir.display());
        if x.already > 0 {
            text.push_str(&format!(", {} already there", fmt_num(x.already)));
        }
        if x.refused > 0 {
            text.push_str(&format!(
                ", {} not overwritten (add -C to overwrite)",
                fmt_num(x.refused)
            ));
        }
        p_label(no_color, "Files extracted: ", &text);
    }
    // threats: one per entry, the most quarantined first
    let mut threats: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in records {
        if let (Some(name), Some(entry)) = (&r.threat_name, &r.entry_file) {
            threats
                .entry(name.as_str())
                .or_default()
                .insert(entry.as_str());
        }
    }
    if !threats.is_empty() {
        p(None, "", true);
        p(
            JunteiColor::Orange.rdg(no_color),
            "Threats quarantined:",
            true,
        );
        let mut list: Vec<(&str, usize)> = threats.iter().map(|(k, v)| (*k, v.len())).collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        for (name, n) in list.iter().take(MAX_PRINTED_THREATS) {
            p(None, &format!("  {name} ({})", fmt_num(*n)), true);
        }
        if list.len() > MAX_PRINTED_THREATS {
            p(
                None,
                &format!("  … and {} more", fmt_num(list.len() - MAX_PRINTED_THREATS)),
                true,
            );
        }
    }
    p(None, "", true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_names_are_safe_file_names() {
        assert_eq!(stream_name(":Zone.Identifier:$DATA"), "Zone.Identifier");
        assert_eq!(stream_name(":../../evil:$DATA"), "_.._evil");
        assert_eq!(stream_name("::$DATA"), "stream");
        assert_eq!(stream_name(":a b/c\\d:$DATA"), "a_b_c_d");
    }
}
