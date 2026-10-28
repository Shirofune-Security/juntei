//! `parse-jump-lists`: Windows jump lists with Yamato Security's ys-jump-lists-parser (from
//! sootmark-shell's jump list and compound file code, with links read by ys-lnk-parser). An
//! automatic jump list (`*.automaticDestinations-ms`) is Windows' own record of what an
//! application opened: each entry's last use, interaction count, pin, the machine and tracker
//! identifiers of the target, its path and its link. A custom jump list
//! (`*.customDestinations-ms`) is the application's own menu: its categories, tasks and links.
//! Written as Eric Zimmerman's JLECmd's two CSV tables and more, or every field as JSON / JSONL,
//! with Hayabusa's input options, progress bar and results summary. The summary flags links left
//! over from an earlier version of a custom list, streams no `DestList` entry names, items staged
//! for a CD or DVD burn, and shells or script hosts started with arguments.

use crate::cli::{JumpListOptions, JumpListOutputType};
use crate::color::JunteiColor;
use crate::lnk::{
    attributes, block_names, drive_type, droid, filetime, flags, launches, link_json, link_target,
    properties_json, system_time, target_mft,
};
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use indicatif::ProgressBar;
use jumplist::{Automatic, Custom, Destination, JumpList, Kind};
use serde_json::{Value, json};
use shell::item::Kind as ItemKind;
use shell::lnk::Link;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Parse errors and jump list problems printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// Items listed per finding in the summary.
const MAX_PRINTED_FINDINGS: usize = 10;
/// Applications listed in the summary.
const MAX_PRINTED_APPS: usize = 5;
/// Larger files are not jump lists (Windows keeps a few hundred entries per application).
const MAX_JUMP_LIST_SIZE: u64 = 256 * 1024 * 1024;
const AUTOMATIC_SUFFIX: &str = ".automaticdestinations-ms";
const CUSTOM_SUFFIX: &str = ".customdestinations-ms";
/// JLECmd's note on a link stream no `DestList` entry names.
const UNLISTED_NOTE: &str = "Found in Directory, not DestList";

/// Run the command; returns the exit status.
pub fn run(opts: &JumpListOptions) -> i32 {
    let no_color = opts.common.no_color;
    let data_on_stdout = opts.data_on_stdout();
    let output_type = opts.output_type();
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
            let found = find_jump_lists(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!(
                        "No jump lists (*.automaticDestinations-ms, *.customDestinations-ms) were found in {}",
                        d.display()
                    ),
                );
                return 1;
            }
            found
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if !shell::codepage::is_supported(opts.code_page) {
        report_error(
            None,
            &format!(
                "Code page {} is not supported (ex: 1252 Western European, 932 Japanese, 936 Simplified Chinese).",
                opts.code_page
            ),
        );
        return 1;
    }
    // CSV tables go to a directory, JSON / JSONL to a file.
    let out_is_dir = output_type == JumpListOutputType::Csv;
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, out_is_dir, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }
    if !data_on_stdout {
        let total: u64 = files
            .iter()
            .map(|p| p.metadata().map_or(0, |m| m.len()))
            .sum();
        p_label(no_color, "Jump lists: ", &fmt_num(files.len()));
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
    let options = jumplist::Options {
        code_page: opts.code_page,
    };
    let mut parsed = Vec::new();
    let mut failed = 0usize;
    let mut printed = 0usize;
    for path in &files {
        if let Some(b) = &bar {
            b.set_message(progress::message(path));
        }
        match parse_file(path, &options) {
            Ok(record) => {
                for problem in record.problems() {
                    printed += 1;
                    if printed <= MAX_PRINTED_ERRORS {
                        report_error(bar.as_ref(), &format!("{}: {problem}", record.source));
                    }
                }
                parsed.push(record);
            }
            Err(e) => {
                failed += 1;
                printed += 1;
                if printed <= MAX_PRINTED_ERRORS {
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
    if printed > MAX_PRINTED_ERRORS {
        report_error(
            bar.as_ref(),
            &format!(
                "{} more problems and files that could not be parsed",
                fmt_num(printed - MAX_PRINTED_ERRORS)
            ),
        );
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- write -----------------------------------------------------------------------------
    let written = match (&opts.output, output_type) {
        (Some(dir), JumpListOutputType::Csv) => write_csv_tables(dir, &parsed),
        (Some(path), _) => create_parent(path).and_then(|()| {
            write_json(
                Box::new(BufWriter::new(File::create(path)?)),
                output_type,
                &parsed,
            )
        }),
        (None, JumpListOutputType::Json | JumpListOutputType::Jsonl) => {
            write_json(Box::new(BufWriter::new(io::stdout())), output_type, &parsed)
        }
        (None, JumpListOutputType::Csv) => Ok(()),
    };
    if let Err(e) = written {
        report_error(None, &format!("Could not write the records: {e}"));
        return 1;
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&parsed, failed, no_color);
        if let Some(out) = &opts.output {
            let value = if out_is_dir {
                format!("{} (2 CSV files)", out.display())
            } else {
                format!("{} ({})", out.display(), util::file_size_display(out))
            };
            p_label(no_color, "Results saved: ", &value);
        } else {
            p(
                None,
                "To save every entry, add -o <DIR> (CSV tables) or -o <FILE> -t json or jsonl.",
                true,
            );
        }
    }
    i32::from(parsed.is_empty())
}

/// One parsed jump list.
struct Parsed {
    source: String,
    /// The file's own times on the file system (created, modified, accessed).
    source_times: [Option<SystemTime>; 3],
    /// The AppID its name starts with (empty when it doesn't), and the application's name.
    app_id: String,
    app_name: Option<&'static str>,
    list: JumpList,
}

impl Parsed {
    fn problems(&self) -> &[String] {
        match &self.list {
            JumpList::Automatic(a) => &a.problems,
            JumpList::Custom(c) => &c.problems,
        }
    }

    /// Every link it holds, with what it is: a `DestList` entry's, an unlisted stream's, a
    /// category's or a leftover.
    fn links(&self) -> Vec<(String, &Link)> {
        match &self.list {
            JumpList::Automatic(a) => a
                .destinations
                .iter()
                .filter_map(|d| d.link.as_ref().map(|l| (format!("entry {:X}", d.entry), l)))
                .chain(a.unlisted.iter().filter_map(|u| {
                    u.link
                        .as_ref()
                        .map(|l| (format!("unlisted stream {}", u.name), l))
                }))
                .collect(),
            JumpList::Custom(c) => c
                .links()
                .map(|(category, l)| (category.kind.name(), l))
                .chain(
                    c.leftover
                        .iter()
                        .map(|o| (format!("left over at {}", o.offset), &o.link)),
                )
                .collect(),
        }
    }
}

fn parse_file(path: &Path, options: &jumplist::Options) -> Result<Parsed, String> {
    let meta = path.metadata().map_err(|e| e.to_string())?;
    if meta.len() > MAX_JUMP_LIST_SIZE {
        return Err(format!("too large for a jump list ({} bytes)", meta.len()));
    }
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let list = parse_data(&name, &data, options)?;
    let app_id = jumplist::appid::app_id(&name).unwrap_or_default();
    Ok(Parsed {
        source: path.to_string_lossy().to_string(),
        source_times: [
            meta.created().ok(),
            meta.modified().ok(),
            meta.accessed().ok(),
        ],
        app_name: jumplist::appid::app_name(&app_id),
        app_id,
        list,
    })
}

/// A jump list of the kind its name says, else of the kind its contents are (a compound file is
/// an automatic one). A custom list that isn't one (another format version, no category read)
/// is an error.
fn parse_data(name: &str, data: &[u8], options: &jumplist::Options) -> Result<JumpList, String> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(AUTOMATIC_SUFFIX)
        || (!lower.ends_with(CUSTOM_SUFFIX) && jumplist::compound::is_compound(data))
    {
        return jumplist::automatic_with(data, options)
            .map(JumpList::Automatic)
            .map_err(|e| e.to_string());
    }
    let list = jumplist::custom_with(data, options);
    if list.version != 2 && list.categories.is_empty() {
        return Err(format!(
            "not a custom jump list ({})",
            list.problems.join("; ")
        ));
    }
    Ok(JumpList::Custom(list))
}

/// JLECmd's link columns (`TargetCreated` … `Arguments`), the target path given as JLECmd gives
/// it: an automatic list's link without target items is named by its local path or network
/// share and common path.
fn link_columns(l: Option<&Link>, automatic: bool) -> Vec<String> {
    let Some(l) = l else {
        return vec![String::new(); LINK_COLUMNS.len()];
    };
    let volume = l.volume.as_ref();
    let tracker = l.tracker.as_ref();
    let mft = target_mft(l);
    let mut target = l.target_path();
    if target.is_empty() && automatic {
        let base = if l.network_path.is_empty() {
            &l.local_path
        } else {
            &l.network_path
        };
        target = format!("{base}\\{}", l.common_path);
    }
    vec![
        filetime(l.created),
        filetime(l.modified),
        filetime(l.accessed),
        l.size.to_string(),
        l.relative_path.clone(),
        l.working_dir.clone(),
        attributes(l.attributes),
        flags(l),
        volume.map_or_else(String::new, |v| drive_type(v.drive_type)),
        volume.map_or_else(String::new, |v| format!("{:08X}", v.serial)),
        volume.map_or_else(String::new, |v| v.label.clone()),
        l.local_path.clone(),
        l.common_path.clone(),
        target,
        mft.map_or_else(String::new, |(e, _)| e.to_string()),
        mft.map_or_else(String::new, |(_, s)| s.to_string()),
        tracker.map_or_else(String::new, |t| t.machine_id.clone()),
        tracker.map_or_else(String::new, |t| t.mac.clone()),
        tracker.map_or_else(String::new, |t| filetime(t.created)),
        block_names(l),
        l.arguments.clone(),
    ]
}

/// The link columns after JLECmd's.
fn extra_link_columns(l: Option<&Link>) -> Vec<String> {
    l.map_or_else(
        || vec![String::new(); 4],
        |l| {
            vec![
                l.network_path.clone(),
                l.name.clone(),
                l.icon_location.clone(),
                l.problems.join("; "),
            ]
        },
    )
}

const LINK_COLUMNS: &[&str] = &[
    "TargetCreated",
    "TargetModified",
    "TargetAccessed",
    "FileSize",
    "RelativePath",
    "WorkingDirectory",
    "FileAttributes",
    "HeaderFlags",
    "DriveType",
    "VolumeSerialNumber",
    "VolumeLabel",
    "LocalPath",
    "CommonPath",
    "TargetIDAbsolutePath",
    "TargetMFTEntryNumber",
    "TargetMFTSequenceNumber",
    "MachineID",
    "MachineMACAddress",
    "TrackerCreatedOn",
    "ExtraBlocksPresent",
    "Arguments",
];

/// JLECmd's columns of `AutomaticDestinations.csv` before the link's.
const AUTOMATIC_COLUMNS: &[&str] = &[
    "SourceFile",
    "SourceCreated",
    "SourceModified",
    "SourceAccessed",
    "AppId",
    "AppIdDescription",
    "HasSps",
    "DestListVersion",
    "LastUsedEntryNumber",
    "MRU",
    "EntryNumber",
    "CreationTime",
    "LastModified",
    "Hostname",
    "MacAddress",
    "Path",
    "InteractionCount",
    "PinStatus",
    "FileBirthDroid",
    "FileDroid",
    "VolumeBirthDroid",
    "VolumeDroid",
];

/// JLECmd's columns of `CustomDestinations.csv` before the link's.
const CUSTOM_COLUMNS: &[&str] = &[
    "SourceFile",
    "SourceCreated",
    "SourceModified",
    "SourceAccessed",
    "AppId",
    "AppIdDescription",
    "EntryName",
];

/// After the link's columns: JLECmd's last automatic column, then those it doesn't write.
const AUTOMATIC_EXTRA: &[&str] = &[
    "Notes",
    "DisplayPath",
    "PinPosition",
    "NetworkPath",
    "Name",
    "IconLocation",
    "Problems",
];
const CUSTOM_EXTRA: &[&str] = &["Notes", "NetworkPath", "Name", "IconLocation", "Problems"];

fn header(before: &[&str], after: &[&str]) -> Vec<String> {
    before
        .iter()
        .chain(LINK_COLUMNS)
        .chain(after)
        .map(|c| (*c).to_owned())
        .collect()
}

fn source_columns(r: &Parsed) -> Vec<String> {
    vec![
        r.source.clone(),
        system_time(r.source_times[0]),
        system_time(r.source_times[1]),
        system_time(r.source_times[2]),
        r.app_id.clone(),
        r.app_name.unwrap_or_default().to_owned(),
    ]
}

fn automatic_rows(r: &Parsed, a: &Automatic) -> Vec<Vec<String>> {
    let has_sps = a.destinations.iter().any(|d| !d.properties.is_empty());
    let header = a.header.as_ref();
    let list_columns = |row: &mut Vec<String>| {
        row.push(if has_sps { "True" } else { "False" }.to_owned());
        row.push(header.map_or_else(String::new, |h| h.version.to_string()));
        row.push(header.map_or_else(String::new, |h| h.last_entry_number.to_string()));
    };
    let mut rows = Vec::new();
    for d in &a.destinations {
        let mut row = source_columns(r);
        list_columns(&mut row);
        row.extend([
            d.position.to_string(),
            format!("{:X}", d.entry),
            filetime(d.droid_created),
            filetime(d.last_used),
            d.hostname.clone(),
            d.mac.clone(),
            d.path.clone(),
            // Version 1 lists (Windows 7, 8) don't record it: 0, as JLECmd writes it.
            d.interaction_count.unwrap_or(0).to_string(),
            if d.pin.is_some() { "True" } else { "False" }.to_owned(),
            droid(&d.file_birth_droid),
            droid(&d.file_droid),
            droid(&d.volume_birth_droid),
            droid(&d.volume_droid),
        ]);
        row.extend(link_columns(d.link.as_ref(), true));
        row.extend([
            String::new(),
            d.display_path(),
            d.pin.map_or_else(String::new, |p| p.to_string()),
        ]);
        row.extend(extra_link_columns(d.link.as_ref()));
        rows.push(row);
    }
    // Streams no entry names, as JLECmd writes them with --withDir.
    for u in &a.unlisted {
        let mut row = source_columns(r);
        list_columns(&mut row);
        row.extend([String::new(), u.name.clone()]);
        row.extend(std::iter::repeat_n(String::new(), 11));
        row.extend(link_columns(u.link.as_ref(), true));
        row.extend([UNLISTED_NOTE.to_owned(), String::new(), String::new()]);
        row.extend(extra_link_columns(u.link.as_ref()));
        rows.push(row);
    }
    rows
}

fn custom_rows(r: &Parsed, c: &Custom) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for (category, link) in c.links() {
        let mut row = source_columns(r);
        row.push(category.kind.name());
        row.extend(link_columns(Some(link), false));
        row.push(String::new());
        row.extend(extra_link_columns(Some(link)));
        rows.push(row);
    }
    for old in &c.leftover {
        let mut row = source_columns(r);
        row.push(String::new());
        row.extend(link_columns(Some(&old.link), false));
        row.push(format!(
            "Left over after the last category, at offset {}",
            old.offset
        ));
        row.extend(extra_link_columns(Some(&old.link)));
        rows.push(row);
    }
    rows
}

/// JLECmd's `AutomaticDestinations.csv` and `CustomDestinations.csv` in `dir`.
fn write_csv_tables(dir: &Path, parsed: &[Parsed]) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut automatic = csv::Writer::from_path(dir.join("AutomaticDestinations.csv"))?;
    automatic.write_record(header(AUTOMATIC_COLUMNS, AUTOMATIC_EXTRA))?;
    let mut custom = csv::Writer::from_path(dir.join("CustomDestinations.csv"))?;
    custom.write_record(header(CUSTOM_COLUMNS, CUSTOM_EXTRA))?;
    for r in parsed {
        match &r.list {
            JumpList::Automatic(a) => {
                for row in automatic_rows(r, a) {
                    automatic.write_record(row)?;
                }
            }
            JumpList::Custom(c) => {
                for row in custom_rows(r, c) {
                    custom.write_record(row)?;
                }
            }
        }
    }
    automatic.flush()?;
    custom.flush()
}

fn create_parent(path: &Path) -> io::Result<()> {
    match path.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
}

fn link_value(l: Option<&Link>) -> Value {
    l.map_or(Value::Null, |l| Value::Object(link_json(l)))
}

fn destination_json(d: &Destination) -> Value {
    json!({
        "mru": d.position,
        "entry_number": d.entry,
        "stream": format!("{:x}", d.entry),
        "last_used": filetime(d.last_used),
        "pinned": d.pin.is_some(),
        "pin_position": d.pin,
        "interaction_count": d.interaction_count,
        "score": d.score,
        "checksum": format!("{:016x}", d.checksum),
        "hostname": d.hostname,
        "mac_address": d.mac,
        "created": filetime(d.droid_created),
        "volume_droid": droid(&d.volume_droid),
        "file_droid": droid(&d.file_droid),
        "volume_droid_birth": droid(&d.volume_birth_droid),
        "file_droid_birth": droid(&d.file_birth_droid),
        "path": d.path,
        "display_path": d.display_path(),
        "properties": properties_json(&d.properties),
        "link": link_value(d.link.as_ref()),
    })
}

fn json_record(r: &Parsed) -> Value {
    let mut v = json!({
        "source_file": r.source,
        "source_created": system_time(r.source_times[0]),
        "source_modified": system_time(r.source_times[1]),
        "source_accessed": system_time(r.source_times[2]),
        "app_id": r.app_id,
        "app_name": r.app_name,
        "problems": r.problems(),
    });
    let fields = match &r.list {
        JumpList::Automatic(a) => json!({
            "type": "automatic",
            "dest_list": a.header.as_ref().map(|h| json!({
                "version": h.version,
                "entry_count": h.entry_count,
                "pinned_count": h.pinned_count,
                "counter": h.counter,
                "last_entry_number": h.last_entry_number,
                "last_revision": h.last_revision,
            })),
            "entries": a.destinations.iter().map(destination_json).collect::<Vec<_>>(),
            "properties": properties_json(&a.properties),
            "unlisted": a.unlisted.iter().map(|u| json!({
                "stream": u.name,
                "link": link_value(u.link.as_ref()),
            })).collect::<Vec<_>>(),
            "streams": a.streams.iter().map(|(name, size)| json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }),
        JumpList::Custom(c) => json!({
            "type": "custom",
            "format_version": c.version,
            "categories": c.categories.iter().map(|category| json!({
                "name": category.kind.name(),
                "kind": match category.kind {
                    Kind::Custom(_) => "custom",
                    Kind::Known(_) => "known",
                    Kind::Tasks => "tasks",
                },
                "links": category.links.iter().map(|l| Value::Object(link_json(l))).collect::<Vec<_>>(),
                "other_objects": category.other_objects,
            })).collect::<Vec<_>>(),
            "trailing_bytes": c.trailing,
            "leftover": c.leftover.iter().map(|o| json!({
                "offset": o.offset,
                "link": Value::Object(link_json(&o.link)),
            })).collect::<Vec<_>>(),
        }),
    };
    if let (Value::Object(v), Value::Object(fields)) = (&mut v, fields) {
        v.extend(fields);
    }
    v
}

fn write_json(
    mut w: Box<dyn Write>,
    output_type: JumpListOutputType,
    parsed: &[Parsed],
) -> io::Result<()> {
    for r in parsed {
        let v = json_record(r);
        // JSON: pretty objects separated by newlines, like parse-lnk; JSONL: one per line
        if output_type == JumpListOutputType::Json {
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
    let automatic: Vec<(&Parsed, &Automatic)> = parsed
        .iter()
        .filter_map(|r| match &r.list {
            JumpList::Automatic(a) => Some((r, a)),
            JumpList::Custom(_) => None,
        })
        .collect();
    let custom: Vec<(&Parsed, &Custom)> = parsed
        .iter()
        .filter_map(|r| match &r.list {
            JumpList::Custom(c) => Some((r, c)),
            JumpList::Automatic(_) => None,
        })
        .collect();
    let mut count = format!(
        "{} (automatic {}, custom {})",
        fmt_num(parsed.len()),
        fmt_num(automatic.len()),
        fmt_num(custom.len())
    );
    if failed > 0 {
        count.push_str(&format!(" (could not parse: {})", fmt_num(failed)));
    }
    p_label(no_color, "Jump lists parsed: ", &count);
    let entries: usize = automatic.iter().map(|(_, a)| a.destinations.len()).sum();
    let pinned = automatic
        .iter()
        .flat_map(|(_, a)| &a.destinations)
        .filter(|d| d.pin.is_some())
        .count();
    let custom_links: usize = custom.iter().map(|(_, c)| c.links().count()).sum();
    p_label(
        no_color,
        "Entries: ",
        &format!(
            "{} (pinned {}), custom list links {}",
            fmt_num(entries),
            fmt_num(pinned),
            fmt_num(custom_links)
        ),
    );

    // Applications by entries
    let mut apps: BTreeMap<(String, Option<&str>), usize> = BTreeMap::new();
    for r in parsed {
        *apps.entry((r.app_id.clone(), r.app_name)).or_default() += r.links().len();
    }
    let mut apps: Vec<_> = apps.into_iter().collect();
    apps.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let named = apps.iter().filter(|((_, name), _)| name.is_some()).count();
    p_label(
        no_color,
        "Applications: ",
        &format!(
            "{} ({} named from their AppID)",
            fmt_num(apps.len()),
            fmt_num(named)
        ),
    );
    for ((id, name), n) in apps.iter().take(MAX_PRINTED_APPS) {
        let id = if id.is_empty() { "(no AppID)" } else { id };
        p(
            None,
            &format!(
                "  {} ({id}): {} links",
                name.unwrap_or("Unknown AppId"),
                fmt_num(*n)
            ),
            true,
        );
    }

    let hosts: BTreeSet<&str> = automatic
        .iter()
        .flat_map(|(_, a)| &a.destinations)
        .map(|d| d.hostname.as_str())
        .filter(|h| !h.is_empty())
        .collect();
    let mut shown: Vec<&str> = hosts.iter().copied().take(5).collect();
    if hosts.len() > shown.len() {
        shown.push("…");
    }
    p_label(
        no_color,
        "Machines in the entries: ",
        &if hosts.is_empty() {
            "0".to_owned()
        } else {
            format!("{} ({})", fmt_num(hosts.len()), shown.join(", "))
        },
    );
    let used: Vec<u64> = automatic
        .iter()
        .flat_map(|(_, a)| &a.destinations)
        .map(|d| d.last_used)
        .filter(|&t| t != 0)
        .collect();
    if let (Some(first), Some(last)) = (used.iter().min(), used.iter().max()) {
        p_label(
            no_color,
            "Last used: ",
            &format!("{} - {}", filetime(*first), filetime(*last)),
        );
    }
    let links: Vec<(&Parsed, String, &Link)> = parsed
        .iter()
        .flat_map(|r| r.links().into_iter().map(move |(what, l)| (r, what, l)))
        .collect();
    let drive = |t: u32| {
        links
            .iter()
            .filter(|(_, _, l)| l.volume.as_ref().is_some_and(|v| v.drive_type == t))
            .count()
    };
    let network = links
        .iter()
        .filter(|(_, _, l)| !l.network_path.is_empty())
        .count();
    p_label(
        no_color,
        "Targets: ",
        &format!(
            "fixed drives {}, removable drives {}, CD/DVD {}, network shares {}",
            fmt_num(drive(3)),
            fmt_num(drive(2)),
            fmt_num(drive(5)),
            fmt_num(network)
        ),
    );
    let damaged = parsed.iter().filter(|r| !r.problems().is_empty()).count();
    p_label(no_color, "With problems: ", &fmt_num(damaged));

    let line = |r: &Parsed, what: &str, l: &Link| {
        let args: String = l.arguments.trim().chars().take(80).collect();
        format!("  {} ({what}) -> {} {args}", r.source, link_target(l))
            .trim_end()
            .to_owned()
    };
    let leftover: Vec<String> = custom
        .iter()
        .flat_map(|(r, c)| {
            c.leftover
                .iter()
                .map(|o| line(r, &format!("at {}", o.offset), &o.link))
        })
        .collect();
    let unlisted: Vec<String> = automatic
        .iter()
        .flat_map(|(r, a)| {
            a.unlisted.iter().map(|u| match &u.link {
                Some(l) => line(r, &format!("stream {}", u.name), l),
                None => format!("  {} (stream {})", r.source, u.name),
            })
        })
        .collect();
    let burned: Vec<String> = links
        .iter()
        .filter(|(_, _, l)| l.target.iter().any(|i| i.kind == ItemKind::CdBurn))
        .map(|(r, what, l)| line(r, what, l))
        .collect();
    let launched: Vec<String> = links
        .iter()
        .filter(|(_, _, l)| launches(&link_target(l), &l.arguments))
        .map(|(r, what, l)| line(r, what, l))
        .collect();
    let findings: [(&str, Vec<String>); 4] = [
        (
            "Links left over from an earlier version of a custom list: ",
            leftover,
        ),
        (
            "Link streams no DestList entry names (removed or damaged entries): ",
            unlisted,
        ),
        ("Items staged for a CD or DVD burn: ", burned),
        ("Shell or script host started with arguments: ", launched),
    ];
    for (label, found) in &findings {
        p_label(no_color, label, &fmt_num(found.len()));
        for l in found.iter().take(MAX_PRINTED_FINDINGS) {
            p(None, l, true);
        }
    }
    p(None, "", true);
}

/// Whether a file name is a jump list: `*.automaticDestinations-ms` or `*.customDestinations-ms`.
pub fn is_jump_list_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(AUTOMATIC_SUFFIX) || name.ends_with(CUSTOM_SUFFIX)
}

/// The jump lists under `dir`, recursively, in path order.
pub fn find_jump_lists(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_jump_list_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_kinds() {
        assert!(is_jump_list_name(
            "f01b4d95cf55d32a.automaticDestinations-ms"
        ));
        assert!(is_jump_list_name("5D696D521DE238C3.CUSTOMDESTINATIONS-MS"));
        assert!(!is_jump_list_name(
            "f01b4d95cf55d32a.automaticDestinations-ms.txt"
        ));
        let options = jumplist::Options::default();
        // a custom list's header with no categories: an empty list
        let empty = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            parse_data("x.customDestinations-ms", &empty, &options),
            Ok(JumpList::Custom(_))
        ));
        assert!(parse_data("x.customDestinations-ms", b"not a jump list", &options).is_err());
        assert!(parse_data("x.automaticDestinations-ms", &empty, &options).is_err());
        assert_eq!(
            header(AUTOMATIC_COLUMNS, AUTOMATIC_EXTRA).len(),
            AUTOMATIC_COLUMNS.len() + LINK_COLUMNS.len() + AUTOMATIC_EXTRA.len()
        );
    }
}
