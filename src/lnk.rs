//! `parse-lnk`: Windows shortcut (`.lnk`) parsing with Yamato Security's ys-lnk-parser (a fork of
//! sootmark-shell that reads every part of a link and does not crash on damaged ones): one record
//! per link with what it points at (the target's times, size and attributes when the link was
//! saved, its path, volume and network share), its arguments, the machine it was made on, and
//! every extra data block, as LECmd's CSV columns and more, or every field as JSON / JSONL, with
//! Hayabusa's input options, progress bar and results summary. The summary flags links that
//! hide their command line, carry data after their end, or start a shell or script host with
//! arguments.

use crate::cli::{LnkOptions, LnkOutputType};
use crate::color::JunteiColor;
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use chrono::{DateTime, SecondsFormat, Utc};
use indicatif::ProgressBar;
use serde_json::{Value, json};
use shell::item::Item;
use shell::lnk::{self, Link};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Parse errors printed; the rest are only counted.
const MAX_PRINTED_ERRORS: usize = 20;
/// Links listed per finding in the summary.
const MAX_PRINTED_FINDINGS: usize = 10;
/// Larger files are not shortcuts (a link's sections are limited to 64 KiB each).
const MAX_LNK_SIZE: u64 = 16 * 1024 * 1024;
/// Programs that run what their arguments say: a link to one with arguments is how malicious
/// shortcuts start their payload.
const LAUNCHERS: [&str; 16] = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "conhost.exe",
    "forfiles.exe",
    "msbuild.exe",
    "installutil.exe",
];

/// Attribute names (`FILE_ATTRIBUTE_*`), by bit.
const ATTRIBUTES: [(u32, &str); 17] = [
    (0x1, "READONLY"),
    (0x2, "HIDDEN"),
    (0x4, "SYSTEM"),
    (0x10, "DIRECTORY"),
    (0x20, "ARCHIVE"),
    (0x40, "DEVICE"),
    (0x80, "NORMAL"),
    (0x100, "TEMPORARY"),
    (0x200, "SPARSE_FILE"),
    (0x400, "REPARSE_POINT"),
    (0x800, "COMPRESSED"),
    (0x1000, "OFFLINE"),
    (0x2000, "NOT_CONTENT_INDEXED"),
    (0x4000, "ENCRYPTED"),
    (0x8000, "INTEGRITY_STREAM"),
    (0x10000, "VIRTUAL"),
    (0x20000, "NO_SCRUB_DATA"),
];

/// Run the command; returns the exit status.
pub fn run(opts: &LnkOptions) -> i32 {
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
            let found = find_links(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!("No shortcuts (*.lnk) were found in {}", d.display()),
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
        p_label(no_color, "Shortcuts (LNK files): ", &fmt_num(files.len()));
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
    let options = lnk::Options {
        code_page: opts.code_page,
    };
    let mut parsed = Vec::new();
    let mut failed = 0usize;
    for path in &files {
        if let Some(b) = &bar {
            b.set_message(progress::message(path));
        }
        match parse_file(path, &options) {
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
                "To save every record, add -o <FILE> (-t csv, json or jsonl).",
                true,
            );
        }
    }
    i32::from(parsed.is_empty())
}

/// One parsed shortcut.
struct Parsed {
    source: String,
    /// The `.lnk` file's own times on the file system (created, modified, accessed).
    source_times: [Option<SystemTime>; 3],
    file_size: u64,
    link: Link,
}

impl Parsed {
    /// Bytes after the link's terminal block (data appended to the shortcut).
    fn appended(&self) -> u64 {
        self.file_size.saturating_sub(self.link.length as u64)
    }

    /// What the link starts: its local or network path, else the path of its target items.
    fn target(&self) -> String {
        if !self.link.local_path.is_empty() {
            format!("{}{}", self.link.local_path, self.link.common_path)
        } else if !self.link.network_path.is_empty() {
            format!("{}\\{}", self.link.network_path, self.link.common_path)
        } else {
            self.link.target_path()
        }
    }

    /// Whether the link starts a shell or script host with arguments.
    fn launches(&self) -> bool {
        let target = self.target().to_ascii_lowercase();
        let program = target.rsplit(['\\', '/']).next().unwrap_or_default();
        !self.link.arguments.trim().is_empty() && LAUNCHERS.contains(&program)
    }

    fn hides_arguments(&self) -> bool {
        self.link
            .problems
            .iter()
            .any(|p| p.starts_with("string data longer than 260"))
    }
}

fn parse_file(path: &Path, options: &lnk::Options) -> Result<Parsed, String> {
    let meta = path.metadata().map_err(|e| e.to_string())?;
    if meta.len() > MAX_LNK_SIZE {
        return Err(format!("too large for a shortcut ({} bytes)", meta.len()));
    }
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let link = lnk::parse_with(&data, options).map_err(|e| e.to_string())?;
    Ok(Parsed {
        source: path.to_string_lossy().to_string(),
        source_times: [
            meta.created().ok(),
            meta.modified().ok(),
            meta.accessed().ok(),
        ],
        file_size: meta.len(),
        link,
    })
}

/// A FILETIME as an RFC 3339 UTC time, like the other commands' timestamps; empty when 0.
fn filetime(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    let ticks = ft as i64 - 116_444_736_000_000_000;
    DateTime::<Utc>::from_timestamp(
        ticks.div_euclid(10_000_000),
        (ticks.rem_euclid(10_000_000) * 100) as u32,
    )
    .map(|t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    .unwrap_or_default()
}

/// A shell item's FAT time (seconds since 1970, as recorded) as RFC 3339.
fn fat_time(secs: Option<i64>) -> Value {
    secs.and_then(|s| DateTime::<Utc>::from_timestamp(s, 0))
        .map_or(Value::Null, |t| {
            json!(t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        })
}

fn system_time(t: Option<SystemTime>) -> String {
    t.map(|t| DateTime::<Utc>::from(t).to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .unwrap_or_default()
}

fn attributes(bits: u32) -> String {
    let mut names: Vec<String> = ATTRIBUTES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| (*n).to_owned())
        .collect();
    let known: u32 = ATTRIBUTES.iter().map(|(b, _)| b).sum();
    if bits & !known != 0 {
        names.push(format!("0x{:08x}", bits & !known));
    }
    names.join("|")
}

fn flags(link: &Link) -> String {
    let mut names: Vec<String> = link.flag_names().iter().map(|s| (*s).to_owned()).collect();
    if link.unknown_flags() != 0 {
        names.push(format!("0x{:08x}", link.unknown_flags()));
    }
    names.join("|")
}

fn drive_type(t: u32) -> String {
    match t {
        0 => "DRIVE_UNKNOWN".into(),
        1 => "DRIVE_NO_ROOT_DIR".into(),
        2 => "DRIVE_REMOVABLE".into(),
        3 => "DRIVE_FIXED".into(),
        4 => "DRIVE_REMOTE".into(),
        5 => "DRIVE_CDROM".into(),
        6 => "DRIVE_RAMDISK".into(),
        other => other.to_string(),
    }
}

fn show_command(link: &Link) -> String {
    link.show_command_name()
        .map_or_else(|| link.show_command.to_string(), str::to_owned)
}

/// A GUID as LECmd writes droids: lower case, no braces.
fn droid(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}

/// The target's NTFS file reference: its last shell item's (not a parent folder's when the
/// target itself has none).
fn target_mft(link: &Link) -> Option<(u64, u16)> {
    link.target.last().and_then(|i| i.mft)
}

fn block_names(link: &Link) -> String {
    link.blocks
        .iter()
        .map(|b| match lnk::block_name(*b) {
            "Unknown" => format!("0x{b:08x}"),
            name => name.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn known_folder(link: &Link) -> String {
    link.known_folder
        .as_ref()
        .map_or_else(String::new, |(id, _)| {
            shell::guid_names::name(id).map_or_else(|| id.clone(), str::to_owned)
        })
}

fn special_folder(link: &Link) -> String {
    link.special_folder.map_or_else(String::new, |(id, _)| {
        lnk::special_folder_name(id).map_or_else(|| id.to_string(), str::to_owned)
    })
}

fn network_provider(link: &Link) -> String {
    link.network_provider.map_or_else(String::new, |p| {
        lnk::network_provider_name(p).map_or_else(|| format!("0x{p:08x}"), str::to_owned)
    })
}

/// LECmd's columns, in its order (MACVendor left out), then the fields LECmd doesn't write.
const CSV_HEADER: &[&str] = &[
    "SourceFile",
    "SourceCreated",
    "SourceModified",
    "SourceAccessed",
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
    "NetworkPath",
    "CommonPath",
    "Arguments",
    "TargetIDAbsolutePath",
    "TargetMFTEntryNumber",
    "TargetMFTSequenceNumber",
    "MachineID",
    "MachineMACAddress",
    "TrackerCreatedOn",
    "ExtraBlocksPresent",
    "Name",
    "IconLocation",
    "ShowWindow",
    "EnvironmentVariables",
    "VolumeDroid",
    "FileDroid",
    "VolumeDroidBirth",
    "FileDroidBirth",
    "Problems",
    "IconIndex",
    "HotKey",
    "IconEnvironment",
    "KnownFolder",
    "SpecialFolder",
    "DarwinId",
    "ShimLayer",
    "NetworkDevice",
    "NetworkProvider",
    "ConsoleCodePage",
    "AppendedBytes",
];

fn csv_row(r: &Parsed) -> Vec<String> {
    let l = &r.link;
    let volume = l.volume.as_ref();
    let tracker = l.tracker.as_ref();
    let mft = target_mft(l);
    vec![
        r.source.clone(),
        system_time(r.source_times[0]),
        system_time(r.source_times[1]),
        system_time(r.source_times[2]),
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
        l.network_path.clone(),
        l.common_path.clone(),
        l.arguments.clone(),
        l.target_path(),
        mft.map_or_else(String::new, |(e, _)| e.to_string()),
        mft.map_or_else(String::new, |(_, s)| s.to_string()),
        tracker.map_or_else(String::new, |t| t.machine_id.clone()),
        tracker.map_or_else(String::new, |t| t.mac.clone()),
        tracker.map_or_else(String::new, |t| filetime(t.created)),
        block_names(l),
        l.name.clone(),
        l.icon_location.clone(),
        show_command(l),
        l.environment_target.clone(),
        tracker.map_or_else(String::new, |t| droid(&t.volume_id)),
        tracker.map_or_else(String::new, |t| droid(&t.object_id)),
        tracker.map_or_else(String::new, |t| droid(&t.birth_volume_id)),
        tracker.map_or_else(String::new, |t| droid(&t.birth_object_id)),
        l.problems.join("; "),
        l.icon_index.to_string(),
        l.hotkey_name(),
        l.icon_environment_target.clone(),
        known_folder(l),
        special_folder(l),
        l.darwin_id.clone(),
        l.shim_layer.clone(),
        l.network_device.clone(),
        network_provider(l),
        l.console_code_page
            .map_or_else(String::new, |c| c.to_string()),
        r.appended().to_string(),
    ]
}

fn item_json(i: &Item) -> Value {
    json!({
        "class": format!("0x{:02x}", i.class),
        "kind": format!("{:?}", i.kind),
        "name": i.name,
        "guid": i.guid,
        "modified": fat_time(i.modified),
        "created": fat_time(i.created),
        "accessed": fat_time(i.accessed),
        "mft_entry": i.mft.map(|m| m.0),
        "mft_sequence": i.mft.map(|m| m.1),
    })
}

fn json_record(r: &Parsed) -> Value {
    let l = &r.link;
    let mft = target_mft(l);
    json!({
        "source_file": r.source,
        "source_created": system_time(r.source_times[0]),
        "source_modified": system_time(r.source_times[1]),
        "source_accessed": system_time(r.source_times[2]),
        "header": {
            "flags": l.flag_names(),
            "unknown_flags": (l.unknown_flags() != 0).then(|| format!("0x{:08x}", l.unknown_flags())),
            "file_attributes": attributes(l.attributes),
            "target_created": filetime(l.created),
            "target_modified": filetime(l.modified),
            "target_accessed": filetime(l.accessed),
            "file_size": l.size,
            "icon_index": l.icon_index,
            "show_command": show_command(l),
            "hotkey": l.hotkey_name(),
        },
        "target_path": l.target_path(),
        "target_mft_entry": mft.map(|m| m.0),
        "target_mft_sequence": mft.map(|m| m.1),
        "target_items": l.target.iter().map(item_json).collect::<Vec<_>>(),
        "link_info": {
            "drive_type": l.volume.as_ref().map(|v| drive_type(v.drive_type)),
            "volume_serial_number": l.volume.as_ref().map(|v| format!("{:08X}", v.serial)),
            "volume_label": l.volume.as_ref().map(|v| v.label.clone()),
            "local_path": l.local_path,
            "network_path": l.network_path,
            "network_device": l.network_device,
            "network_provider": network_provider(l),
            "common_path": l.common_path,
        },
        "name": l.name,
        "relative_path": l.relative_path,
        "working_directory": l.working_dir,
        "arguments": l.arguments,
        "icon_location": l.icon_location,
        "extra_blocks": l.blocks.iter().map(|b| lnk::block_name(*b)).collect::<Vec<_>>(),
        "environment_variables": l.environment_target,
        "icon_environment": l.icon_environment_target,
        "known_folder": l.known_folder.as_ref().map(|(id, offset)| json!({
            "id": id, "name": shell::guid_names::name(id), "item_offset": offset,
        })),
        "special_folder": l.special_folder.map(|(id, offset)| json!({
            "id": id, "name": lnk::special_folder_name(id), "item_offset": offset,
        })),
        "darwin_id": l.darwin_id,
        "shim_layer": l.shim_layer,
        "console": l.console.as_ref().map(|c| json!({
            "face_name": c.face_name,
            "font_size": c.font_size,
            "font_weight": c.font_weight,
            "screen_buffer_size": [c.screen_buffer_size.0, c.screen_buffer_size.1],
            "window_size": [c.window_size.0, c.window_size.1],
            "window_origin": [c.window_origin.0, c.window_origin.1],
            "fill_attributes": c.fill_attributes,
            "popup_fill_attributes": c.popup_fill_attributes,
            "cursor_size": c.cursor_size,
            "full_screen": c.full_screen,
            "quick_edit": c.quick_edit,
            "insert_mode": c.insert_mode,
            "auto_position": c.auto_position,
            "history_buffer_size": c.history_buffer_size,
            "history_buffers": c.history_buffers,
            "history_no_dup": c.history_no_dup,
            "color_table": c.color_table,
        })),
        "console_code_page": l.console_code_page,
        "properties": l.properties.iter().map(|p| json!({
            "format_id": p.format_id,
            "id": p.id,
            "name": p.name,
            "canonical_name": p.canonical_name(),
            "value": p.value.display(),
        })).collect::<Vec<_>>(),
        "vista_target_path": l.vista_target_path(),
        "tracker": l.tracker.as_ref().map(|t| json!({
            "machine_id": t.machine_id,
            "volume_droid": droid(&t.volume_id),
            "file_droid": droid(&t.object_id),
            "volume_droid_birth": droid(&t.birth_volume_id),
            "file_droid_birth": droid(&t.birth_object_id),
            "mac_address": t.mac,
            "created": filetime(t.created),
            "birth_mac_address": t.birth_mac,
            "birth_created": filetime(t.birth_created),
        })),
        "problems": l.problems,
        "appended_bytes": r.appended(),
    })
}

fn write_records(
    mut w: Box<dyn Write>,
    output_type: LnkOutputType,
    parsed: &[Parsed],
) -> io::Result<()> {
    if output_type == LnkOutputType::Csv {
        let mut csv = csv::Writer::from_writer(w);
        csv.write_record(CSV_HEADER)?;
        for r in parsed {
            csv.write_record(csv_row(r))?;
        }
        return csv.flush();
    }
    for r in parsed {
        let v = json_record(r);
        // JSON: pretty objects separated by newlines, like parse-mft; JSONL: one per line
        if output_type == LnkOutputType::Json {
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
    p_label(no_color, "Shortcuts parsed: ", &count);
    let drive = |t: u32| {
        parsed
            .iter()
            .filter(|r| r.link.volume.as_ref().is_some_and(|v| v.drive_type == t))
            .count()
    };
    let network = parsed
        .iter()
        .filter(|r| !r.link.network_path.is_empty())
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
    let machines: BTreeSet<&str> = parsed
        .iter()
        .filter_map(|r| r.link.tracker.as_ref())
        .map(|t| t.machine_id.as_str())
        .filter(|m| !m.is_empty())
        .collect();
    let mut shown: Vec<&str> = machines.iter().copied().take(5).collect();
    if machines.len() > shown.len() {
        shown.push("…");
    }
    p_label(
        no_color,
        "Machines that made them: ",
        &if machines.is_empty() {
            "0".to_owned()
        } else {
            format!("{} ({})", fmt_num(machines.len()), shown.join(", "))
        },
    );
    let times: Vec<u64> = parsed
        .iter()
        .flat_map(|r| [r.link.created, r.link.modified, r.link.accessed])
        .filter(|&t| t != 0)
        .collect();
    if let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) {
        p_label(
            no_color,
            "Target times: ",
            &format!("{} - {}", filetime(*first), filetime(*last)),
        );
    }
    let damaged = parsed
        .iter()
        .filter(|r| !r.link.problems.is_empty())
        .count();
    p_label(no_color, "With problems: ", &fmt_num(damaged));
    let findings: [(&str, Vec<&Parsed>); 3] = [
        (
            "Hidden command line (string data over 260 characters): ",
            parsed.iter().filter(|r| r.hides_arguments()).collect(),
        ),
        (
            "Data after the end of the link: ",
            parsed.iter().filter(|r| r.appended() > 0).collect(),
        ),
        (
            "Shell or script host started with arguments: ",
            parsed.iter().filter(|r| r.launches()).collect(),
        ),
    ];
    for (label, found) in &findings {
        p_label(no_color, label, &fmt_num(found.len()));
        for r in found.iter().take(MAX_PRINTED_FINDINGS) {
            let args: String = r.link.arguments.trim().chars().take(80).collect();
            let line = format!("  {} -> {} {args}", r.source, r.target());
            p(None, line.trim_end(), true);
        }
    }
    p(None, "", true);
}

/// Whether a file name is a shortcut: `*.lnk`.
pub fn is_lnk_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".lnk")
}

/// The shortcuts under `dir`, recursively, in path order.
pub fn find_links(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_lnk_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_formats() {
        assert!(is_lnk_name("Report.docx.LNK"));
        assert!(!is_lnk_name("Report.lnk.txt"));
        assert_eq!(attributes(0x21), "READONLY|ARCHIVE");
        assert_eq!(attributes(0x8000_0020), "ARCHIVE|0x80000000");
        assert_eq!(attributes(0), "");
        assert_eq!(drive_type(2), "DRIVE_REMOVABLE");
        assert_eq!(
            droid("{38648BD4-606F-459B-91E5-D8883D4B70B1}"),
            "38648bd4-606f-459b-91e5-d8883d4b70b1"
        );
        assert_eq!(filetime(0), "");
        assert_eq!(
            filetime(130_131_449_897_040_000),
            "2013-05-16T02:29:49.704Z"
        );
        assert_eq!(fat_time(Some(0)), json!("1970-01-01T00:00:00Z"));
        assert_eq!(fat_time(None), Value::Null);
    }
}
