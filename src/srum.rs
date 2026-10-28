//! `parse-srum`: Windows System Resource Usage Monitor (`SRUDB.dat`) parsing with Yamato
//! Security's ys-srum-parser (a fork of Sootmark's ese and srum crates): every entry of every
//! provider table, with its program, account and network named the way SrumECmd names them, as
//! one CSV table per provider or one JSON object per entry. The volume's SOFTWARE hive, given or
//! found in the same collection, names the accounts and Wi-Fi networks. Hayabusa's input options,
//! progress bar and results summary around it.

use crate::cli::{SrumOptions, SrumOutputType};
use crate::color::JunteiColor;
use crate::hive::{Hive, Key};
use crate::progress;
use crate::util::{self, check_output, error_msg, fmt_num, p, p_label};
use chrono::{DateTime, SecondsFormat, Utc};
use indicatif::ProgressBar;
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Value as Json, json};
use srum::{Context, Entry, Kind, Srum, Time, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Problems printed per database; the rest are only counted.
const MAX_PRINTED_PROBLEMS: usize = 10;
/// Programs listed under "Top senders" in the summary.
const TOP_SENDERS: usize = 5;

/// Run the command; returns the exit status.
pub fn run(opts: &SrumOptions) -> i32 {
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
    if opts.output_type == Some(SrumOutputType::Csv) && opts.output.is_none() {
        report_error(
            None,
            "CSV output needs -o <DIR>: every SRUM table is its own CSV file.",
        );
        return 1;
    }

    // --- inputs ---------------------------------------------------------------------------
    let (databases, root) = match (&opts.filepath, &opts.directory) {
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
            let found = find_databases(d);
            if found.is_empty() {
                report_error(
                    None,
                    &format!(
                        "No SRUM databases (SRUDB.dat) were found in {}",
                        d.display()
                    ),
                );
                return 1;
            }
            (found, Some(d.as_path()))
        }
        (None, None) => unreachable!("clap requires -f or -d"),
    };
    if let Some(s) = &opts.software
        && !s.is_file()
    {
        report_error(None, &format!("The file does not exist: {}", s.display()));
        return 1;
    }
    if root.is_some() && data_on_stdout {
        report_error(
            None,
            "With -d, save the entries with -o <DIR> (one file per database): the entries of several databases cannot be told apart on stdout.",
        );
        return 1;
    }
    // CSV tables always go to a directory; JSON / JSONL with -d too (one file per database).
    let out_is_dir = output_type == SrumOutputType::Csv || root.is_some();
    if let Some(out) = &opts.output
        && let Err(msg) = check_output(out, out_is_dir, opts.clobber)
    {
        report_error(None, &msg);
        return 1;
    }

    let total: u64 = databases
        .iter()
        .map(|d| d.metadata().map_or(0, |m| m.len()))
        .sum();
    if !data_on_stdout {
        p_label(no_color, "SRUM databases: ", &fmt_num(databases.len()));
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
        progress::progress_bar(databases.len(), no_color)
    });

    // --- parse and write -------------------------------------------------------------------
    let mut stats = Stats::default();
    let mut used_names = HashSet::new();
    let mut saved = 0usize;
    let mut stdout_writer = data_on_stdout
        .then(|| RecordWriter::new(Box::new(BufWriter::new(io::stdout())), output_type));
    for database in &databases {
        let source = database.to_string_lossy().to_string();
        if let Some(b) = &bar {
            b.set_message(progress::message(database));
        }
        // the names of the SOFTWARE hive, when there is one that can be read
        let context = match opts.software.clone().or_else(|| software_hive(database)) {
            Some(hive) => match read_software(&hive) {
                Ok((context, problems)) => {
                    for problem in problems.iter().take(MAX_PRINTED_PROBLEMS) {
                        report_error(bar.as_ref(), &format!("{}: {problem}", hive.display()));
                    }
                    Some(context)
                }
                Err(e) => {
                    report_error(
                        bar.as_ref(),
                        &format!(
                            "Could not read the SOFTWARE hive {} (no account or Wi-Fi names): {e}",
                            hive.display()
                        ),
                    );
                    None
                }
            },
            None => None,
        };
        let parsed = std::fs::read(database)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                srum::read_with(&data, context.as_ref().unwrap_or(&Context::default()))
                    .map_err(|e| e.to_string())
            });
        let srum = match parsed {
            Ok(srum) => srum,
            Err(e) => {
                stats.failed += 1;
                report_error(bar.as_ref(), &format!("Could not parse {source}: {e}"));
                if let Some(b) = &bar {
                    b.inc(1);
                }
                continue;
            }
        };
        for problem in srum.problems.iter().take(MAX_PRINTED_PROBLEMS) {
            report_error(bar.as_ref(), &format!("{source}: {problem}"));
        }
        stats.add(&srum, context.as_ref());

        let written = match (&opts.output, &mut stdout_writer) {
            (Some(out), _) => {
                let name = root.map(|r| util::unique_name(r, database, &mut used_names));
                match output_type {
                    SrumOutputType::Csv => {
                        let dir = name.map_or_else(|| out.clone(), |n| out.join(n));
                        write_csv_tables(&dir, &srum).map(|files| saved += files)
                    }
                    SrumOutputType::Json | SrumOutputType::Jsonl => {
                        let path = name.map_or_else(
                            || out.clone(),
                            |n| out.join(format!("{n}.{}", output_type.extension())),
                        );
                        write_entries_to(&path, &srum, &source, output_type).map(|()| saved += 1)
                    }
                }
            }
            (None, Some(w)) => srum.entries.iter().try_for_each(|e| w.entry(e, &source)),
            (None, None) => Ok(()),
        };
        if let Err(e) = written {
            report_error(
                bar.as_ref(),
                &format!("Could not write the entries of {source}: {e}"),
            );
            return 1;
        }
        stats.databases += 1;
        if let Some(b) = &bar {
            b.inc(1);
        }
    }
    if let Some(w) = stdout_writer
        && let Err(e) = w.finish()
    {
        report_error(None, &format!("Could not write the entries: {e}"));
        return 1;
    }
    if let Some(b) = &bar {
        b.finish_with_message(progress::finished_message(no_color));
    }

    // --- summary ---------------------------------------------------------------------------
    if !data_on_stdout {
        print_summary(&stats, no_color);
        if let Some(out) = &opts.output {
            let value = if out_is_dir {
                let what = if output_type == SrumOutputType::Csv {
                    "CSV files"
                } else {
                    "files"
                };
                format!("{} ({} {what})", out.display(), fmt_num(saved))
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
    i32::from(stats.databases == 0)
}

// --- SOFTWARE hive ------------------------------------------------------------------------------

/// The names the SOFTWARE hive gives what SRUM only numbers, read as SrumECmd reads them:
/// account names (the last component of each `ProfileList` profile's `ProfileImagePath`) and
/// Wi-Fi network names (each `WlanSvc` profile's `ProfileIndex`, with the SSID in its
/// `MetaData\Channel Hints`; the first profile with an index wins). A profile that can't be read
/// is a problem, not an error.
fn read_software(path: &Path) -> Result<(Context, Vec<String>), String> {
    let hive = Hive::from_path(path)?;
    let mut context = Context::default();
    let mut problems = Vec::new();
    let profiles = r"Microsoft\Windows NT\CurrentVersion\ProfileList";
    let accounts = hive
        .open(profiles)
        .and_then(|key| key.map(|k| k.subkeys()).transpose());
    match accounts {
        Ok(accounts) => {
            for profile in accounts.unwrap_or_default() {
                let image = profile
                    .value("ProfileImagePath")
                    .and_then(|v| v.map(|v| v.string()).transpose());
                match image {
                    Ok(Some(image)) => {
                        context
                            .user_names
                            .insert(profile.name(), file_name(&image).to_string());
                    }
                    Ok(None) => {}
                    Err(e) => problems.push(format!("profile {}: {e}", profile.name())),
                }
            }
        }
        Err(e) => problems.push(format!("{profiles}: {e}")),
    }
    let interfaces = r"Microsoft\WlanSvc\Interfaces";
    let wlan = hive
        .open(interfaces)
        .and_then(|key| key.map(|k| k.subkeys()).transpose());
    match wlan {
        Ok(wlan) => {
            for interface in wlan.unwrap_or_default() {
                let wifi = interface
                    .subkey("Profiles")
                    .and_then(|key| key.map(|k| k.subkeys()).transpose());
                let wifi = match wifi {
                    Ok(wifi) => wifi.unwrap_or_default(),
                    Err(e) => {
                        problems.push(format!("Wi-Fi interface {}: {e}", interface.name()));
                        continue;
                    }
                };
                for profile in wifi {
                    match wifi_profile(&profile) {
                        Ok(Some((index, ssid))) => {
                            context.network_profiles.entry(index).or_insert(ssid);
                        }
                        Ok(None) => {}
                        Err(e) => problems.push(format!(
                            "Wi-Fi profile {}\\{}: {e}",
                            interface.name(),
                            profile.name()
                        )),
                    }
                }
            }
        }
        Err(e) => problems.push(format!("{interfaces}: {e}")),
    }
    Ok((context, problems))
}

/// A Wi-Fi profile's index and SSID; `None` for a profile without them.
fn wifi_profile(profile: &Key<'_>) -> Result<Option<(i64, String)>, String> {
    let Some(index) = profile.value("ProfileIndex")? else {
        return Ok(None);
    };
    let index = i64::from(index.dword()?);
    let hints = match profile.subkey("MetaData")? {
        Some(meta) => meta.value("Channel Hints")?,
        None => None,
    };
    let Some(hints) = hints else {
        return Ok(None);
    };
    Ok(channel_hints_ssid(&hints.data()?)?.map(|ssid| (index, ssid)))
}

/// The SSID in a `Channel Hints` value: a 32-bit length, then that many ASCII bytes. `None` for
/// a value too short to hold the length.
fn channel_hints_ssid(raw: &[u8]) -> Result<Option<String>, String> {
    let Some(length) = raw.get(..4) else {
        return Ok(None);
    };
    let length = i32::from_le_bytes([length[0], length[1], length[2], length[3]]);
    let name = usize::try_from(length)
        .ok()
        .and_then(|n| raw.get(4..4 + n))
        .ok_or_else(|| {
            format!(
                "Channel Hints says the name has {length} bytes, but the value has {}",
                raw.len()
            )
        })?;
    Ok(Some(name.iter().map(|&b| char::from(b)).collect()))
}

/// The last component of a Windows path (`C:\Users\alice` → `alice`).
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The SOFTWARE hive of the Windows a database comes from, in a collection that keeps the
/// layout (KAPE: `Windows/System32/sru/SRUDB.dat` and `Windows/System32/config/SOFTWARE`), or
/// copied next to the database. Names are matched ignoring case.
fn software_hive(database: &Path) -> Option<PathBuf> {
    let directory = database.parent()?;
    if directory
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("sru"))
        && let Some(hive) = directory
            .parent()
            .and_then(|system32| child(system32, "config"))
            .and_then(|config| child(&config, "SOFTWARE"))
            .filter(|p| p.is_file())
    {
        return Some(hive);
    }
    child(directory, "SOFTWARE").filter(|p| p.is_file())
}

/// The entry of `dir` named `name`, ignoring case.
fn child(dir: &Path, name: &str) -> Option<PathBuf> {
    dir.read_dir()
        .ok()?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|e| e.path())
}

// --- entries as rows ----------------------------------------------------------------------------

/// The CSV file / provider an entry belongs to: SrumECmd's name for the known tables (the two
/// energy usage tables share `EnergyUsage`), the table's own name for the others.
fn output_name(e: &Entry) -> String {
    e.kind
        .map_or_else(|| e.table.clone(), |k| k.output_name().to_string())
}

/// An entry's columns, in order: SrumECmd's (`Id`, `Timestamp`, the program, the account, the
/// raw ids), then the table's own. FILETIME columns become times; the network tables get
/// `InterfaceType` after `InterfaceLuid` and `ProfileName` after `L2ProfileId`; the energy
/// usage tables get `IsLt` (the long-term table).
fn row(e: &Entry) -> Vec<(String, Json)> {
    let text = |s: Option<&str>| s.map_or(Json::Null, |s| json!(s));
    let number = |n: Option<i64>| n.map_or(Json::Null, |n| json!(n));
    let app = e.app.as_ref();
    let mut r = vec![
        ("Id".to_string(), number(e.id)),
        ("Timestamp".to_string(), time(e.time)),
        ("ExeInfo".to_string(), text(app.map(|a| a.name.as_str()))),
        (
            "ExeInfoDescription".to_string(),
            text(app.and_then(|a| a.description.as_deref())),
        ),
        ("ExeTimestamp".to_string(), time(app.and_then(|a| a.time))),
        (
            "AppType".to_string(),
            e.app_kind.map_or(Json::Null, |k| json!(k.name())),
        ),
        ("Sid".to_string(), text(e.user.as_deref())),
        ("UserName".to_string(), text(e.user_name.as_deref())),
        ("UserId".to_string(), number(e.user_id)),
        ("AppId".to_string(), number(e.app_id)),
    ];
    if let Some(kind @ (Kind::EnergyUsage | Kind::EnergyUsageLongTerm)) = e.kind {
        r.push(("IsLt".to_string(), json!(kind == Kind::EnergyUsageLongTerm)));
    }
    let time_columns = e.kind.map_or(&[][..], Kind::time_columns);
    for (name, value) in &e.values {
        if time_columns.contains(&name.as_str()) {
            let filetime = value.as_i64().and_then(Time::from_filetime);
            r.push((name.clone(), time(filetime)));
        } else {
            r.push((name.clone(), json_value(value)));
        }
        if name == "InterfaceLuid" {
            let interface = e.interface_type().filter(|_| !value.is_null());
            r.push((
                "InterfaceType".to_string(),
                interface.map_or(Json::Null, |t| {
                    json!(
                        srum::interface_type_name(t).map_or_else(|| t.to_string(), str::to_string)
                    )
                }),
            ));
        }
        if name == "L2ProfileId" {
            r.push(("ProfileName".to_string(), text(e.profile_name.as_deref())));
        }
    }
    r
}

/// A UTC time as RFC 3339, like the timestamps of the other commands.
fn time(t: Option<Time>) -> Json {
    t.and_then(|t| {
        let ticks = t.unix_ticks();
        DateTime::<Utc>::from_timestamp(
            ticks.div_euclid(10_000_000),
            (ticks.rem_euclid(10_000_000) * 100) as u32,
        )
    })
    .map_or(Json::Null, |t| {
        json!(t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    })
}

/// An ESE value as JSON: numbers as numbers, an OLE date as a time, a GUID in its usual form,
/// binary data in hex, NULL as null.
fn json_value(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => json!(b),
        Value::U8(n) => json!(n),
        Value::I16(n) => json!(n),
        Value::U16(n) => json!(n),
        Value::I32(n) => json!(n),
        Value::U32(n) => json!(n),
        Value::I64(n) | Value::Currency(n) => json!(n),
        Value::U64(n) => json!(n),
        Value::F32(f) => json!(f),
        Value::F64(f) => json!(f),
        Value::DateTime(days) => time(Time::from_ole_date(*days)),
        Value::Guid(g) => json!(guid(g)),
        Value::Text(s) => json!(s),
        Value::Binary(b) => json!(b.iter().map(|x| format!("{x:02X}")).collect::<String>()),
        Value::MultiValue(values) => Json::Array(values.iter().map(json_value).collect()),
    }
}

/// A GUID's 16 bytes as stored (the first three fields little-endian) in the usual form.
fn guid(g: &[u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10..]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    )
}

/// A JSON value in a CSV cell: text as is, null empty, a list joined with `, `.
fn cell(v: &Json) -> String {
    match v {
        Json::Null => String::new(),
        Json::String(s) => s.clone(),
        Json::Array(values) => values.iter().map(cell).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// A row serialized as a JSON object with its columns in order.
struct Ordered<'a>(&'a [(String, Json)]);

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

// --- writers ------------------------------------------------------------------------------------

/// One CSV file per provider in `dir` (SrumECmd's names: `NetworkUsages.csv`,
/// `AppResourceUseInfo.csv`, …), with the columns of every entry it holds, and
/// `SruDbIdMapTable.csv`; returns the number of files written.
fn write_csv_tables(dir: &Path, srum: &Srum) -> io::Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut tables: BTreeMap<String, CsvTable> = BTreeMap::new();
    for e in &srum.entries {
        tables.entry(output_name(e)).or_default().push(row(e));
    }
    let mut used = HashSet::new();
    for (name, table) in &tables {
        let path = dir.join(format!("{}.csv", safe_file_name(name, &mut used)));
        table.write(&path)?;
    }
    let mut ids = csv::Writer::from_path(dir.join("SruDbIdMapTable.csv"))?;
    ids.write_record(["IdIndex", "IdType", "IdBlob"])?;
    for id in &srum.ids {
        ids.write_record([
            id.index.to_string(),
            id.kind.name(),
            id.name.clone().unwrap_or_default(),
        ])?;
    }
    ids.flush()?;
    Ok(tables.len() + 1)
}

/// The rows of one CSV file, with every column any of them has, in the order first seen.
#[derive(Default)]
struct CsvTable {
    columns: Vec<String>,
    index: HashMap<String, usize>,
    rows: Vec<Vec<(String, Json)>>,
}

impl CsvTable {
    fn push(&mut self, row: Vec<(String, Json)>) {
        for (name, _) in &row {
            if !self.index.contains_key(name) {
                self.index.insert(name.clone(), self.columns.len());
                self.columns.push(name.clone());
            }
        }
        self.rows.push(row);
    }

    fn write(&self, path: &Path) -> io::Result<()> {
        let mut w = csv::Writer::from_path(path)?;
        w.write_record(&self.columns)?;
        let mut cells = vec![String::new(); self.columns.len()];
        for row in &self.rows {
            cells.iter_mut().for_each(String::clear);
            for (name, value) in row {
                cells[self.index[name]] = cell(value);
            }
            w.write_record(&cells)?;
        }
        w.flush()?;
        Ok(())
    }
}

/// A table name as a file name: only letters, digits and `-_{}` (a crafted table name can't
/// leave the directory), unique among the files written.
fn safe_file_name(name: &str, used: &mut HashSet<String>) -> String {
    let mut safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_{}".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() || safe.eq_ignore_ascii_case("SruDbIdMapTable") {
        safe.insert(0, '_');
    }
    let mut candidate = safe.clone();
    let mut n = 1;
    while !used.insert(candidate.to_ascii_lowercase()) {
        n += 1;
        candidate = format!("{safe}_{n}");
    }
    candidate
}

fn write_entries_to(
    path: &Path,
    srum: &Srum,
    source: &str,
    output_type: SrumOutputType,
) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut w = RecordWriter::new(Box::new(BufWriter::new(File::create(path)?)), output_type);
    for e in &srum.entries {
        w.entry(e, source)?;
    }
    w.finish()
}

/// The JSON / JSONL writer of one output.
struct RecordWriter {
    out: Box<dyn Write>,
    pretty: bool,
}

impl RecordWriter {
    fn new(out: Box<dyn Write>, output_type: SrumOutputType) -> Self {
        RecordWriter {
            out,
            pretty: output_type == SrumOutputType::Json,
        }
    }

    /// One entry: where it comes from, then its columns as in the CSV tables.
    fn entry(&mut self, e: &Entry, source: &str) -> io::Result<()> {
        let mut columns = vec![
            ("SourceFile".to_string(), json!(source)),
            ("Table".to_string(), json!(e.table)),
            ("Provider".to_string(), json!(output_name(e))),
        ];
        columns.extend(row(e));
        // JSON: a pretty object and a newline, like the other commands; JSONL: one per line.
        if self.pretty {
            serde_json::to_writer_pretty(&mut self.out, &Ordered(&columns))?;
        } else {
            serde_json::to_writer(&mut self.out, &Ordered(&columns))?;
        }
        self.out.write_all(b"\n")
    }

    fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

// --- summary ------------------------------------------------------------------------------------

/// Counts for the results summary.
#[derive(Default)]
struct Stats {
    databases: usize,
    failed: usize,
    dirty: usize,
    entries: BTreeMap<String, usize>,
    first: Option<Time>,
    last: Option<Time>,
    programs: HashSet<i64>,
    accounts: HashSet<String>,
    sent: u64,
    received: u64,
    senders: HashMap<String, u64>,
    hives: usize,
    without_hive: usize,
    account_names: usize,
    wifi_names: usize,
    problems: usize,
}

impl Stats {
    fn add(&mut self, srum: &Srum, context: Option<&Context>) {
        match context {
            Some(context) => {
                self.hives += 1;
                self.account_names += context.user_names.len();
                self.wifi_names += context.network_profiles.len();
            }
            None => self.without_hive += 1,
        }
        self.dirty += usize::from(srum.dirty);
        self.problems += srum.problems.len();
        for e in &srum.entries {
            *self.entries.entry(output_name(e)).or_default() += 1;
            if let Some(t) = e.time {
                self.first = Some(self.first.map_or(t, |f| f.min(t)));
                self.last = Some(self.last.map_or(t, |l| l.max(t)));
            }
            if e.app.is_some()
                && let Some(id) = e.app_id
            {
                self.programs.insert(id);
            }
            if let Some(sid) = &e.user {
                self.accounts.insert(sid.clone());
            }
            if e.kind == Some(Kind::NetworkUsage) {
                let bytes = |column: &str| {
                    e.value(column)
                        .and_then(Value::as_i64)
                        .and_then(|n| u64::try_from(n).ok())
                        .unwrap_or(0)
                };
                let sent = bytes("BytesSent");
                self.sent = self.sent.saturating_add(sent);
                self.received = self.received.saturating_add(bytes("BytesRecvd"));
                if sent > 0 {
                    let program = e.app.as_ref().map_or_else(
                        || format!("[AppId {}, no name]", e.app_id.unwrap_or_default()),
                        |a| a.name.clone(),
                    );
                    let total = self.senders.entry(program).or_default();
                    *total = total.saturating_add(sent);
                }
            }
        }
    }
}

fn print_summary(s: &Stats, no_color: bool) {
    p(JunteiColor::Green.rdg(no_color), "Results Summary:", true);
    p(None, "", true);
    let mut parsed = fmt_num(s.databases);
    if s.failed > 0 {
        parsed.push_str(&format!(" (could not parse: {})", fmt_num(s.failed)));
    }
    p_label(no_color, "SRUM databases parsed: ", &parsed);
    if s.dirty > 0 {
        p_label(
            no_color,
            "Left dirty (changes still only in SRU*.log are missing): ",
            &fmt_num(s.dirty),
        );
    }
    let total: usize = s.entries.values().sum();
    p_label(no_color, "Entries: ", &fmt_num(total));
    for (table, n) in &s.entries {
        p(None, &format!("  {table}: {}", fmt_num(*n)), true);
    }
    if let (Some(first), Some(last)) = (s.first, s.last) {
        p_label(
            no_color,
            "Time range: ",
            &format!("{} - {}", cell(&time(Some(first))), cell(&time(Some(last)))),
        );
    }
    p_label(
        no_color,
        "Programs / accounts: ",
        &format!(
            "{} / {}",
            fmt_num(s.programs.len()),
            fmt_num(s.accounts.len())
        ),
    );
    p_label(
        no_color,
        "Network: ",
        &format!(
            "{} sent, {} received",
            util::size_display(s.sent),
            util::size_display(s.received)
        ),
    );
    let mut senders: Vec<(&String, &u64)> = s.senders.iter().collect();
    senders.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    if !senders.is_empty() {
        p(JunteiColor::Green.rdg(no_color), "Top senders:", true);
        for (program, bytes) in senders.into_iter().take(TOP_SENDERS) {
            p(
                None,
                &format!("  {:>10}  {program}", util::size_display(*bytes)),
                true,
            );
        }
    }
    let names = match s.hives {
        0 => "none (no SOFTWARE hive found; give one with -r)".to_string(),
        n => format!(
            "from {} ({} accounts, {} Wi-Fi networks)",
            if n == 1 {
                "the SOFTWARE hive".to_string()
            } else {
                format!("{} SOFTWARE hives", fmt_num(n))
            },
            fmt_num(s.account_names),
            fmt_num(s.wifi_names)
        ),
    };
    p_label(no_color, "Account and Wi-Fi names: ", &names);
    if s.hives > 0 && s.without_hive > 0 {
        p_label(
            no_color,
            "Databases without a SOFTWARE hive: ",
            &fmt_num(s.without_hive),
        );
    }
    p_label(no_color, "Problems: ", &fmt_num(s.problems));
    p(None, "", true);
}

/// Whether a file name is a SRUM database: `SRUDB.dat`, or a name ending in it
/// (`HOST1_SRUDB.dat`).
pub fn is_database_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("srudb.dat")
}

/// The SRUM databases under `dir`, recursively, in path order.
pub fn find_databases(dir: &Path) -> Vec<PathBuf> {
    util::find_files(dir, is_database_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_names() {
        assert!(is_database_name("SRUDB.dat"));
        assert!(is_database_name("srudb.dat"));
        assert!(is_database_name("HOST1_SRUDB.dat"));
        assert!(!is_database_name("SRUDB.dat.LOG"));
        assert!(!is_database_name("SRU00001.log"));
    }

    #[test]
    fn the_software_hive_of_the_same_windows() {
        let dir = tempfile::tempdir().unwrap();
        let sru = dir.path().join("C/Windows/System32/sru");
        std::fs::create_dir_all(&sru).unwrap();
        let database = sru.join("SRUDB.dat");
        std::fs::write(&database, b"").unwrap();
        assert_eq!(software_hive(&database), None);
        // next to the database
        std::fs::write(sru.join("SOFTWARE"), b"").unwrap();
        assert_eq!(software_hive(&database), Some(sru.join("SOFTWARE")));
        // KAPE's layout first, names in any case
        let config = dir.path().join("C/Windows/System32/Config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("software"), b"").unwrap();
        assert_eq!(software_hive(&database), Some(config.join("software")));
    }

    #[test]
    fn values_and_names() {
        assert_eq!(file_name(r"C:\Users\alice"), "alice");
        assert_eq!(
            file_name(r"%systemroot%\system32\config\systemprofile"),
            "systemprofile"
        );
        assert_eq!(file_name("plain"), "plain");
        let mut hints = 4i32.to_le_bytes().to_vec();
        hints.extend_from_slice(b"Cafe and more");
        assert_eq!(channel_hints_ssid(&hints).unwrap().as_deref(), Some("Cafe"));
        assert_eq!(channel_hints_ssid(&[1, 0]).unwrap(), None);
        assert!(channel_hints_ssid(&[40, 0, 0, 0, b'x']).is_err());
        assert!(channel_hints_ssid(&(-1i32).to_le_bytes()).is_err());
        let g = [
            0x5c, 0x5d, 0x90, 0x97, 0x90, 0x1d, 0x44, 0x49, 0xbe, 0x9e, 0x24, 0xb9, 0x42, 0x31,
            0xa1, 0x74,
        ];
        assert_eq!(guid(&g), "{97905D5C-1D90-4944-BE9E-24B94231A174}");
        assert_eq!(cell(&json!(null)), "");
        assert_eq!(cell(&json!([1, "a"])), "1, a");
        assert_eq!(json_value(&Value::Binary(vec![0xab, 1])), json!("AB01"));
        assert_eq!(
            cell(&json_value(&Value::DateTime(44_630.690_960_648_15))),
            "2022-03-10T16:34:59Z"
        );
    }

    #[test]
    fn table_names_stay_in_the_directory() {
        let mut used = HashSet::new();
        assert_eq!(safe_file_name("NetworkUsages", &mut used), "NetworkUsages");
        assert_eq!(safe_file_name("../../evil", &mut used), "______evil");
        assert_eq!(
            safe_file_name("networkusages", &mut used),
            "networkusages_2"
        );
        assert_eq!(
            safe_file_name("SruDbIdMapTable", &mut used),
            "_SruDbIdMapTable"
        );
        assert_eq!(safe_file_name("", &mut used), "_");
    }
}
