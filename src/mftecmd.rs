//! `parse-mft`'s CSV: the columns of Eric Zimmerman's MFTECmd for `$MFT`, computed as MFTECmd
//! (and its MFT library) computes them, from the FILE records that ys-mft-parser reads: one row per
//! file name of every base record (in-use records first, then free ones), and one more per
//! alternate data stream, with the parent paths of MFTECmd's directory map, both sets of
//! timestamps and the timestomping indicators `SI<FN`, `uSecZeros` and `Copied`.
//!
//! The values come from the attributes' raw bytes, at the offsets MFTECmd reads, so that a value
//! MFTECmd treats as no time (zero, negative or past the year 9999) is no time here too.

use crate::cli::EntryRanges;
use crate::util;
use indicatif::ProgressBar;
use mft::attribute::MftAttributeType;
use mft::attribute::header::ResidentialHeader;
use mft::{MftEntry, MftParser};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, Write};

/// The columns, in MFTECmd's order and with its names.
pub const CSV_HEADER: [&str; 35] = [
    "EntryNumber",
    "SequenceNumber",
    "InUse",
    "ParentEntryNumber",
    "ParentSequenceNumber",
    "ParentPath",
    "FileName",
    "Extension",
    "FileSize",
    "ReferenceCount",
    "ReparseTarget",
    "IsDirectory",
    "HasAds",
    "IsAds",
    "SI<FN",
    "uSecZeros",
    "Copied",
    "SiFlags",
    "NameType",
    "Created0x10",
    "Created0x30",
    "LastModified0x10",
    "LastModified0x30",
    "LastRecordChange0x10",
    "LastRecordChange0x30",
    "LastAccess0x10",
    "LastAccess0x30",
    "UpdateSequenceNumber",
    "LogfileSequenceNumber",
    "SecurityId",
    "ObjectIdFileDroid",
    "LoggedUtilStream",
    "ZoneIdContents",
    "SourceFile",
    "ParseErrors",
];

/// MFTECmd's `$MFT` options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// `--at`: every `$FILE_NAME` time, not only those that differ from `$STANDARD_INFORMATION`.
    pub all_times: bool,
    /// `--sn`: rows for DOS (8.3) names too.
    pub short_names: bool,
    /// `--cutoff`, as a FILETIME: only records whose `$STANDARD_INFORMATION` created or modified
    /// time is on or after it.
    pub cutoff: Option<i64>,
}

/// An entry number and the sequence number that references to it use: a free record's is one
/// less than its own (NTFS raises it when the record is freed), so a deleted file still finds its
/// deleted directory. MFTECmd's record key.
type Key = (u64, i32);

const ROOT: Key = (5, 5);

/// The largest valid FILETIME: .NET's `DateTime.MaxValue` (the end of 9999).
const MAX_FILETIME: i64 = 2_650_467_743_999_999_999;

const NAMESPACE_DOS: u8 = 2;

/// A FILETIME, or nothing when MFTECmd would not show it as a time.
fn filetime(raw: i64) -> Option<i64> {
    (raw > 0 && raw <= MAX_FILETIME).then_some(raw)
}

fn i64_at(b: &[u8], at: usize) -> i64 {
    b.get(at..at + 8)
        .map_or(0, |s| i64::from_le_bytes(s.try_into().expect("8 bytes")))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    b.get(at..at + 4)
        .map_or(0, |s| i32::from_le_bytes(s.try_into().expect("4 bytes")))
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes(s.try_into().expect("2 bytes")))
}

/// A file reference: the entry number (48 bits) and the sequence number.
fn reference(b: &[u8], at: usize) -> (u64, u16) {
    let raw = u64_at(b, at);
    (raw & 0xFFFF_FFFF_FFFF, (raw >> 48) as u16)
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// `$STANDARD_INFORMATION`.
#[derive(Clone, Debug)]
struct StandardInfo {
    created: Option<i64>,
    modified: Option<i64>,
    changed: Option<i64>,
    accessed: Option<i64>,
    flags: i32,
    security_id: i32,
    usn: i64,
}

/// `$FILE_NAME`.
#[derive(Clone, Debug)]
struct FileName {
    parent: (u64, u16),
    created: Option<i64>,
    modified: Option<i64>,
    changed: Option<i64>,
    accessed: Option<i64>,
    logical_size: u64,
    namespace: u8,
    name: String,
}

impl FileName {
    fn parent_key(&self) -> Key {
        (self.parent.0, i32::from(self.parent.1))
    }
}

/// A `$DATA` attribute.
#[derive(Clone, Debug)]
struct Data {
    /// The stream name; empty for the file's content.
    name: String,
    /// The content of a resident stream (only kept for `Zone.Identifier`), and its size.
    resident: Option<(u64, Option<Vec<u8>>)>,
    /// The first VCN and the size of a non-resident stream.
    non_resident: Option<(u64, u64)>,
}

impl Data {
    /// The size MFTECmd shows: the resident content's, or the non-resident stream's.
    fn size(&self) -> u64 {
        match (&self.resident, self.non_resident) {
            (Some((len, _)), _) => *len,
            (None, Some((_, size))) => size,
            (None, None) => 0,
        }
    }
}

#[derive(Clone, Debug)]
enum Attr {
    Si(StandardInfo),
    Name(FileName),
    Data(Data),
    ObjectId(String),
    Reparse(String),
    LoggedUtilityStream(String),
}

/// A FILE record, as much of it as the columns need.
#[derive(Clone, Debug)]
struct Record {
    /// The entry number in the record (at 0x2C), else its position.
    entry: u64,
    sequence: u16,
    flags: u16,
    lsn: i64,
    base: (u64, u16),
    attrs: Vec<Attr>,
    errors: Vec<String>,
}

impl Record {
    /// The record, unless it isn't a FILE record (`BAAD`, or never written).
    fn of(entry: &MftEntry, position: u64) -> Option<Record> {
        if &entry.header.signature != b"FILE" {
            return None;
        }
        let data = &entry.data;
        // NTFS 3.0 records have no entry number (their fixup array starts at 0x2A).
        let number = if entry.header.usa_offset >= 0x30 && data.len() >= 0x30 {
            u64::from(u32::from_le_bytes(
                data[0x2C..0x30].try_into().expect("4 bytes"),
            ))
        } else {
            position
        };
        let mut record = Record {
            entry: number,
            sequence: entry.header.sequence,
            flags: entry.header.flags.bits(),
            lsn: i64_at(data, 0x08),
            base: (
                entry.header.base_reference.entry,
                entry.header.base_reference.sequence,
            ),
            attrs: Vec::new(),
            errors: Vec::new(),
        };
        if entry.valid_fixup == Some(false) {
            record.errors.push("fixup values do not match".to_string());
        }
        for item in entry.iter_attribute_records_matching(None) {
            let (header, raw) = match item {
                Ok(item) => item,
                Err(e) => {
                    record.errors.push(format!("attribute not readable: {e}"));
                    continue;
                }
            };
            // A resident value that doesn't fit in the record (or a value too short for its
            // attribute) is a damaged attribute: MFTECmd leaves it out and says so in ParseErrors.
            let value = || match &header.residential_header {
                ResidentialHeader::Resident(r) => r.value(raw).map_err(|_| {
                    format!(
                        "its value (0x{:X} bytes at 0x{:X}) runs past the end of the attribute",
                        r.data_size, r.data_offset
                    )
                }),
                ResidentialHeader::NonResident(_) => Err("not resident".to_string()),
            };
            let attr: Result<Option<Attr>, String> = match header.type_code {
                MftAttributeType::StandardInformation => standard_info(raw).map(Some),
                MftAttributeType::FileName => value().and_then(file_name).map(Some),
                MftAttributeType::DATA => {
                    let name = header.name.to_utf8_string();
                    match &header.residential_header {
                        ResidentialHeader::Resident(r) => value().map(|content| {
                            let keep = (name == "Zone.Identifier").then(|| content.to_vec());
                            Some(Attr::Data(Data {
                                name,
                                resident: Some((u64::from(r.data_size), keep)),
                                non_resident: None,
                            }))
                        }),
                        ResidentialHeader::NonResident(n) => Ok(Some(Attr::Data(Data {
                            name,
                            resident: None,
                            non_resident: Some((n.vnc_first, n.file_size)),
                        }))),
                    }
                }
                MftAttributeType::ObjectId => value().and_then(|v| match v.get(..16) {
                    Some(id) => Ok(Some(Attr::ObjectId(guid(id)))),
                    None => Err(format!("{} bytes, an object ID needs 16", v.len())),
                }),
                MftAttributeType::ReparsePoint => {
                    value().map(|v| Some(Attr::Reparse(reparse_target(v))))
                }
                MftAttributeType::LoggedUtilityStream => Ok(Some(Attr::LoggedUtilityStream(
                    header.name.to_utf8_string(),
                ))),
                _ => Ok(None),
            };
            match attr {
                Ok(Some(attr)) => record.attrs.push(attr),
                Ok(None) => {}
                Err(e) => record.errors.push(format!(
                    "{} attribute at 0x{:X} left out: {e}",
                    attribute_name(header.type_code),
                    header.start_offset
                )),
            }
        }
        Some(record)
    }

    fn in_use(&self) -> bool {
        self.flags & 1 != 0
    }

    fn is_dir(&self) -> bool {
        self.flags & 2 != 0
    }

    /// An extension record: one that names its base record (MFTECmd needs both numbers nonzero).
    fn is_extension(&self) -> bool {
        self.base.0 > 0 && self.base.1 > 0
    }

    fn key(&self) -> Key {
        let sequence = i32::from(self.sequence);
        (
            self.entry,
            if self.in_use() {
                sequence
            } else {
                sequence - 1
            },
        )
    }

    fn base_key(&self) -> Key {
        (self.base.0, i32::from(self.base.1))
    }

    fn names(&self) -> impl Iterator<Item = &FileName> {
        self.attrs.iter().filter_map(|a| match a {
            Attr::Name(n) => Some(n),
            _ => None,
        })
    }

    /// The first name that isn't a DOS name, with its parent: what MFTECmd's directory map
    /// keeps.
    fn first_long_name(&self) -> Option<DirName> {
        self.names()
            .find(|n| n.namespace != NAMESPACE_DOS)
            .map(|n| DirName {
                name: n.name.clone(),
                parent: n.parent_key(),
            })
    }
}

/// The NTFS name of an attribute type, for `ParseErrors`.
fn attribute_name(t: MftAttributeType) -> &'static str {
    match t {
        MftAttributeType::StandardInformation => "$STANDARD_INFORMATION",
        MftAttributeType::FileName => "$FILE_NAME",
        MftAttributeType::DATA => "$DATA",
        MftAttributeType::ObjectId => "$OBJECT_ID",
        MftAttributeType::ReparsePoint => "$REPARSE_POINT",
        MftAttributeType::LoggedUtilityStream => "$LOGGED_UTILITY_STREAM",
        _ => "an",
    }
}

/// `$STANDARD_INFORMATION` at MFTECmd's offsets in the attribute record (the value starts at
/// 0x18); the owner, security and USN fields only when the record is longer than 0x48 bytes.
fn standard_info(raw: &[u8]) -> Result<Attr, String> {
    if raw.len() < 0x48 {
        return Err(format!("{} bytes, it needs 0x48", raw.len()));
    }
    let long = raw.len() > 0x48;
    Ok(Attr::Si(StandardInfo {
        created: filetime(i64_at(raw, 0x18)),
        modified: filetime(i64_at(raw, 0x20)),
        changed: filetime(i64_at(raw, 0x28)),
        accessed: filetime(i64_at(raw, 0x30)),
        flags: i32_at(raw, 0x38),
        security_id: if long { i32_at(raw, 0x4C) } else { 0 },
        usn: if long { i64_at(raw, 0x58) } else { 0 },
    }))
}

/// `$FILE_NAME` from its value.
fn file_name(v: &[u8]) -> Result<Attr, String> {
    let too_short = || format!("{} bytes, too short for its name", v.len());
    let length = usize::from(*v.get(0x40).ok_or_else(too_short)?);
    let name = v.get(0x42..0x42 + length * 2).ok_or_else(too_short)?;
    Ok(Attr::Name(FileName {
        parent: reference(v, 0),
        created: filetime(i64_at(v, 0x08)),
        modified: filetime(i64_at(v, 0x10)),
        changed: filetime(i64_at(v, 0x18)),
        accessed: filetime(i64_at(v, 0x20)),
        logical_size: u64_at(v, 0x30),
        namespace: v[0x41],
        name: utf16(name),
    }))
}

/// A GUID as .NET writes it (`Guid.ToString()`): lowercase, the first three fields little-endian.
fn guid(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// The substitute name of a symbolic link or a junction (mount point), without `\??\`: the target
/// MFTECmd shows. Other reparse points have none.
fn reparse_target(v: &[u8]) -> String {
    const MOUNT_POINT: u32 = 0xA000_0003;
    const SYMBOLIC_LINK: u32 = 0xA000_000C;
    if v.len() <= 8 {
        return String::new();
    }
    let tag = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
    let path_buffer = match tag {
        MOUNT_POINT => 0x10,
        SYMBOLIC_LINK => 0x14,
        _ => return String::new(),
    };
    let offset = usize::from(u16_at(v, 8));
    let length = usize::from(u16_at(v, 10));
    v.get(path_buffer + offset..path_buffer + offset + length)
        .map(utf16)
        .unwrap_or_default()
        .replace(r"\??\", "")
}

/// The name of a directory in MFTECmd's directory map, and the key of its parent.
#[derive(Clone, Debug)]
struct DirName {
    name: String,
    parent: Key,
}

/// What MFTECmd knows of the whole MFT before it writes a row: the base records, the extension
/// records of each, and the names of the directories.
struct Index {
    base_keys: HashSet<Key>,
    /// The positions of the extension records that name each base key, in MFT order.
    extensions: HashMap<Key, Vec<u64>>,
    dirs: HashMap<Key, DirName>,
}

impl Index {
    fn build<R: Read + Seek>(parser: &mut MftParser<R>, bar: Option<&ProgressBar>) -> Index {
        // (in use, key, the directory's own first long name, its position)
        let mut dir_bases: Vec<(bool, Key, Option<DirName>)> = Vec::new();
        let mut base_keys = HashSet::new();
        let mut extensions: HashMap<Key, Vec<u64>> = HashMap::new();
        // The extension keys in the order they first appear, and what each extension record is.
        let mut extension_order: Vec<Key> = Vec::new();
        let mut extension_names: HashMap<u64, (bool, Option<DirName>)> = HashMap::new();
        for position in 0..parser.get_entry_count() {
            if let Some(b) = bar {
                b.inc(1);
            }
            let Some(record) = parser
                .get_entry(position)
                .ok()
                .and_then(|e| Record::of(&e, position))
            else {
                continue;
            };
            if record.is_extension() {
                let key = record.base_key();
                let positions = extensions.entry(key).or_default();
                if positions.is_empty() {
                    extension_order.push(key);
                }
                positions.push(position);
                extension_names.insert(position, (record.is_dir(), record.first_long_name()));
            } else {
                base_keys.insert(record.key());
                if record.is_dir() {
                    dir_bases.push((record.in_use(), record.key(), record.first_long_name()));
                }
            }
        }
        // In-use directories first, then free ones; the first name for a key wins. A directory's
        // name is its first long name, in its own record or else in its extension records.
        let mut dirs: HashMap<Key, DirName> = HashMap::new();
        for in_use in [true, false] {
            for (_, key, own) in dir_bases.iter().filter(|(u, ..)| *u == in_use) {
                let name = own.clone().or_else(|| {
                    extensions.get(key).and_then(|positions| {
                        positions
                            .iter()
                            .find_map(|p| extension_names.get(p).and_then(|(_, n)| n.clone()))
                    })
                });
                if let Some(name) = name {
                    dirs.entry(*key).or_insert(name);
                }
            }
        }
        // Then the directories whose base record is gone: their extension records' names.
        for key in &extension_order {
            if base_keys.contains(key) {
                continue;
            }
            for position in &extensions[key] {
                if let Some((true, Some(name))) = extension_names.get(position) {
                    dirs.entry(*key).or_insert_with(|| name.clone());
                }
            }
        }
        Index {
            base_keys,
            extensions,
            dirs,
        }
    }

    /// The path of the directory `key`, as MFTECmd builds it: `.` for the root, then the names
    /// down to the directory; a chain that doesn't reach the root (a missing directory, or a
    /// loop) starts with `.\PathUnknown\Directory with ID 0x<entry>-<sequence>`.
    fn parent_path(&self, key: Key) -> String {
        let mut names: Vec<&str> = Vec::new();
        let mut seen = HashSet::new();
        let mut current = key;
        while let Some(dir) = self.dirs.get(&current) {
            if !seen.insert(current) {
                break;
            }
            names.push(&dir.name);
            if current == ROOT {
                break;
            }
            current = dir.parent;
        }
        let mut path = String::new();
        if current != ROOT {
            // MFTECmd formats the key as two 8-digit hex numbers.
            path = format!(
                ".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}",
                current.0, current.1
            );
        }
        for name in names.iter().rev() {
            if !path.is_empty() {
                path.push('\\');
            }
            path.push_str(name);
        }
        path
    }
}

/// `$STANDARD_INFORMATION` flags as .NET writes MFTECmd's flags enum, `|` between the names;
/// the number when a bit has no name.
fn si_flags(value: i32) -> String {
    const NAMES: [(u32, &str); 24] = [
        (0x1, "ReadOnly"),
        (0x2, "Hidden"),
        (0x4, "System"),
        (0x8, "VolumeLabel"),
        (0x10, "Directory"),
        (0x20, "Archive"),
        (0x40, "Device"),
        (0x80, "Normal"),
        (0x100, "Temporary"),
        (0x200, "SparseFile"),
        (0x400, "ReparsePoint"),
        (0x800, "Compressed"),
        (0x1000, "Offline"),
        (0x2000, "NotContentIndexed"),
        (0x4000, "Encrypted"),
        (0x8000, "IntegrityStream"),
        (0x1_0000, "Virtual"),
        (0x2_0000, "NoScrubData"),
        (0x4_0000, "RecallOnOpen"),
        (0x8_0000, "Pinned"),
        (0x10_0000, "UnPinned"),
        (0x40_0000, "RecallOnDataAccess"),
        (0x1000_0000, "IsDirectory"),
        (0x2000_0000, "IsIndexView"),
    ];
    if value == 0 {
        return "None".to_string();
    }
    let bits = value as u32;
    let named = NAMES.iter().fold(0, |acc, (bit, _)| acc | bit);
    if bits & !named != 0 {
        return value.to_string();
    }
    NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

fn name_type(namespace: u8) -> String {
    match namespace {
        0 => "Posix".to_string(),
        1 => "Windows".to_string(),
        2 => "Dos".to_string(),
        3 => "DosWindows".to_string(),
        n => n.to_string(),
    }
}

/// A FILETIME as an RFC 3339 UTC time with its 100 ns (7 decimals), like `parse-mft`'s JSON.
fn time(t: Option<i64>) -> String {
    t.and_then(|ft| {
        let unix = ft - 116_444_736_000_000_000;
        chrono::DateTime::from_timestamp(unix.div_euclid(10_000_000), 0).map(|d| {
            format!(
                "{}.{:07}Z",
                d.format("%Y-%m-%dT%H:%M:%S"),
                unix.rem_euclid(10_000_000)
            )
        })
    })
    .unwrap_or_default()
}

/// Windows-1252 text, all of it (MFTECmd decodes `Zone.Identifier` with this code page).
fn windows_1252(bytes: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
        '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}',
        'ž', 'Ÿ',
    ];
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => HIGH[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

fn flag(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

/// Whether the millisecond part of a time is zero (.NET's `DateTimeOffset.Millisecond`).
fn whole_millisecond(t: Option<i64>) -> bool {
    t.is_some_and(|ft| (ft / 10_000) % 1000 == 0)
}

/// `a < b` when both are times.
fn earlier(a: Option<i64>, b: Option<i64>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a < b)
}

/// Write the rows of every base record (in-use first, then free; only those in `ranges`).
/// Returns how many rows were written.
pub fn write<R: Read + Seek>(
    parser: &mut MftParser<R>,
    source: &str,
    options: Options,
    ranges: Option<&EntryRanges>,
    out: &mut csv::Writer<Box<dyn Write>>,
    bar: Option<&ProgressBar>,
) -> io::Result<u64> {
    let index = Index::build(parser, bar);
    let in_ranges =
        |position: u64| ranges.is_none_or(|r| r.0.iter().any(|range| range.contains(&position)));
    let mut written = 0;
    let mut free = Vec::new();
    for position in 0..parser.get_entry_count() {
        if let Some(b) = bar {
            b.inc(1);
        }
        let Some(record) = parser
            .get_entry(position)
            .ok()
            .and_then(|e| Record::of(&e, position))
        else {
            continue;
        };
        if record.is_extension() || !in_ranges(position) {
            continue;
        }
        if record.in_use() {
            written += write_record(parser, &index, record, source, options, out)?;
        } else {
            free.push(position);
        }
    }
    for position in free {
        if let Some(record) = parser
            .get_entry(position)
            .ok()
            .and_then(|e| Record::of(&e, position))
        {
            written += write_record(parser, &index, record, source, options, out)?;
        }
    }
    Ok(written)
}

/// The rows of one base record, with its extension records' attributes after its own.
fn write_record<R: Read + Seek>(
    parser: &mut MftParser<R>,
    index: &Index,
    mut record: Record,
    source: &str,
    options: Options,
    out: &mut csv::Writer<Box<dyn Write>>,
) -> io::Result<u64> {
    let key = record.key();
    if index.base_keys.contains(&key)
        && let Some(positions) = index.extensions.get(&key)
    {
        for position in positions {
            if let Some(extension) = parser
                .get_entry(*position)
                .ok()
                .and_then(|e| Record::of(&e, *position))
            {
                record.attrs.extend(extension.attrs);
            }
        }
    }
    let rows = rows(&record, index, source, options);
    for row in &rows {
        out.write_record(row).map_err(io::Error::other)?;
    }
    Ok(rows.len() as u64)
}

/// What the rows of a record share.
struct Shared<'a> {
    si: Option<&'a StandardInfo>,
    file_size: u64,
    reference_count: usize,
    reparse_target: &'a str,
    object_id: &'a str,
    logged_utility_stream: &'a str,
    streams: Vec<&'a Data>,
    errors: String,
}

fn rows(record: &Record, index: &Index, source: &str, options: Options) -> Vec<Vec<String>> {
    let first = |pick: fn(&Attr) -> Option<&str>| record.attrs.iter().find_map(pick).unwrap_or("");
    let data: Vec<&Data> = record
        .attrs
        .iter()
        .filter_map(|a| match a {
            Attr::Data(d) => Some(d),
            _ => None,
        })
        .collect();
    // The file size: 0 for a directory, else the first $DATA attribute's, else the first name's.
    let file_size = if record.is_dir() {
        0
    } else if let Some(d) = data.first() {
        d.size()
    } else {
        record.names().next().map_or(0, |n| n.logical_size)
    };
    let mut links = HashSet::new();
    for n in record.names().filter(|n| n.namespace != NAMESPACE_DOS) {
        links.insert((n.name.as_str(), n.parent_key()));
    }
    let shared = Shared {
        si: record.attrs.iter().find_map(|a| match a {
            Attr::Si(si) => Some(si),
            _ => None,
        }),
        file_size,
        reference_count: links.len(),
        reparse_target: first(|a| match a {
            Attr::Reparse(t) => Some(t.as_str()),
            _ => None,
        }),
        object_id: first(|a| match a {
            Attr::ObjectId(g) => Some(g.as_str()),
            _ => None,
        }),
        logged_utility_stream: first(|a| match a {
            Attr::LoggedUtilityStream(n) => Some(n.as_str()),
            _ => None,
        }),
        // Named streams; a non-resident stream continued from another record counts once.
        streams: data
            .into_iter()
            .filter(|d| !d.name.is_empty() && d.non_resident.is_none_or(|(vcn, _)| vcn == 0))
            .collect(),
        errors: record.errors.join("; "),
    };
    let mut names: Vec<&FileName> = record.names().collect();
    names.sort_by_key(|n| n.namespace);
    let mut rows = Vec::new();
    for name in names {
        if name.namespace == NAMESPACE_DOS && !options.short_names {
            continue;
        }
        let (row, created, modified) = row(record, index, &shared, name, None, source, options);
        if let Some(cutoff) = options.cutoff
            && !(created.is_some_and(|t| t >= cutoff) || modified.is_some_and(|t| t >= cutoff))
        {
            continue;
        }
        rows.push(row);
        for stream in &shared.streams {
            rows.push(row_for(
                record, index, &shared, name, stream, source, options,
            ));
        }
    }
    rows
}

fn row_for(
    record: &Record,
    index: &Index,
    shared: &Shared,
    name: &FileName,
    stream: &Data,
    source: &str,
    options: Options,
) -> Vec<String> {
    row(record, index, shared, name, Some(stream), source, options).0
}

/// A row's timestamps (the `0x10` ones and, where shown, the `0x30` ones) and what MFTECmd
/// derives from them.
struct Times {
    created: Option<i64>,
    created_fn: Option<i64>,
    modified: Option<i64>,
    modified_fn: Option<i64>,
    changed: Option<i64>,
    changed_fn: Option<i64>,
    accessed: Option<i64>,
    accessed_fn: Option<i64>,
    stomped: bool,
    zeros: bool,
    copied: bool,
    flags: i32,
    security_id: i32,
    usn: i64,
}

/// `$STANDARD_INFORMATION`'s times, and `$FILE_NAME`'s where they differ (all of them with
/// `--at`); the timestomping indicators: `SI<FN` (`$STANDARD_INFORMATION` created before a
/// different `$FILE_NAME` created), `uSecZeros` (created or modified on a whole millisecond) and
/// `Copied` (modified before created). Without `$STANDARD_INFORMATION`, `$FILE_NAME`'s times go
/// where MFTECmd puts them: created in `Created0x30`, the others in the `0x10` columns.
fn times(si: Option<&StandardInfo>, name: &FileName, all: bool) -> Times {
    let Some(si) = si else {
        return Times {
            created: None,
            created_fn: name.created,
            modified: name.modified,
            modified_fn: None,
            changed: name.changed,
            changed_fn: None,
            accessed: name.accessed,
            accessed_fn: None,
            stomped: false,
            zeros: false,
            copied: false,
            flags: 0,
            security_id: 0,
            usn: 0,
        };
    };
    let shown = |fn_time: Option<i64>, si_time: Option<i64>| {
        if all || fn_time != si_time {
            fn_time
        } else {
            None
        }
    };
    let created_fn = shown(name.created, si.created);
    Times {
        created: si.created,
        created_fn,
        modified: si.modified,
        modified_fn: shown(name.modified, si.modified),
        changed: si.changed,
        changed_fn: shown(name.changed, si.changed),
        accessed: si.accessed,
        accessed_fn: shown(name.accessed, si.accessed),
        stomped: created_fn.is_some() && earlier(si.created, created_fn),
        zeros: whole_millisecond(si.created) || whole_millisecond(si.modified),
        copied: earlier(si.modified, si.created),
        flags: si.flags,
        security_id: si.security_id,
        usn: si.usn,
    }
}

/// One row, and its `Created0x10` and `LastModified0x10` (for `--cutoff`).
#[allow(clippy::too_many_arguments)]
fn row(
    record: &Record,
    index: &Index,
    shared: &Shared,
    name: &FileName,
    stream: Option<&Data>,
    source: &str,
    options: Options,
) -> (Vec<String>, Option<i64>, Option<i64>) {
    let mut file_name = name.name.clone();
    let mut extension = if record.is_dir() {
        String::new()
    } else {
        util::dotnet_extension(&name.name).to_string()
    };
    let mut file_size = shared.file_size;
    let mut zone = String::new();
    if let Some(s) = stream {
        file_name = format!("{}:{}", name.name, s.name);
        file_size = s.size();
        extension = util::dotnet_extension(&s.name).to_string();
        if s.name == "Zone.Identifier" {
            zone = match &s.resident {
                Some((_, Some(content))) => windows_1252(content),
                Some((_, None)) => String::new(),
                None => "(Zone.Identifier data is non-resident)".to_string(),
            };
        }
    }

    let t = times(shared.si, name, options.all_times);
    let row = vec![
        record.entry.to_string(),
        record.sequence.to_string(),
        flag(record.in_use()).to_string(),
        name.parent.0.to_string(),
        name.parent.1.to_string(),
        index.parent_path(name.parent_key()),
        file_name,
        extension,
        file_size.to_string(),
        shared.reference_count.to_string(),
        shared.reparse_target.to_string(),
        flag(record.is_dir()).to_string(),
        flag(stream.is_none() && !shared.streams.is_empty()).to_string(),
        flag(stream.is_some()).to_string(),
        flag(t.stomped).to_string(),
        flag(t.zeros).to_string(),
        flag(t.copied).to_string(),
        si_flags(t.flags),
        name_type(name.namespace),
        time(t.created),
        time(t.created_fn),
        time(t.modified),
        time(t.modified_fn),
        time(t.changed),
        time(t.changed_fn),
        time(t.accessed),
        time(t.accessed_fn),
        t.usn.to_string(),
        record.lsn.to_string(),
        t.security_id.to_string(),
        shared.object_id.to_string(),
        shared.logged_utility_stream.to_string(),
        zone,
        source.to_string(),
        shared.errors.clone(),
    ];
    (row, t.created, t.modified)
}

/// `--cutoff`: a date (`2025-10-19`), a date and time (`2025-10-19 13:45:30`) in UTC, or an
/// RFC 3339 time with its offset (`2025-10-19T13:45:30+09:00`), as a FILETIME.
pub fn parse_cutoff(s: &str) -> Result<i64, String> {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};
    let s = s.trim();
    let utc = DateTime::parse_from_rfc3339(s)
        .map(|t| t.naive_utc())
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .or_else(|_| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map(|d| d.and_hms_opt(0, 0, 0).expect("midnight"))
        })
        .map_err(|_| {
            format!("'{s}' is not a date or time (ex: 2025-10-19 or 2025-10-19T13:45:30Z)")
        })?;
    let t = utc.and_utc();
    t.timestamp()
        .checked_mul(10_000_000)
        .and_then(|ticks| ticks.checked_add(i64::from(t.timestamp_subsec_nanos() / 100)))
        .and_then(|ticks| ticks.checked_add(116_444_736_000_000_000))
        .filter(|ft| (0..=MAX_FILETIME).contains(ft))
        .ok_or_else(|| {
            format!("'{s}' is outside the times NTFS can hold (1601-01-01 to 9999-12-31)")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(si_flags(0), "None");
        assert_eq!(si_flags(0x6), "Hidden|System");
        assert_eq!(si_flags(0x2020), "Archive|NotContentIndexed");
        assert_eq!(si_flags(0x20_0000), (0x20_0000).to_string());
        assert_eq!(si_flags(0x8000_0020u32 as i32), "-2147483616");
        assert_eq!(name_type(3), "DosWindows");
        assert_eq!(name_type(7), "7");
        // 2007-06-30 12:50:52.2523952 UTC
        assert_eq!(
            time(Some(128_276_814_522_523_952)),
            "2007-06-30T12:50:52.2523952Z"
        );
        assert_eq!(time(filetime(0)), "");
        assert_eq!(time(filetime(-5)), "");
        assert_eq!(time(filetime(MAX_FILETIME + 1)), "");
        assert!(whole_millisecond(Some(128_276_454_520_000_123)));
        assert!(!whole_millisecond(Some(128_276_454_522_523_952)));
        assert!(!whole_millisecond(None));
        assert!(earlier(Some(1), Some(2)) && !earlier(None, Some(2)) && !earlier(Some(2), Some(2)));
        assert_eq!(
            guid(&[
                0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
                0x56, 0x78
            ]),
            "12345678-1234-5678-9abc-def012345678"
        );
    }

    #[test]
    fn reparse_targets() {
        // A junction: tag, data length, substitute (offset 0, 12 bytes), print name after it.
        let mut v = vec![0x03, 0x00, 0x00, 0xA0, 0, 0, 0, 0];
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&12u16.to_le_bytes());
        v.extend_from_slice(&14u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        for c in r"\??\C:".encode_utf16().chain("C:".encode_utf16()) {
            v.extend_from_slice(&c.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]);
        assert_eq!(reparse_target(&v), "C:");
        // Another tag has no target; a header without data has none either.
        v[0] = 0x17;
        v[3] = 0x80;
        assert_eq!(reparse_target(&v), "");
        assert_eq!(reparse_target(&v[..8]), "");
    }

    #[test]
    fn parent_paths() {
        let dir = |name: &str, parent: Key| DirName {
            name: name.to_string(),
            parent,
        };
        let index = Index {
            base_keys: HashSet::new(),
            extensions: HashMap::new(),
            dirs: HashMap::from([
                (ROOT, dir(".", ROOT)),
                ((30, 1), dir("Windows", ROOT)),
                ((31, 1), dir("System32", (30, 1))),
                ((40, 2), dir("lost", (99, 3))),
                ((50, 1), dir("a", (51, 1))),
                ((51, 1), dir("b", (50, 1))),
            ]),
        };
        assert_eq!(index.parent_path(ROOT), ".");
        assert_eq!(index.parent_path((31, 1)), r".\Windows\System32");
        assert_eq!(
            index.parent_path((40, 2)),
            r".\PathUnknown\Directory with ID 0x00000063-00000003\lost"
        );
        assert_eq!(
            index.parent_path((77, 1)),
            r".\PathUnknown\Directory with ID 0x0000004D-00000001"
        );
        // a loop: a, its parent b, then a again (MFTECmd's stack gives the names in that order)
        assert_eq!(
            index.parent_path((50, 1)),
            r".\PathUnknown\Directory with ID 0x00000032-00000001\b\a"
        );
    }

    #[test]
    fn cutoffs() {
        let day = parse_cutoff("2025-10-19").unwrap();
        assert_eq!(parse_cutoff("2025-10-19T00:00:00Z").unwrap(), day);
        assert_eq!(
            parse_cutoff("2025-10-19 09:00:00").unwrap(),
            day + 9 * 36_000_000_000
        );
        assert_eq!(
            parse_cutoff("2025-10-19T09:00:00+09:00").unwrap(),
            day,
            "the offset is applied"
        );
        assert!(parse_cutoff("yesterday").is_err());
        // the times a FILETIME can hold, and no overflow past them
        assert_eq!(parse_cutoff("1601-01-01").unwrap(), 0);
        assert_eq!(
            parse_cutoff("9999-12-31T23:59:59.9999999Z").unwrap(),
            MAX_FILETIME
        );
        for outside in [
            "1600-12-31",
            "+262142-12-31T23:59:59",
            "-262143-01-01T00:00:00",
        ] {
            let e = parse_cutoff(outside).unwrap_err();
            assert!(
                e.contains("outside the times NTFS can hold"),
                "{outside}: {e}"
            );
        }
    }
}
