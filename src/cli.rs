//! Command line definition (clap derive). Option letters and help headings follow Hayabusa so a
//! user of the sibling tools finds the same flags in the same places.

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use std::ops::RangeInclusive;
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str =
    "Yamato Security (https://github.com/Yamato-Security/juntei - @SecurityYamato)";

#[derive(Parser)]
#[command(name = "juntei")]
#[command(version = VERSION)]
#[command(author = AUTHOR)]
#[command(about = "Windows forensics artifact parser")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

// The variant names are the command names (parse-amcache, parse-mft, ...).
#[allow(clippy::enum_variant_names)]
#[derive(Subcommand)]
pub enum Commands {
    /// Parse Amcache.hve: inventoried executables (with SHA-1), PnP devices and findings
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-amcache <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseAmcache(AmcacheOptions),

    /// Parse $MFT: every file record with its full path, flags, sizes and timestamps
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-mft <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseMft(MftOptions),

    /// Parse Prefetch files (*.pf): executions with run counts, last run times and loaded files
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-prefetch <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParsePrefetch(PrefetchOptions),

    /// Parse the USN journal ($UsnJrnl:$J): every file change with its reasons and the path it had
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-usn-journal <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseUsnJournal(UsnJournalOptions),

    /// Parse SRUM (SRUDB.dat): about 30 days of network and resource usage per program and user
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-srum <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseSrum(SrumOptions),

    /// Parse shortcuts (*.lnk): what each points at, its arguments and the machine it was made on
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-lnk <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseLnk(LnkOptions),

    /// Parse jump lists: files and folders each application opened, pinned items and tasks
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-jump-lists <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseJumpLists(JumpListOptions),

    /// Parse the ShimCache (AppCompatCache) of SYSTEM hives: executables Windows saw, with their times and whether they ran
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-shimcache <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseShimcache(ShimcacheOptions),

    /// Parse Microsoft Defender's quarantine: what was quarantined, for which threat and when, and the quarantined files' hashes, owners and download origins (extracted only with --extract)
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-defender-quarantine <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseDefenderQuarantine(DefenderQuarantineOptions),

    /// Parse registry hives: every key and value, with last-write times, types and data; dirty hives replayed with their transaction logs
    #[command(
        author = AUTHOR,
        version = VERSION,
        help_template = "\nVersion: {version}\n{author-with-newline}\n{usage-heading}\n  juntei parse-registry <INPUT> [OPTIONS]\n\n{all-args}",
        disable_help_flag = true,
        disable_version_flag = true
    )]
    ParseRegistry(RegistryOptions),
}

#[derive(Args, Clone, Debug, Default)]
pub struct CommonOptions {
    /// Show the help menu
    #[clap(help_heading = Some("General Options"), short = 'h', long = "help", action = ArgAction::Help, required = false, display_order = 10)]
    pub help: Option<bool>,

    /// Disable color output
    #[arg(help_heading = Some("Display Settings"), short = 'K', long = "no-color", global = true, display_order = 400)]
    pub no_color: bool,

    /// Quiet mode: do not display the launch banner
    #[arg(help_heading = Some("Display Settings"), short, long, global = true, display_order = 401)]
    pub quiet: bool,
}

/// What `parse-amcache` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputType {
    /// One CSV table per record type (summary, findings, files, devices); needs -o <DIR>
    Csv,
    /// One pretty-printed JSON document per hive
    Json,
    /// One JSON object per line: summary, findings, files, devices
    Jsonl,
    /// The human-readable report
    Text,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct AmcacheOptions {
    /// Directory to search recursively for Amcache hives (Amcache.hve)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one Amcache.hve
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Include every inventoried executable (InventoryApplicationFile)
    #[arg(help_heading = Some("Records"), long, display_order = 200)]
    pub files: bool,

    /// Include every inventoried PnP device (InventoryDevicePnp)
    #[arg(help_heading = Some("Records"), long, display_order = 201)]
    pub devices: bool,

    /// Include executables and devices (default for -o and for json, jsonl, csv)
    #[arg(help_heading = Some("Records"), short = 'a', long, display_order = 202)]
    pub all: bool,

    /// Save the results to a file (text, json, jsonl) or a directory (csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "PATH", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default with -o), json, jsonl, text (default on the terminal)
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<OutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl AmcacheOptions {
    /// The output type: `-t`, otherwise csv when saving with `-o` and text on the terminal.
    pub fn output_type(&self) -> OutputType {
        self.output_type.unwrap_or(if self.output.is_some() {
            OutputType::Csv
        } else {
            OutputType::Text
        })
    }

    /// Which detailed records to include: the selectors, otherwise every record except for the
    /// text report on the terminal (summary and findings only, like ys-amcache-parser).
    pub fn records(&self) -> (bool, bool) {
        if self.all || (!self.files && !self.devices && self.saves_records_by_default()) {
            (true, true)
        } else {
            (self.files, self.devices)
        }
    }

    fn saves_records_by_default(&self) -> bool {
        self.output.is_some() || self.output_type() != OutputType::Text
    }

    /// Structured output (json, jsonl) on stdout: nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && matches!(self.output_type(), OutputType::Json | OutputType::Jsonl)
    }
}

/// What `parse-mft` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MftOutputType {
    /// One row per file name and per alternate data stream
    Csv,
    /// One row per entry (the columns of ys-mft-parser, upstream's mft_dump)
    #[value(alias = "mft-dump-csv")]
    YsMftParserCsv,
    /// One pretty-printed JSON object per entry
    Json,
    /// One JSON object per line
    Jsonl,
}

impl MftOutputType {
    pub fn extension(&self) -> &'static str {
        match self {
            MftOutputType::Csv | MftOutputType::YsMftParserCsv => "csv",
            MftOutputType::Json => "json",
            MftOutputType::Jsonl => "jsonl",
        }
    }
}

/// Entry numbers to parse: `0-15,30`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRanges(pub Vec<RangeInclusive<u64>>);

impl EntryRanges {
    /// How many entry numbers the ranges hold.
    pub fn len(&self) -> u64 {
        self.0
            .iter()
            .map(|r| r.end().saturating_sub(*r.start()).saturating_add(1))
            .fold(0u64, u64::saturating_add)
    }
}

fn parse_ranges(s: &str) -> Result<EntryRanges, String> {
    let mut ranges = Vec::new();
    for part in s.split(',').map(str::trim) {
        let number = |n: &str| {
            n.trim()
                .parse::<u64>()
                .map_err(|_| format!("'{part}' is not an entry number or a range (ex: 0-15,30)"))
        };
        let range = match part.split_once('-') {
            Some((a, b)) => number(a)?..=number(b)?,
            None => {
                let n = number(part)?;
                n..=n
            }
        };
        if range.is_empty() {
            return Err(format!(
                "'{part}' is an empty range (the start is after the end)"
            ));
        }
        ranges.push(range);
    }
    Ok(EntryRanges(ranges))
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct MftOptions {
    /// Directory to search recursively for $MFT files
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one $MFT
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Parse only these entry numbers (ex: 0-15,30)
    #[arg(help_heading = Some("Filtering"), short = 'r', long, value_name = "RANGES", value_parser = parse_ranges, display_order = 200)]
    pub ranges: Option<EntryRanges>,

    /// Save every entry to a file (with -d: a directory with one file per $MFT)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "PATH", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), ys-mft-parser-csv, json, jsonl. Without -o, the entries are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<MftOutputType>,

    /// Write the resident $DATA streams (the content of small files and alternate data streams) to files in DIR
    #[arg(help_heading = Some("Output"), short = 'e', long = "extract-resident-streams", value_name = "DIR", display_order = 302)]
    pub extract: Option<PathBuf>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, display_order = 303)]
    pub clobber: bool,

    /// Write every $FILE_NAME time, not only those that differ from $STANDARD_INFORMATION
    #[arg(help_heading = Some("CSV Output"), short = 'a', long, display_order = 400)]
    pub all_times: bool,

    /// Write rows for DOS (8.3) names too
    #[arg(help_heading = Some("CSV Output"), short = 's', long, display_order = 401)]
    pub short_names: bool,

    /// Only records whose $STANDARD_INFORMATION created or modified time is on or after DATE, in UTC unless an offset is given (ex: 2025-10-19, 2025-10-19T13:45:30Z)
    #[arg(help_heading = Some("CSV Output"), long, value_name = "DATE", value_parser = crate::mft_csv::parse_cutoff, display_order = 402)]
    pub cutoff: Option<i64>,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl MftOptions {
    /// The options of the CSV.
    pub fn csv_options(&self) -> crate::mft_csv::Options {
        crate::mft_csv::Options {
            all_times: self.all_times,
            short_names: self.short_names,
            cutoff: self.cutoff,
        }
    }

    /// Whether an option of the CSV is given.
    pub fn has_csv_options(&self) -> bool {
        self.all_times || self.short_names || self.cutoff.is_some()
    }

    pub fn output_type(&self) -> MftOutputType {
        self.output_type.unwrap_or(MftOutputType::Csv)
    }

    /// Entries on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-prefetch` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchOutputType {
    /// One row per prefetch file (or per execution with -T)
    Csv,
    /// One pretty-printed JSON object per prefetch file (or per execution with -T)
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct PrefetchOptions {
    /// Directory to search recursively for prefetch files (*.pf)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one prefetch file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// One record per execution (the last 8 run times of every file), sorted by time
    #[arg(help_heading = Some("Records"), short = 'T', long, display_order = 200)]
    pub timeline: bool,

    /// Save every record to a file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<PrefetchOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl PrefetchOptions {
    pub fn output_type(&self) -> PrefetchOutputType {
        self.output_type.unwrap_or(PrefetchOutputType::Csv)
    }

    /// Records on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-usn-journal` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsnOutputType {
    /// One row per record
    Csv,
    /// One pretty-printed JSON object per record (range-tracking records included)
    Json,
    /// One JSON object per line
    Jsonl,
}

impl UsnOutputType {
    pub fn extension(&self) -> &'static str {
        match self {
            UsnOutputType::Csv => "csv",
            UsnOutputType::Json => "json",
            UsnOutputType::Jsonl => "jsonl",
        }
    }
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct UsnJournalOptions {
    /// Directory to search recursively for USN journals ($J)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one USN journal ($J), or with --carve any file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// The volume's $MFT, for paths (default: the $MFT next to the journal's $Extend directory)
    #[arg(help_heading = Some("Input"), short = 'm', long = "mft", value_name = "FILE", conflicts_with = "directory", display_order = 102)]
    pub mft: Option<PathBuf>,

    /// Carve records out of a disk image, unallocated space or any other file that is not a journal
    #[arg(help_heading = Some("Input"), long, conflicts_with = "directory", display_order = 103)]
    pub carve: bool,

    /// Save every record to a file (with -d: a directory with one file per journal)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "PATH", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<UsnOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl UsnJournalOptions {
    pub fn output_type(&self) -> UsnOutputType {
        self.output_type.unwrap_or(UsnOutputType::Csv)
    }

    /// Records on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-srum` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrumOutputType {
    /// One CSV table per provider in a directory
    Csv,
    /// One pretty-printed JSON object per entry
    Json,
    /// One JSON object per line
    Jsonl,
}

impl SrumOutputType {
    pub fn extension(&self) -> &'static str {
        match self {
            SrumOutputType::Csv => "csv",
            SrumOutputType::Json => "json",
            SrumOutputType::Jsonl => "jsonl",
        }
    }
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct SrumOptions {
    /// Directory to search recursively for SRUM databases (SRUDB.dat)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one SRUM database (SRUDB.dat)
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// The SOFTWARE hive, for account and Wi-Fi names (default: config/SOFTWARE of the same Windows, or a SOFTWARE next to the database)
    #[arg(help_heading = Some("Input"), short = 'r', long = "software", value_name = "FILE", conflicts_with = "directory", display_order = 102)]
    pub software: Option<PathBuf>,

    /// Save every entry: a directory of CSV tables, or a file (json, jsonl; with -d a directory with one file per database)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "PATH", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, json and jsonl entries are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<SrumOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl SrumOptions {
    pub fn output_type(&self) -> SrumOutputType {
        self.output_type.unwrap_or(SrumOutputType::Csv)
    }

    /// Entries on stdout (`-t json` or `-t jsonl` without `-o`): nothing but the data may be
    /// printed there. CSV tables need a directory.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none()
            && matches!(
                self.output_type,
                Some(SrumOutputType::Json | SrumOutputType::Jsonl)
            )
    }
}

/// What `parse-lnk` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LnkOutputType {
    /// One row per shortcut
    Csv,
    /// One pretty-printed JSON object per shortcut (shell items, property store, every block)
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct LnkOptions {
    /// Directory to search recursively for shortcuts (*.lnk)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one shortcut
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Code page of text that isn't Unicode: the system's ANSI code page (932 for Japanese)
    #[arg(help_heading = Some("Input"), long = "code-page", value_name = "CP", default_value_t = 1252, display_order = 102)]
    pub code_page: u16,

    /// Save every record to a file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<LnkOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl LnkOptions {
    pub fn output_type(&self) -> LnkOutputType {
        self.output_type.unwrap_or(LnkOutputType::Csv)
    }

    /// Records on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-jump-lists` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum JumpListOutputType {
    /// Two tables in a directory: AutomaticDestinations.csv and CustomDestinations.csv
    Csv,
    /// One pretty-printed JSON object per jump list (every entry, link and property)
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct JumpListOptions {
    /// Directory to search recursively for jump lists (*.automaticDestinations-ms, *.customDestinations-ms)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one jump list
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Code page of text in links that isn't Unicode: the system's ANSI code page (932 for Japanese)
    #[arg(help_heading = Some("Input"), long = "code-page", value_name = "CP", default_value_t = 1252, display_order = 102)]
    pub code_page: u16,

    /// Save every entry: a directory of CSV tables, or a file (json, jsonl)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "PATH", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, json and jsonl are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<JumpListOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl JumpListOptions {
    pub fn output_type(&self) -> JumpListOutputType {
        self.output_type.unwrap_or(JumpListOutputType::Csv)
    }

    /// Records on stdout (`-t json` or `-t jsonl` without `-o`): nothing but the data may be
    /// printed there. CSV tables need a directory.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none()
            && matches!(
                self.output_type,
                Some(JumpListOutputType::Json | JumpListOutputType::Jsonl)
            )
    }
}

/// What `parse-shimcache` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShimcacheOutputType {
    /// One row per entry
    Csv,
    /// One pretty-printed JSON object per entry
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct ShimcacheOptions {
    /// Directory to search recursively for SYSTEM hives
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one SYSTEM hive, or an AppCompatCache value saved to a file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Read a dirty hive as it is, without its transaction logs (SYSTEM.LOG1, SYSTEM.LOG2)
    #[arg(help_heading = Some("Input"), long = "no-logs", display_order = 102)]
    pub no_logs: bool,

    /// Save every entry to a file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the entries are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<ShimcacheOutputType>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 302)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl ShimcacheOptions {
    pub fn output_type(&self) -> ShimcacheOutputType {
        self.output_type.unwrap_or(ShimcacheOutputType::Csv)
    }

    /// Entries on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-defender-quarantine` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefenderQuarantineOutputType {
    /// One row per resource quarantined (and per content or record no entry holds)
    Csv,
    /// One pretty-printed JSON object per record, with every field and stream
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
#[clap(group(ArgGroup::new("destination").args(["output", "extract"]).multiple(true)))]
pub struct DefenderQuarantineOptions {
    /// Directory to search recursively for Defender quarantine folders (a volume, a Quarantine folder, a collection of hosts)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one quarantine entry (Quarantine\Entries\{GUID})
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// Save every record to a file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<DefenderQuarantineOutputType>,

    /// Write the quarantined files (likely malware, never run) to this directory, named by their SHA-1
    #[arg(help_heading = Some("Output"), long, value_name = "DIR", display_order = 302)]
    pub extract: Option<PathBuf>,

    /// Overwrite files when saving or extracting
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "destination", display_order = 303)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl DefenderQuarantineOptions {
    pub fn output_type(&self) -> DefenderQuarantineOutputType {
        self.output_type
            .unwrap_or(DefenderQuarantineOutputType::Csv)
    }

    /// Records on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

/// What `parse-registry` writes.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryOutputType {
    /// One row per value, and per key without values or with damage
    Csv,
    /// One pretty-printed JSON object per record
    Json,
    /// One JSON object per line
    Jsonl,
}

#[derive(Args, Clone, Debug, Default)]
#[clap(group(ArgGroup::new("input").args(["directory", "filepath"]).required(true).multiple(false)))]
pub struct RegistryOptions {
    /// Directory to search recursively for registry hives (every file that is one, logs aside)
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", display_order = 100)]
    pub directory: Option<PathBuf>,

    /// File path to one registry hive
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", display_order = 101)]
    pub filepath: Option<PathBuf>,

    /// A transaction log of the hive given with -f, once per log (default: <hive>.LOG, .LOG1 and .LOG2 next to it)
    #[arg(help_heading = Some("Input"), long = "log", value_name = "FILE", conflicts_with_all = ["directory", "no_logs"], display_order = 102)]
    pub logs: Vec<PathBuf>,

    /// Read a dirty hive as it is, without its transaction logs
    #[arg(help_heading = Some("Input"), long = "no-logs", display_order = 103)]
    pub no_logs: bool,

    /// Only this key (its path under the hive's root key, ex: Microsoft\Windows\CurrentVersion\Group Policy\State) and the keys under it
    #[arg(help_heading = Some("Filtering"), short = 'k', long, value_name = "PATH", display_order = 200)]
    pub key: Option<String>,

    /// Only keys whose path matches REGEX (ignoring case)
    #[arg(help_heading = Some("Filtering"), long, value_name = "REGEX", display_order = 201)]
    pub key_regex: Option<String>,

    /// Only values whose name matches REGEX (ignoring case; the default value's name is empty)
    #[arg(help_heading = Some("Filtering"), long, value_name = "REGEX", display_order = 202)]
    pub value_name: Option<String>,

    /// Only values whose data, as written, matches REGEX (ignoring case, so a GUID matches in any case)
    #[arg(help_heading = Some("Filtering"), long, value_name = "REGEX", display_order = 203)]
    pub value_data: Option<String>,

    /// Only keys last written on or after DATE, in UTC unless an offset is given (ex: 2025-10-19, 2025-10-19T13:45:30Z)
    #[arg(help_heading = Some("Filtering"), long, value_name = "DATE", value_parser = crate::mft_csv::parse_cutoff, display_order = 204)]
    pub timeline_start: Option<i64>,

    /// Only keys last written on or before DATE
    #[arg(help_heading = Some("Filtering"), long, value_name = "DATE", value_parser = crate::mft_csv::parse_cutoff, display_order = 205)]
    pub timeline_end: Option<i64>,

    /// Save every record to a file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 300)]
    pub output: Option<PathBuf>,

    /// Output type: csv (default), json, jsonl. Without -o, the records are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<RegistryOutputType>,

    /// Write every value's bytes in hex (ValueDataRaw), not only those that don't decode as their type
    #[arg(help_heading = Some("Output"), long, display_order = 302)]
    pub raw_data: bool,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, requires = "output", display_order = 303)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl RegistryOptions {
    pub fn output_type(&self) -> RegistryOutputType {
        self.output_type.unwrap_or(RegistryOutputType::Csv)
    }

    /// Records on stdout (`-t` without `-o`): nothing but the data may be printed there.
    pub fn data_on_stdout(&self) -> bool {
        self.output.is_none() && self.output_type.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> AmcacheOptions {
        let mut argv = vec!["juntei", "parse-amcache"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).unwrap().cmd {
            Commands::ParseAmcache(opts) => opts,
            _ => panic!("not parse-amcache"),
        }
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn input_is_one_file_or_one_directory() {
        let p = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-amcache"];
            argv.extend_from_slice(a);
            Cli::try_parse_from(argv)
        };
        assert!(p(&["-f", "a", "-d", "b"]).is_err());
        assert!(p(&[]).is_err());
        assert!(p(&["-d", "b"]).is_ok());
        assert!(p(&["-f", "a", "-C"]).is_err(), "-C needs -o");
    }

    #[test]
    fn entry_ranges() {
        assert_eq!(
            parse_ranges("1-15,30").unwrap(),
            EntryRanges(vec![1..=15, 30..=30])
        );
        assert_eq!(parse_ranges("7").unwrap().len(), 1);
        assert_eq!(parse_ranges("0-9, 20-29").unwrap().len(), 20);
        assert!(parse_ranges("abc").is_err());
        assert!(parse_ranges("1-2-3").is_err());
        assert!(parse_ranges("9-3").is_err());
        assert!(parse_ranges("").is_err());
    }

    #[test]
    fn mft_output_defaults() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-mft"];
            argv.extend_from_slice(a);
            match Cli::try_parse_from(argv).unwrap().cmd {
                Commands::ParseMft(o) => o,
                _ => panic!(),
            }
        };
        let o = parse(&["-f", "MFT"]);
        assert_eq!(o.output_type(), MftOutputType::Csv);
        assert!(!o.data_on_stdout());
        assert!(parse(&["-f", "MFT", "-t", "jsonl"]).data_on_stdout());
        assert!(!parse(&["-f", "MFT", "-o", "x.json", "-t", "json"]).data_on_stdout());
        assert_eq!(parse(&["-f", "MFT", "-r", "0-3"]).ranges.unwrap().len(), 4);
    }

    #[test]
    fn output_type_and_record_defaults() {
        let o = parse(&["-f", "a"]);
        assert_eq!(o.output_type(), OutputType::Text);
        assert_eq!(o.records(), (false, false));
        assert!(!o.data_on_stdout());
        let o = parse(&["-f", "a", "--files"]);
        assert_eq!(o.records(), (true, false));
        let o = parse(&["-f", "a", "-o", "out"]);
        assert_eq!(o.output_type(), OutputType::Csv);
        assert_eq!(o.records(), (true, true));
        let o = parse(&["-f", "a", "-o", "out.txt", "-t", "text", "--devices"]);
        assert_eq!(o.records(), (false, true));
        let o = parse(&["-f", "a", "-t", "jsonl"]);
        assert_eq!(o.records(), (true, true));
        assert!(o.data_on_stdout());
        let o = parse(&["-f", "a", "-t", "csv"]);
        assert!(
            !o.data_on_stdout(),
            "csv cannot go to stdout: an error is printed instead"
        );
        let o = parse(&["-f", "a", "-t", "text", "-a"]);
        assert_eq!(o.records(), (true, true));
    }

    #[test]
    fn prefetch_output_defaults() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-prefetch"];
            argv.extend_from_slice(a);
            match Cli::try_parse_from(argv).unwrap().cmd {
                Commands::ParsePrefetch(o) => o,
                _ => panic!(),
            }
        };
        let o = parse(&["-d", "Prefetch"]);
        assert_eq!(o.output_type(), PrefetchOutputType::Csv);
        assert!(!o.data_on_stdout());
        assert!(!o.timeline);
        assert!(parse(&["-d", "Prefetch", "-t", "csv", "-T"]).data_on_stdout());
        assert!(!parse(&["-f", "A.pf", "-o", "a.json", "-t", "json"]).data_on_stdout());
        let argv = ["juntei", "parse-prefetch", "-f", "A.pf", "-C"];
        assert!(Cli::try_parse_from(argv).is_err(), "-C needs -o");
    }

    #[test]
    fn usn_journal_options() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-usn-journal"];
            argv.extend_from_slice(a);
            Cli::try_parse_from(argv).map(|c| match c.cmd {
                Commands::ParseUsnJournal(o) => o,
                _ => panic!(),
            })
        };
        let o = parse(&["-f", "$J"]).unwrap();
        assert_eq!(o.output_type(), UsnOutputType::Csv);
        assert!(!o.data_on_stdout());
        assert!(
            parse(&["-f", "$J", "-t", "jsonl"])
                .unwrap()
                .data_on_stdout()
        );
        assert!(parse(&["-f", "$J", "-m", "$MFT", "--carve"]).is_ok());
        assert!(
            parse(&["-d", "triage", "-m", "$MFT"]).is_err(),
            "-m needs -f"
        );
        assert!(
            parse(&["-d", "triage", "--carve"]).is_err(),
            "--carve needs -f"
        );
    }

    #[test]
    fn srum_options() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-srum"];
            argv.extend_from_slice(a);
            Cli::try_parse_from(argv).map(|c| match c.cmd {
                Commands::ParseSrum(o) => o,
                _ => panic!(),
            })
        };
        let o = parse(&["-f", "SRUDB.dat"]).unwrap();
        assert_eq!(o.output_type(), SrumOutputType::Csv);
        assert!(!o.data_on_stdout());
        assert!(
            parse(&["-f", "SRUDB.dat", "-t", "jsonl"])
                .unwrap()
                .data_on_stdout()
        );
        assert!(
            !parse(&["-f", "SRUDB.dat", "-t", "csv"])
                .unwrap()
                .data_on_stdout(),
            "csv cannot go to stdout: an error is printed instead"
        );
        assert!(parse(&["-f", "SRUDB.dat", "-r", "SOFTWARE"]).is_ok());
        assert!(
            parse(&["-d", "triage", "-r", "SOFTWARE"]).is_err(),
            "-r needs -f"
        );
    }

    #[test]
    fn lnk_options() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-lnk"];
            argv.extend_from_slice(a);
            Cli::try_parse_from(argv).map(|c| match c.cmd {
                Commands::ParseLnk(o) => o,
                _ => panic!(),
            })
        };
        let o = parse(&["-d", "Recent"]).unwrap();
        assert_eq!((o.output_type(), o.code_page), (LnkOutputType::Csv, 1252));
        assert!(!o.data_on_stdout());
        assert!(
            parse(&["-f", "a.lnk", "-t", "jsonl"])
                .unwrap()
                .data_on_stdout()
        );
        assert_eq!(
            parse(&["-f", "a.lnk", "--code-page", "932"])
                .unwrap()
                .code_page,
            932
        );
        assert!(parse(&["-f", "a.lnk", "-C"]).is_err(), "-C needs -o");
        assert!(parse(&["-f", "a.lnk", "--code-page", "x"]).is_err());
    }

    #[test]
    fn jump_list_options() {
        let parse = |a: &[&str]| {
            let mut argv = vec!["juntei", "parse-jump-lists"];
            argv.extend_from_slice(a);
            Cli::try_parse_from(argv).map(|c| match c.cmd {
                Commands::ParseJumpLists(o) => o,
                _ => panic!(),
            })
        };
        let o = parse(&["-d", "Recent"]).unwrap();
        assert_eq!(
            (o.output_type(), o.code_page),
            (JumpListOutputType::Csv, 1252)
        );
        assert!(!o.data_on_stdout());
        // CSV tables need a directory: never on stdout
        assert!(
            !parse(&["-d", "Recent", "-t", "csv"])
                .unwrap()
                .data_on_stdout()
        );
        assert!(
            parse(&["-f", "a.automaticDestinations-ms", "-t", "jsonl"])
                .unwrap()
                .data_on_stdout()
        );
        assert!(parse(&["-f", "a", "-C"]).is_err(), "-C needs -o");
        assert!(parse(&["-f", "a", "-d", "b"]).is_err());
        assert!(parse(&[]).is_err());
    }
}
