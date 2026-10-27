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
    /// text report on the terminal (summary and findings only, like amcache4n6).
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
    /// One row per entry (the columns of mft_dump)
    Csv,
    /// One pretty-printed JSON object per entry
    Json,
    /// One JSON object per line
    Jsonl,
}

impl MftOutputType {
    pub fn extension(&self) -> &'static str {
        match self {
            MftOutputType::Csv => "csv",
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

    /// Output type: csv (default), json, jsonl. Without -o, the entries are written to stdout
    #[arg(help_heading = Some("Output"), short = 't', long = "output-type", value_name = "TYPE", value_enum, hide_possible_values = true, display_order = 301)]
    pub output_type: Option<MftOutputType>,

    /// Write the resident $DATA streams (the content of small files and alternate data streams) to files in DIR
    #[arg(help_heading = Some("Output"), short = 'e', long = "extract-resident-streams", value_name = "DIR", display_order = 302)]
    pub extract: Option<PathBuf>,

    /// Overwrite files when saving
    #[arg(help_heading = Some("Output"), short = 'C', long, display_order = 303)]
    pub clobber: bool,

    #[clap(flatten)]
    pub common: CommonOptions,
}

impl MftOptions {
    pub fn output_type(&self) -> MftOutputType {
        self.output_type.unwrap_or(MftOutputType::Csv)
    }

    /// Entries on stdout (`-t` without `-o`): nothing but the data may be printed there.
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
            Commands::ParseMft(_) => panic!("not parse-amcache"),
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
                Commands::ParseAmcache(_) => panic!(),
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
}
