//! Command line definition (clap derive). Option letters and help headings follow Hayabusa so a
//! user of the sibling tools finds the same flags in the same places.

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> AmcacheOptions {
        let mut argv = vec!["juntei", "parse-amcache"];
        argv.extend_from_slice(args);
        let Commands::ParseAmcache(opts) = Cli::try_parse_from(argv).unwrap().cmd;
        opts
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
