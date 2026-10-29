//! Juntei: Windows forensics artifact parser.

mod amcache;
mod cli;
mod color;
mod defender_quarantine;
mod hive;
mod jump_lists;
mod lnk;
mod mft;
mod mft_csv;
mod prefetch;
mod progress;
mod shimcache;
mod srum;
mod usn_journal;
mod util;

use chrono::Local;
use clap::{CommandFactory, Parser};
use cli::{Cli, Commands, VERSION};
use color::JunteiColor::Green;
use std::env;
use std::time::Instant;
use util::p;

const LOGO: &str = include_str!("../art/logo.txt");

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 || (args.len() == 2 && (args[1] == "-h" || args[1] == "--help")) {
        display_logo(false, false, false, true);
        Cli::command().print_help().ok();
        return;
    }

    let start = Instant::now();
    let cli = Cli::parse();
    let code = match &cli.cmd {
        Commands::ParseAmcache(opts) => {
            // JSON / JSONL on stdout: nothing but the data is printed there
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = amcache::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseMft(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = mft::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParsePrefetch(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = prefetch::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseUsnJournal(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = usn_journal::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseSrum(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = srum::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseLnk(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = lnk::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseJumpLists(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = jump_lists::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseDefenderQuarantine(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = defender_quarantine::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
        Commands::ParseShimcache(opts) => {
            let data_only = opts.data_on_stdout();
            if !data_only {
                display_logo(opts.common.quiet, opts.common.no_color, true, false);
            }
            let code = shimcache::run(opts);
            if !data_only {
                print_elapsed(start, opts.common.no_color);
            }
            code
        }
    };
    std::process::exit(code);
}

fn print_elapsed(start: Instant, no_color: bool) {
    let duration = start.elapsed();
    let hours = duration.as_secs() / 3600;
    let minutes = (duration.as_secs() % 3600) / 60;
    let seconds = duration.as_secs() % 60;
    let millis = duration.subsec_millis();
    p(Green.rdg(no_color), "Elapsed time: ", false);
    p(
        None,
        &format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}\n"),
        true,
    );
}

fn display_logo(quiet: bool, no_color: bool, time: bool, help: bool) {
    if !quiet {
        p(Green.rdg(no_color), LOGO, true);
        p(None, "", true);
    }
    if time {
        let msg = Local::now().format("%Y/%m/%d %H:%M").to_string();
        p(Green.rdg(no_color), "Start time: ", false);
        p(None, &msg, true);
    }
    if help {
        p(None, &format!("Version: {VERSION}"), true);
    } else {
        p(Green.rdg(no_color), "Version: ", false);
        p(None, VERSION, true);
    }
    p(None, "", true);
}
