//! Hayabusa's progress bar: elapsed time, files done / total, a green spinner and bar, the
//! percentage, and the file being processed on the line below. It is shown while results are
//! saved to a file and draws only on a terminal.

use crate::util;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::path::Path;
use std::time::Duration;

pub fn progress_bar(len: usize, no_color: bool) -> ProgressBar {
    progress_bar_with_len(len as u64, no_color)
}

/// The same bar for a count that is not files (the entries of an $MFT).
pub fn progress_bar_with_len(len: u64, no_color: bool) -> ProgressBar {
    let bar = ProgressBar::with_draw_target(Some(len), ProgressDrawTarget::stdout_with_hz(10))
        .with_tab_width(55);
    bar.set_style(
        ProgressStyle::with_template(&template(no_color))
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    bar.enable_steady_tick(Duration::from_millis(300));
    bar
}

/// The same bar for a count of bytes (a USN journal read twice).
pub fn progress_bar_bytes(len: u64, no_color: bool) -> ProgressBar {
    let bar = progress_bar_with_len(len, no_color);
    bar.set_style(
        ProgressStyle::with_template(
            &template(no_color).replace("{human_pos} / {human_len}", "{bytes} / {total_bytes}"),
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> "),
    );
    bar
}

fn template(no_color: bool) -> String {
    let green = |s: &str| {
        if no_color {
            s.to_string()
        } else {
            format!("\x1b[38;2;0;255;0m{s}\x1b[0m")
        }
    };
    format!(
        "[{{elapsed_precise}}] {{human_pos}} / {{human_len}} {} [{}] {{percent}}%\n\n{{msg}}",
        green("{spinner}"),
        green("{bar:40}")
    )
}

/// The file being processed, quoted, with its size: `"C:/Windows/AppCompat/Programs/Amcache.hve" (1.0 MiB)`.
pub fn message(path: &Path) -> String {
    format!(
        "{:?} ({})",
        path.to_string_lossy().replace('\\', "/"),
        util::file_size_display(path)
    )
}

/// The message the bar ends with, in Hayabusa's orange.
pub fn finished_message(no_color: bool) -> String {
    let msg = "Parsing finished.\n";
    if no_color {
        msg.to_string()
    } else {
        format!("\x1b[38;5;214m{msg}\x1b[0m")
    }
}

/// Runs `f` with the progress bar cleared, so a message printed meanwhile does not tear it.
pub fn suspended<R>(bar: Option<&ProgressBar>, f: impl FnOnce() -> R) -> R {
    match bar {
        Some(b) => b.suspend(f),
        None => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_hayabusas_with_a_green_spinner_and_bar() {
        assert_eq!(
            template(true),
            "[{elapsed_precise}] {human_pos} / {human_len} {spinner} [{bar:40}] {percent}%\n\n{msg}"
        );
        assert!(template(false).contains("\x1b[38;2;0;255;0m{bar:40}\x1b[0m"));
        for no_color in [true, false] {
            assert!(ProgressStyle::with_template(&template(no_color)).is_ok());
        }
    }

    #[test]
    fn message_quotes_the_path_and_shows_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let hive = dir.path().join("Amcache.hve");
        std::fs::write(&hive, vec![0u8; 2048]).unwrap();
        assert_eq!(
            message(&hive),
            format!(
                "\"{}\" (2.0 KiB)",
                hive.display().to_string().replace('\\', "/")
            )
        );
        assert_eq!(message(Path::new("a\\b.hve")), "\"a/b.hve\" (-)");
    }

    #[test]
    fn finished_message_is_orange_unless_colors_are_disabled() {
        assert_eq!(finished_message(true), "Parsing finished.\n");
        assert_eq!(
            finished_message(false),
            "\x1b[38;5;214mParsing finished.\n\x1b[0m"
        );
    }
}
