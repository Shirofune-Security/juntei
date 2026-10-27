//! Small shared helpers: colored printing and number / size formatting.

use crate::color::JunteiColor;
use std::io::Write;
use std::path::Path;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

/// Print `msg` to stdout in `color` (or the default color when `None`).
pub fn p(color: Option<Color>, msg: &str, newline: bool) {
    // Only emit escape sequences when there is a color to set, so -K output stays plain.
    let wtr = BufferWriter::stdout(if color.is_some() {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    });
    let mut buf = wtr.buffer();
    if let Some(c) = color {
        buf.set_color(ColorSpec::new().set_fg(Some(c))).ok();
    }
    if newline {
        writeln!(buf, "{msg}").ok();
    } else {
        write!(buf, "{msg}").ok();
    }
    if color.is_some() {
        buf.reset().ok();
    }
    wtr.print(&buf).ok();
}

/// Print a `Label: value` pair with a green label, like the sibling tools.
pub fn p_label(no_color: bool, label: &str, value: &str) {
    p(JunteiColor::Green.rdg(no_color), label, false);
    p(None, value, true);
}

/// Print an error in red.
pub fn error_msg(no_color: bool, msg: &str) {
    p(JunteiColor::Red.rdg(no_color), msg, true);
}

/// `1234567` → `1,234,567`.
pub fn fmt_num(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The human-readable size of a byte count (`1.2 MiB`).
pub fn size_display(bytes: u64) -> String {
    bytesize::ByteSize::b(bytes).display().to_string()
}

/// The human-readable size of a file, or `-` when it cannot be read.
pub fn file_size_display(path: &Path) -> String {
    path.metadata()
        .map_or_else(|_| "-".to_string(), |m| size_display(m.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(1_234_567), "1,234,567");
    }

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(size_display(2048), "2.0 KiB");
        assert_eq!(file_size_display(Path::new("no/such/file")), "-");
    }
}
