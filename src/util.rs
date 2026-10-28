//! Small shared helpers: colored printing and number / size formatting.

use crate::color::JunteiColor;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
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

/// The output name of one file found with `-d`: its path under the input directory without the
/// extension, with `_` for separators and unsafe characters
/// (`HOST1/C/Windows/AppCompat/Programs/Amcache.hve` → `HOST1_C_Windows_AppCompat_Programs_Amcache`),
/// numbered when two files would share it.
pub fn unique_name(root: &Path, input: &Path, used: &mut HashSet<String>) -> String {
    let relative = input.strip_prefix(root).unwrap_or(input);
    let relative = relative.with_extension("");
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let name: String = parts
        .join("_")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = if name.is_empty() {
        "output".to_string()
    } else {
        name
    };
    let mut candidate = name.clone();
    let mut n = 1;
    while !used.insert(candidate.clone()) {
        n += 1;
        candidate = format!("{name}_{n}");
    }
    candidate
}

/// Refuse to overwrite existing results without `-C`.
pub fn check_output(out: &Path, is_dir: bool, clobber: bool) -> Result<(), String> {
    let exists = || {
        format!(
            "The output file already exists: {}. Please specify a different filename or add the -C, --clobber option to overwrite.",
            out.display()
        )
    };
    if is_dir {
        if out.is_file() {
            return Err(format!("{} is a file, not a directory.", out.display()));
        }
        let non_empty = out
            .read_dir()
            .map(|mut e| e.next().is_some())
            .unwrap_or(false);
        if non_empty && !clobber {
            return Err(exists());
        }
    } else if out.is_dir() {
        return Err(format!("{} is a directory.", out.display()));
    } else if out.exists() && !clobber {
        return Err(exists());
    }
    Ok(())
}

/// The extension of a file name, with its dot (`.dll`), as Eric Zimmerman's tools give it (.NET's
/// `Path.GetExtension`: from the last dot, the whole name when it starts with one, nothing when
/// the dot is last).
pub fn dotnet_extension(name: &str) -> &str {
    match name.rfind('.') {
        Some(at) if at + 1 < name.len() => &name[at..],
        _ => "",
    }
}

/// The files under `dir` whose name `is_match` accepts, recursively, in path order. Symlinked
/// directories are not followed (a link loop would never end).
pub fn find_files(dir: &Path, is_match: fn(&str) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = d.read_dir() else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                stack.push(path);
            } else if (kind.is_file() || (kind.is_symlink() && path.is_file()))
                && is_match(&entry.file_name().to_string_lossy())
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_outputs_need_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out.csv");
        assert!(check_output(&file, false, false).is_ok());
        std::fs::write(&file, b"x").unwrap();
        assert!(check_output(&file, false, false).is_err());
        assert!(check_output(&file, false, true).is_ok());
        assert!(
            check_output(&file, true, true).is_err(),
            "a file is not a directory"
        );
        assert!(check_output(dir.path(), false, true).is_err());
        assert!(check_output(dir.path(), true, false).is_err());
        assert!(check_output(dir.path(), true, true).is_ok());
    }

    #[test]
    fn output_names_follow_the_input_path_and_are_never_shared() {
        let root = Path::new("triage");
        let mut used = HashSet::new();
        assert_eq!(
            unique_name(
                root,
                &root.join("HOST1/C/Windows/AppCompat/Programs/Amcache.hve"),
                &mut used
            ),
            "HOST1_C_Windows_AppCompat_Programs_Amcache"
        );
        assert_eq!(
            unique_name(root, &root.join("Amcache.hve"), &mut used),
            "Amcache"
        );
        assert_eq!(
            unique_name(root, &root.join("a b/Amcache.hve"), &mut used),
            "a_b_Amcache"
        );
        // `a_b/Amcache.hve` sanitizes to the same name
        assert_eq!(
            unique_name(root, &root.join("a_b/Amcache.hve"), &mut used),
            "a_b_Amcache_2"
        );
    }

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
