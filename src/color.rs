//! Terminal colors. The palette is the one Hayabusa uses, so a user of the sibling tools reads the
//! same colors the same way: green for labels, red for errors, orange for warnings and high
//! severity, yellow for medium severity.

use termcolor::Color;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JunteiColor {
    Red,
    Orange,
    Yellow,
    Green,
}

impl JunteiColor {
    /// The termcolor color, or `None` when colors are disabled.
    pub fn rdg(&self, no_color: bool) -> Option<Color> {
        if no_color {
            return None;
        }
        Some(match self {
            JunteiColor::Red => Color::Rgb(255, 0, 0),
            JunteiColor::Orange => Color::Rgb(255, 175, 0),
            JunteiColor::Yellow => Color::Rgb(255, 255, 0),
            JunteiColor::Green => Color::Rgb(0, 255, 0),
        })
    }

    /// Color of a finding severity: critical red, high orange, medium yellow, the rest default.
    pub fn for_severity(severity: &str) -> Option<JunteiColor> {
        match severity.to_ascii_lowercase().as_str() {
            "critical" => Some(JunteiColor::Red),
            "high" => Some(JunteiColor::Orange),
            "medium" => Some(JunteiColor::Yellow),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_are_disabled_with_no_color() {
        assert_eq!(JunteiColor::Green.rdg(true), None);
        assert_eq!(JunteiColor::Green.rdg(false), Some(Color::Rgb(0, 255, 0)));
        assert_eq!(JunteiColor::for_severity("HIGH"), Some(JunteiColor::Orange));
        assert_eq!(JunteiColor::for_severity("low"), None);
    }
}
