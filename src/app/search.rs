//! Search-box query matching shared by the MFT and journal views.
//!
//! * plain text   — substring of the name or full path (case-insensitive)
//! * `*` and `?`  — wildcard match against the whole name, e.g. `*.exe`
//! * contains `\` — match against the full path instead, e.g. `*\temp\*.ps1`

use eframe::egui::{self, RichText};

pub(super) struct Matcher {
    kind: Kind,
    on_path: bool,
}

enum Kind {
    Any,
    Substr(String),
    Glob(Vec<char>),
}

impl Matcher {
    pub fn new(query: &str) -> Self {
        let q = query.trim().to_lowercase();
        let on_path = q.contains('\\');
        let kind = if q.is_empty() {
            Kind::Any
        } else if q.contains(['*', '?']) {
            Kind::Glob(q.chars().collect())
        } else {
            Kind::Substr(q)
        };
        Self { kind, on_path }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.kind, Kind::Any)
    }

    /// `name_lc` / `path_lc` must already be lowercase.
    pub fn matches(&self, name_lc: &str, path_lc: &str) -> bool {
        match &self.kind {
            Kind::Any => true,
            Kind::Substr(s) if self.on_path => path_lc.contains(s.as_str()),
            Kind::Substr(s) => name_lc.contains(s.as_str()) || path_lc.contains(s.as_str()),
            Kind::Glob(p) => glob(p, if self.on_path { path_lc } else { name_lc }),
        }
    }
}

/// Whole-string wildcard match (`*` = any run, `?` = one char).
fn glob(pattern: &[char], text: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let (mut p, mut i) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while i < t.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == t[i]) {
            p += 1;
            i += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, i));
            p += 1;
        } else if let Some((sp, si)) = star {
            p = sp + 1;
            i = si + 1;
            star = Some((sp, si + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

pub(super) const SEARCH_HELP: &str = "text — name or path contains\n\
    *.exe — wildcards match the whole name\n\
    *\\temp\\*.ps1 — include \\ to match the full path";

/// The "find in tree" box. Returns true when the query changed.
pub(super) fn find_box(ui: &mut egui::Ui, query: &mut String, what: &str) -> bool {
    let mut changed = false;
    // Right-to-left so the text box can take exactly the space that is left;
    // asking for more (frame margins included) would widen the panel every frame.
    let height = ui.spacing().interact_size.y;
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), height),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            if !query.is_empty() && ui.small_button("✖").clicked() {
                query.clear();
                changed = true;
            }
            changed |= ui
                .add(
                    egui::TextEdit::singleline(query)
                        .hint_text(format!("Find {what}…"))
                        .desired_width(f32::INFINITY),
                )
                .on_hover_text(SEARCH_HELP)
                .changed();
        },
    );
    changed
}

pub(super) fn hits_header(ui: &mut egui::Ui, n: usize, cap: usize) {
    let text = if n >= cap {
        format!("first {cap} matches — refine the search")
    } else {
        format!("{n} matches")
    };
    ui.label(RichText::new(text).weak().small());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let m = Matcher::new("*.EXE");
        assert!(m.matches("cmd.exe", r"\windows\system32\cmd.exe"));
        assert!(!m.matches("cmd.exe.mui", r"\windows\cmd.exe.mui"));
        let m = Matcher::new(r"*\temp\*.ps1");
        assert!(m.matches("a.ps1", r"\users\bob\appdata\local\temp\a.ps1"));
        assert!(!m.matches("a.ps1", r"\users\bob\a.ps1"));
        let m = Matcher::new("rep?rt*");
        assert!(m.matches("report_2025.docx", ""));
        assert!(Matcher::new("SYSTEM32").matches("x", r"\windows\system32\x"));
        assert!(Matcher::new("  ").is_empty());
    }
}
