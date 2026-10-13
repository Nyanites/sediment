//! Back / forward navigation across both views.
//!
//! A history entry is recorded whenever the *location* changes: the active
//! view, the MFT folder, the journal folder or the journal record filter.
//! Selections and search text ride along with the location they were made
//! in, so going back also restores what was selected there.

use eframe::egui::PointerButton;

use super::*;

const MAX_HISTORY: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Location {
    active: ViewKind,
    folder: Option<u32>,
    jfolder: Option<u32>,
    jref: Option<u64>,
    pf: Option<usize>,
}

#[derive(Clone)]
pub(super) struct NavState {
    loc: Location,
    selected: Option<usize>,
    jselected: Option<usize>,
    filter: String,
    jfilter: String,
}

#[derive(Default)]
pub(super) struct History {
    current: Option<NavState>,
    back: Vec<NavState>,
    forward: Vec<NavState>,
}

impl MftApp {
    fn nav_snapshot(&self) -> NavState {
        NavState {
            loc: Location {
                active: self.active,
                folder: self.folder,
                jfolder: self.jtree.folder,
                jref: self.jv.ref_filter,
                pf: self.pf.selected,
            },
            selected: self.selected,
            jselected: self.jv.selected,
            filter: self.filter.clone(),
            jfilter: self.jv.filter.clone(),
        }
    }

    /// Called once per frame, after all UI handling.
    pub(super) fn nav_track(&mut self) {
        let now = self.nav_snapshot();
        let h = &mut self.history;
        match &h.current {
            Some(cur) if cur.loc != now.loc => {
                h.back.push(cur.clone());
                if h.back.len() > MAX_HISTORY {
                    h.back.remove(0);
                }
                h.forward.clear();
            }
            _ => {}
        }
        h.current = Some(now);
    }

    pub(super) fn nav_back(&mut self) {
        if let Some(prev) = self.history.back.pop() {
            let now = self.nav_snapshot();
            self.history.forward.push(now);
            self.nav_restore(prev);
        }
    }

    pub(super) fn nav_forward(&mut self) {
        if let Some(next) = self.history.forward.pop() {
            let now = self.nav_snapshot();
            self.history.back.push(now);
            self.nav_restore(next);
        }
    }

    fn nav_restore(&mut self, s: NavState) {
        self.active = s.loc.active;

        // MFT side
        if self.folder != s.loc.folder {
            self.folder = s.loc.folder;
            if let Some(f) = s.loc.folder {
                self.reveal_in_tree(f);
            }
        }
        self.filter = s.filter.clone();
        let mft_len = self.file.as_ref().map_or(0, |f| f.entries.len());
        match s.selected {
            Some(r) if r < mft_len => {
                if self.selected != Some(r) {
                    self.selected = None;
                    self.select(r);
                }
            }
            _ => {
                self.clear_selection();
                self.mft_journal_hits.clear();
            }
        }
        self.view_dirty = true;

        // Journal side
        self.jtree.folder = s.loc.jfolder;
        if let Some(f) = s.loc.jfolder
            && (f as usize) < self.jtree.nodes.len() {
                self.set_journal_folder(Some(f));
            }
        self.jv.ref_filter = s.loc.jref;
        self.jv.filter = s.jfilter.clone();
        self.jv.selected = s.jselected;
        self.jv.dirty = true;

        // Prefetch side
        if s.loc.pf.is_none_or(|i| i < self.pf.entries.len()) {
            self.pf.select(s.loc.pf);
        }

        // Restoring must not itself count as a navigation.
        self.history.current = Some(s);
    }

    fn nav_describe(&self, s: &NavState) -> String {
        let mut d = match s.loc.active {
            ViewKind::Mft => match (s.loc.folder, &self.file) {
                (Some(ORPHAN_NODE), _) => "MFT: [Orphan]".to_string(),
                (Some(f), Some(file)) => match file.entries.get(f as usize) {
                    Some(_) if f == ROOT_NODE => "MFT: \\".to_string(),
                    Some(e) => format!("MFT: {}", e.path),
                    None => "MFT".to_string(),
                },
                _ => "MFT: all records".to_string(),
            },
            ViewKind::Prefetch => match s.loc.pf.and_then(|i| self.pf.entries.get(i)) {
                Some(e) => format!("Prefetch: {}", e.name()),
                None => "Prefetch".to_string(),
            },
            ViewKind::Journal => {
                if let Some(r) = s.loc.jref {
                    format!("Journal: entries for record #{r}")
                } else if let Some(n) = s.loc.jfolder.and_then(|f| self.jtree.nodes.get(f as usize)) {
                    format!("Journal: {}", if n.path.is_empty() { &n.name } else { &n.path })
                } else {
                    "Journal: all entries".to_string()
                }
            }
        };
        let filter = match s.loc.active {
            ViewKind::Mft => &s.filter,
            ViewKind::Journal => &s.jfilter,
            ViewKind::Prefetch => "",
        };
        if !filter.trim().is_empty() {
            d.push_str(&format!("  (filter: {})", filter.trim()));
        }
        d
    }

    pub(super) fn nav_buttons(&mut self, ui: &mut egui::Ui) {
        let back = self.history.back.last().map(|s| self.nav_describe(s));
        let fwd = self.history.forward.last().map(|s| self.nav_describe(s));
        let b = ui
            .add_enabled(back.is_some(), egui::Button::new("⏴ Back"))
            .on_hover_text(format!(
                "{}\n(Alt+← or mouse back button)",
                back.as_deref().map_or("Nothing to go back to".into(), |d| format!("Back to {d}"))
            ));
        if b.clicked() {
            self.nav_back();
        }
        let f = ui
            .add_enabled(fwd.is_some(), egui::Button::new("⏵"))
            .on_hover_text(format!(
                "{}\n(Alt+→ or mouse forward button)",
                fwd.as_deref().map_or("Nothing to go forward to".into(), |d| format!("Forward to {d}"))
            ));
        if f.clicked() {
            self.nav_forward();
        }
    }

    pub(super) fn nav_input(&mut self, ctx: &egui::Context) {
        let (back, fwd) = ctx.input(|i| {
            (
                (i.modifiers.alt && i.key_pressed(Key::ArrowLeft))
                    || i.pointer.button_pressed(PointerButton::Extra1),
                (i.modifiers.alt && i.key_pressed(Key::ArrowRight))
                    || i.pointer.button_pressed(PointerButton::Extra2),
            )
        });
        if back {
            self.nav_back();
        } else if fwd {
            self.nav_forward();
        }
    }
}
