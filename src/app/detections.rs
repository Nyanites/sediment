//! Detections in the UI: the 🛡 Detections menu (rules grouped by ATT&CK
//! tactic, coloured by severity, with hit counts), the banner explaining the
//! active rule, filtering each view to a rule's hits, and the links from a
//! selected item to the rules that flagged it.

use std::collections::HashSet;

use super::*;
use crate::detect::{self, Artifact, Detections, Severity, Target};

/// What the detection filter is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Active {
    /// Every flagged item in the current view.
    All,
    /// Index into the rule list.
    Rule(usize),
}

#[derive(Default)]
pub(super) struct DetState {
    pub results: Option<Detections>,
    pub dirty: bool,
    pub active: Option<Active>,
    show_empty: bool,
    /// Items the active detection shows.
    filter: HashSet<Target>,
}

impl DetState {
    /// The items to keep in a view, when a detection filter is active.
    pub fn filter(&self) -> Option<&HashSet<Target>> {
        self.active.map(|_| &self.filter)
    }

    /// Text colour for a flagged item: its most severe rule's.
    pub fn color(&self, t: Target, dark: bool) -> Option<Color32> {
        self.results.as_ref()?.top_for(t).map(|r| severity_color(r.severity, dark))
    }
}

pub(super) fn severity_color(s: Severity, dark: bool) -> Color32 {
    match (s, dark) {
        (Severity::Critical, _) => Color32::from_rgb(235, 60, 120),
        (Severity::High, true) => Color32::from_rgb(245, 105, 90),
        (Severity::High, false) => Color32::from_rgb(200, 45, 30),
        (Severity::Medium, true) => Color32::from_rgb(240, 175, 60),
        (Severity::Medium, false) => Color32::from_rgb(175, 105, 0),
        (Severity::Low, true) => Color32::from_rgb(120, 180, 240),
        (Severity::Low, false) => Color32::from_rgb(30, 100, 190),
        (Severity::Info, true) => Color32::from_gray(160),
        (Severity::Info, false) => Color32::from_gray(90),
    }
}

/// "T1558.003" -> https://attack.mitre.org/techniques/T1558/003/
fn mitre_url(t: &str) -> String {
    format!("https://attack.mitre.org/techniques/{}/", t.replace('.', "/"))
}

fn view_of(a: Artifact) -> ViewKind {
    match a {
        Artifact::Mft => ViewKind::Mft,
        Artifact::Journal => ViewKind::Journal,
        Artifact::Prefetch => ViewKind::Prefetch,
    }
}

fn artifact_of(t: Target) -> Artifact {
    match t {
        Target::Mft(_) => Artifact::Mft,
        Target::Journal(_) => Artifact::Journal,
        Target::Prefetch(_) => Artifact::Prefetch,
    }
}

fn short_url(u: &str) -> &str {
    u.trim_start_matches("https://").trim_start_matches("www.").trim_end_matches('/')
}

impl MftApp {
    /// Runs every rule over what's loaded. Called when an artifact changes.
    pub(super) fn run_detections(&mut self) {
        self.det.dirty = false;
        if self.file.is_some() {
            self.ensure_mft_path_index();
        }
        let input = detect::Input {
            mft: self.file.as_ref(),
            journal: self.journal.as_ref(),
            prefetch: self.pf.entries.iter().map(|e| e.result.as_ref().ok()).collect(),
            prefetch_names: self.pf.entries.iter().map(|e| e.name()).collect(),
            mft_paths: self.mft_path_index.as_ref(),
        };
        self.det.results = Some(detect::run(&input));
        // Keep showing the same rule; its hits may have changed.
        let active = self.det.active;
        self.det.active = None;
        if let Some(a) = active {
            self.apply_detection(Some(a), false);
        }
    }

    /// Shows a detection: switches to the view holding its hits, clears the
    /// filters that could hide them and selects the first one.
    pub(super) fn set_detection(&mut self, a: Option<Active>) {
        self.apply_detection(a, true);
    }

    fn apply_detection(&mut self, a: Option<Active>, navigate: bool) {
        self.det.active = a;
        self.det.filter.clear();
        self.view_dirty = true;
        self.jv.dirty = true;
        let Some(results) = &self.det.results else { return };
        let Some(a) = a else { return };
        self.det.filter = match a {
            Active::Rule(i) => results.hits.get(i).map(|h| h.iter().map(|h| h.target).collect()).unwrap_or_default(),
            Active::All => results.by_target.keys().copied().collect(),
        };
        if !navigate {
            return;
        }
        let artifact = match a {
            Active::Rule(i) => results.rules[i].artifact,
            Active::All => {
                let here = match self.active {
                    ViewKind::Mft => Artifact::Mft,
                    ViewKind::Journal => Artifact::Journal,
                    ViewKind::Prefetch => Artifact::Prefetch,
                };
                if self.det.filter.iter().any(|t| artifact_of(*t) == here) {
                    here
                } else {
                    [Artifact::Prefetch, Artifact::Journal, Artifact::Mft]
                        .into_iter()
                        .find(|&x| self.det.filter.iter().any(|t| artifact_of(*t) == x))
                        .unwrap_or(here)
                }
            }
        };
        self.active = view_of(artifact);
        let first = self.det.filter.iter().copied().filter(|t| artifact_of(*t) == artifact).min();
        match artifact {
            Artifact::Mft => {
                self.folder = None;
                self.filter.clear();
                self.state_filter = StateFilter::All;
                self.kind_filter = KindFilter::All;
                self.only_ads = false;
                self.only_timestomp = false;
                if let Some(Target::Mft(r)) = first {
                    self.select(r as usize);
                }
            }
            Artifact::Journal => {
                self.jv.clear_filters();
                self.jtree.folder = None;
                if let Some(Target::Journal(i)) = first {
                    self.jv.selected = Some(i as usize);
                }
            }
            Artifact::Prefetch => {
                if let Some(Target::Prefetch(i)) = first {
                    self.pf.selected = Some(i as usize);
                }
            }
        }
    }

    pub(super) fn detections_menu(&mut self, ui: &mut egui::Ui) {
        let dark = ui.visuals().dark_mode;
        let Some(results) = &self.det.results else {
            ui.add_enabled(false, egui::Button::new("🛡 Detections"))
                .on_disabled_hover_text("Detections run once an $MFT, journal or prefetch file is loaded");
            return;
        };
        let matched = results.matched_rules();
        let label = RichText::new(format!("🛡 Detections ({matched})"));
        let label = match results.top_severity() {
            Some(s) => label.color(severity_color(s, dark)),
            None => label,
        };
        let mut picked: Option<Option<Active>> = None;
        ui.menu_button(label, |ui| {
            ui.set_min_width(520.0);
            ui.label(
                RichText::new(format!(
                    "{matched} of {} rules matched · {} items flagged · {} ms",
                    results.rules.len(),
                    results.by_target.len(),
                    results.elapsed.as_millis()
                ))
                .weak(),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!results.by_target.is_empty(), egui::Button::new(format!("Show all flagged ({})", results.by_target.len())))
                    .on_hover_text("Filter the current view to everything any rule flagged")
                    .clicked()
                {
                    picked = Some(Some(Active::All));
                    ui.close();
                }
                if self.det.active.is_some() && ui.button("✖ Clear").clicked() {
                    picked = Some(None);
                    ui.close();
                }
            });
            ui.checkbox(&mut self.det.show_empty, "Show rules with no matches");
            ui.separator();
            let mut order: Vec<usize> = (0..results.rules.len())
                .filter(|&i| self.det.show_empty || !results.hits[i].is_empty())
                .collect();
            order.sort_by_key(|&i| {
                let r = &results.rules[i];
                (r.tactic, std::cmp::Reverse(r.severity), r.name.clone())
            });
            egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                let mut last = None;
                for i in order {
                    let r = &results.rules[i];
                    let n = results.hits[i].len();
                    if last != Some(r.tactic) {
                        last = Some(r.tactic);
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("{}  ·  {}", r.tactic.label(), r.tactic.id())).strong());
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:<8}", r.severity.label())).monospace().color(severity_color(r.severity, dark)));
                        let text = if n > 0 { RichText::new(&r.name) } else { RichText::new(&r.name).weak() };
                        let selected = self.det.active == Some(Active::Rule(i));
                        let resp = ui
                            .add_enabled(n > 0, egui::Button::selectable(selected, text))
                            .on_hover_text(format!("{}  ·  {}  ·  {}\n\n{}", r.mitre, r.tactic.label(), r.artifact.label(), r.description));
                        if resp.clicked() {
                            picked = Some(Some(Active::Rule(i)));
                            ui.close();
                        }
                        ui.label(RichText::new(r.artifact.label()).small().weak());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(n.to_string()).monospace());
                        });
                    });
                }
                if matched == 0 && !self.det.show_empty {
                    ui.label(RichText::new("No rule matched what's loaded.").weak());
                }
            });
        });
        if let Some(a) = picked {
            self.set_detection(a);
        }
    }

    /// Explains the active detection above the views.
    pub(super) fn detection_banner(&mut self, ui: &mut egui::Ui) {
        let (Some(active), Some(results)) = (self.det.active, &self.det.results) else { return };
        let dark = ui.visuals().dark_mode;
        let mut clear = false;
        egui::Panel::top("detection_banner").show(ui, |ui| {
            ui.add_space(4.0);
            match active {
                Active::All => {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🛡 All flagged items").strong());
                        ui.label(format!("{} items matched at least one rule; each view shows its own", results.by_target.len()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            clear = ui.button("✖ Clear").clicked();
                        });
                    });
                }
                Active::Rule(i) => {
                    let r = &results.rules[i];
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(" {} ", r.severity.label()))
                                .strong()
                                .color(Color32::BLACK)
                                .background_color(severity_color(r.severity, dark)),
                        );
                        ui.label(RichText::new(&r.name).strong().size(15.0));
                        let n = results.hits[i].len();
                        ui.label(RichText::new(format!("· {n} hit{} in {}", if n == 1 { "" } else { "s" }, r.artifact.label())).weak());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            clear = ui.button("✖ Clear").clicked();
                        });
                    });
                    ui.label(&r.description);
                    egui::Grid::new("det_banner").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
                        ui.label(RichText::new("ATT&CK").weak());
                        ui.horizontal_wrapped(|ui| {
                            ui.hyperlink_to(format!("{} {}", r.tactic.id(), r.tactic.label()), format!("https://attack.mitre.org/tactics/{}/", r.tactic.id()));
                            ui.label("·");
                            for t in r.mitre.split(',').map(str::trim) {
                                ui.hyperlink_to(t, mitre_url(t));
                            }
                        });
                        ui.end_row();
                        ui.label(RichText::new("Logic").weak());
                        ui.add(egui::Label::new(RichText::new(&r.logic).monospace()).wrap());
                        ui.end_row();
                        ui.label(RichText::new("False positives").weak());
                        ui.label(r.false_positives);
                        ui.end_row();
                        ui.label(RichText::new("References").weak());
                        ui.horizontal_wrapped(|ui| {
                            for u in &r.references {
                                ui.hyperlink_to(short_url(u), *u);
                            }
                        });
                        ui.end_row();
                        ui.label(RichText::new("Rule").weak());
                        ui.label(RichText::new(format!("{} · Sediment built-in", r.id)).weak().monospace());
                        ui.end_row();
                    });
                }
            }
            ui.add_space(4.0);
        });
        if clear {
            self.set_detection(None);
        }
    }

    /// The rules that flagged `t`, each with why; clicking one shows all its
    /// hits. Returns the rule clicked.
    pub(super) fn detection_links(&self, ui: &mut egui::Ui, t: Target) -> Option<usize> {
        let results = self.det.results.as_ref()?;
        let list = results.by_target.get(&t)?;
        let dark = ui.visuals().dark_mode;
        let mut clicked = None;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("🛡 Detections").strong());
            for &(ri, hi) in list {
                let r = &results.rules[ri];
                ui.horizontal_wrapped(|ui| {
                    let text = RichText::new(format!("[{}] {}", r.severity.label(), r.name)).color(severity_color(r.severity, dark));
                    if ui
                        .link(text)
                        .on_hover_text(format!("{}  ·  {}\n\n{}\n\nClick to show every hit of this rule.", r.mitre, r.tactic.label(), r.description))
                        .clicked()
                    {
                        clicked = Some(ri);
                    }
                    ui.label(RichText::new(format!("{} · {}", r.tactic.label(), r.mitre)).weak().small());
                });
                if let Some(h) = results.hits[ri].get(hi) {
                    ui.label(RichText::new(&h.detail).weak().small());
                }
            }
        });
        clicked
    }
}
