//! `$UsnJrnl:$J` view: change-journal table, filters and record details.

use std::collections::HashMap;

use super::*;
use crate::usn::{self, UsnJournal, UsnRecord};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum JCol {
    Usn,
    Timestamp,
    Name,
    Reason,
    FileRef,
    ParentRef,
    Attrs,
    Path,
    Source,
    Offset,
}

const JCOLUMNS: &[(JCol, &str, f32)] = &[
    (JCol::Usn, "USN", 95.0),
    (JCol::Timestamp, "Timestamp (UTC)", 200.0),
    (JCol::Name, "Name", 240.0),
    (JCol::Reason, "Reason", 260.0),
    (JCol::FileRef, "File ref", 95.0),
    (JCol::ParentRef, "Parent ref", 95.0),
    (JCol::Attrs, "Attr", 55.0),
    (JCol::Path, "Resolved path", 520.0),
    (JCol::Source, "Source", 60.0),
    (JCol::Offset, "Offset", 90.0),
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReasonFilter {
    Any,
    Create,
    Delete,
    Rename,
    Data,
    BasicInfo,
    Security,
    Stream,
}

impl ReasonFilter {
    const ALL: [(ReasonFilter, &'static str); 8] = [
        (ReasonFilter::Any, "Any reason"),
        (ReasonFilter::Create, "File create"),
        (ReasonFilter::Delete, "File delete"),
        (ReasonFilter::Rename, "Rename"),
        (ReasonFilter::Data, "Data write / truncate"),
        (ReasonFilter::BasicInfo, "Basic info (timestamps/attrs)"),
        (ReasonFilter::Security, "Security change"),
        (ReasonFilter::Stream, "Stream (ADS) change"),
    ];

    fn mask(self) -> u32 {
        match self {
            ReasonFilter::Any => u32::MAX,
            ReasonFilter::Create => usn::REASON_FILE_CREATE,
            ReasonFilter::Delete => usn::REASON_FILE_DELETE,
            ReasonFilter::Rename => usn::REASON_RENAME,
            ReasonFilter::Data => usn::REASON_DATA,
            ReasonFilter::BasicInfo => usn::REASON_BASIC_INFO,
            ReasonFilter::Security => usn::REASON_SECURITY_CHANGE,
            ReasonFilter::Stream => usn::REASON_STREAM_CHANGE,
        }
    }

    fn label(self) -> &'static str {
        Self::ALL.iter().find(|(r, _)| *r == self).map_or("", |(_, l)| l)
    }
}

pub(super) struct JournalView {
    pub(super) filter: String,
    reason: ReasonFilter,
    kind: KindFilter,
    /// Restrict to entries for one MFT record number.
    pub(super) ref_filter: Option<u64>,
    view: Vec<u32>,
    pub(super) dirty: bool,
    pub(super) paths_dirty: bool,
    sort_col: JCol,
    sort_asc: bool,
    pub(super) selected: Option<usize>,
    scroll_to_row: Option<usize>,
}

impl Default for JournalView {
    fn default() -> Self {
        Self {
            filter: String::new(),
            reason: ReasonFilter::Any,
            kind: KindFilter::All,
            ref_filter: None,
            view: Vec::new(),
            dirty: true,
            paths_dirty: true,
            sort_col: JCol::Usn,
            sort_asc: true,
            selected: None,
            scroll_to_row: None,
        }
    }
}

fn fmt_ref(rec: u64, seq: u16) -> String {
    format!("{rec}-{seq}")
}

fn jcell(r: &UsnRecord, c: JCol) -> String {
    match c {
        JCol::Usn => r.usn.to_string(),
        JCol::Timestamp => mft::format_filetime(r.timestamp),
        JCol::Name => r.name.clone(),
        JCol::Reason => usn::reason_text(r.reason),
        JCol::FileRef => fmt_ref(r.file_record, r.file_seq),
        JCol::ParentRef => fmt_ref(r.parent_record, r.parent_seq),
        JCol::Attrs => mft::file_attr_short(r.file_attributes),
        JCol::Path => r.path.clone(),
        JCol::Source => {
            if r.source_info == 0 {
                String::new()
            } else {
                format!("0x{:X}", r.source_info)
            }
        }
        JCol::Offset => format!("0x{:X}", r.offset),
    }
}

fn jcompare(a: &UsnRecord, b: &UsnRecord, c: JCol) -> CmpOrdering {
    let ord = match c {
        JCol::Usn => a.usn.cmp(&b.usn),
        JCol::Timestamp => a.timestamp.cmp(&b.timestamp),
        JCol::Name => a.name_lc.cmp(&b.name_lc),
        JCol::Reason => a.reason.cmp(&b.reason),
        JCol::FileRef => (a.file_record, a.file_seq).cmp(&(b.file_record, b.file_seq)),
        JCol::ParentRef => (a.parent_record, a.parent_seq).cmp(&(b.parent_record, b.parent_seq)),
        JCol::Attrs => a.file_attributes.cmp(&b.file_attributes),
        JCol::Path => a.path_lc.cmp(&b.path_lc),
        JCol::Source => a.source_info.cmp(&b.source_info),
        JCol::Offset => a.offset.cmp(&b.offset),
    };
    ord.then(a.usn.cmp(&b.usn))
}

/// Resolves every record's full path. Directories are looked up in the
/// `$MFT` when its sequence number still matches; otherwise the journal's
/// own record of that directory's name and parent is used, so folders that
/// have since been deleted or reused can still be named.
pub(super) fn resolve_paths(journal: &mut UsnJournal, mft: Option<&MftFile>) {
    let mut known: HashMap<(u64, u16), (String, u64, u16)> = HashMap::new();
    for r in &journal.records {
        // Later records win, but keep the pre-rename name out of it.
        if r.reason & 0x1000 == 0 {
            known.insert(
                (r.file_record, r.file_seq),
                (r.name.clone(), r.parent_record, r.parent_seq),
            );
        }
    }

    fn dir_path(
        rec: u64,
        seq: u16,
        mft: Option<&MftFile>,
        known: &HashMap<(u64, u16), (String, u64, u16)>,
        memo: &mut HashMap<(u64, u16), String>,
        depth: usize,
    ) -> String {
        if let Some(p) = memo.get(&(rec, seq)) {
            return p.clone();
        }
        let from_mft = mft.and_then(|m| {
            let e = m.entries.get(rec as usize)?;
            let seq_ok = e.sequence == seq || (!e.in_use && e.sequence == seq.wrapping_add(1));
            (seq_ok && !e.path.is_empty()).then(|| e.path.clone())
        });
        let path = match from_mft {
            Some(p) => p,
            None if rec == mft::ROOT_RECORD as u64 => "\\".to_string(),
            None => match known.get(&(rec, seq)) {
                Some((name, prec, pseq)) if depth < 64 && (*prec, *pseq) != (rec, seq) => {
                    let parent = dir_path(*prec, *pseq, mft, known, memo, depth + 1);
                    mft::join_path(&parent, name)
                }
                _ => format!("[#{rec}-{seq}]"),
            },
        };
        memo.insert((rec, seq), path.clone());
        path
    }

    let mut memo = HashMap::new();
    for r in &mut journal.records {
        let parent = dir_path(r.parent_record, r.parent_seq, mft, &known, &mut memo, 0);
        r.path = mft::join_path(&parent, &r.name);
        r.path_lc = r.path.to_lowercase();
    }
}

impl MftApp {
    /// Recomputes per-MFT-record journal counts and the selected record's
    /// journal entries.
    fn refresh_journal_links(&mut self) {
        let Some(f) = &mut self.file else { return };
        for e in &mut f.entries {
            e.journal_count = 0;
        }
        if let Some(j) = &self.journal {
            for r in &j.records {
                if let Some(e) = f.entries.get_mut(r.file_record as usize) {
                    e.journal_count += 1;
                }
            }
        }
        self.refresh_mft_journal_hits();
    }

    pub(super) fn refresh_mft_journal_hits(&mut self) {
        self.mft_journal_hits.clear();
        let (Some(j), Some(sel)) = (&self.journal, self.selected) else { return };
        self.mft_journal_hits.extend(
            j.records
                .iter()
                .enumerate()
                .filter(|(_, r)| r.file_record == sel as u64)
                .map(|(i, _)| i as u32),
        );
    }

    /// Switches to the journal view showing only entries for MFT record
    /// `rec`, optionally selecting journal record `select`.
    pub(super) fn open_journal_for(&mut self, rec: u64, select: Option<usize>) {
        if self.journal.is_none() {
            return;
        }
        self.active = ViewKind::Journal;
        self.jv.ref_filter = Some(rec);
        self.jv.selected = select;
        self.jtree.folder = None;
        self.jv.dirty = true;
    }

    /// Switches to the journal view scoped to the folder at `path`.
    pub(super) fn open_journal_folder(&mut self, path: &str) {
        match self.jtree.node_by_path(path) {
            Some(n) => {
                self.active = ViewKind::Journal;
                self.jv.ref_filter = None;
                self.set_journal_folder(Some(n));
            }
            None => {
                self.status_msg = Some(format!("No USN journal activity under {path}"));
            }
        }
    }

    /// Switches to the MFT view scoped to the folder at `path`.
    pub(super) fn open_mft_folder(&mut self, path: &str) {
        let Some(file) = &self.file else { return };
        let lc = path.to_lowercase();
        let found = if lc == "\\" {
            Some(ROOT_NODE)
        } else {
            file.entries
                .iter()
                .find(|e| e.is_dir && e.base_record == 0 && e.path_lc == lc)
                .map(|e| e.record as u32)
        };
        match found {
            Some(n) => {
                self.active = ViewKind::Mft;
                self.set_folder(Some(n));
                self.reveal_in_tree(n);
            }
            None => {
                self.status_msg = Some(format!(
                    "{path} is not in the $MFT any more (deleted or renamed since)"
                ));
            }
        }
    }

    /// "Journal" tab of the MFT details panel. Returns the journal record to
    /// open (`Some(None)` = open all entries for this record).
    pub(super) fn mft_journal_tab(
        &self,
        ui: &mut egui::Ui,
        rec: usize,
        current_seq: u16,
    ) -> Option<Option<usize>> {
        let Some(j) = &self.journal else {
            ui.label("Load the matching $J ($UsnJrnl) to see this file's change history.");
            return None;
        };
        let mut open = None;
        let hits = &self.mft_journal_hits;
        if hits.is_empty() {
            ui.label(format!("No USN journal entries for record #{rec}."));
            return None;
        }
        let current = hits
            .iter()
            .filter(|&&i| j.records[i as usize].file_seq == current_seq)
            .count();
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "{} entries · {current} for the current file (seq {current_seq})",
                hits.len()
            ));
            if ui.button("Open in journal view").clicked() {
                open = Some(None);
            }
        });
        if current < hits.len() {
            ui.label(
                RichText::new("Dimmed rows belong to an earlier file that used this record.")
                    .weak()
                    .small(),
            );
        }
        ui.separator();
        let deleted = deleted_color(ui);
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        egui::ScrollArea::both()
            .id_salt("mft_journal_hits")
            .auto_shrink(false)
            .show_rows(ui, row_h, hits.len(), |ui, range| {
                for &i in &hits[range] {
                    let r = &j.records[i as usize];
                    let same = r.file_seq == current_seq;
                    let mut reason = RichText::new(usn::reason_text(r.reason));
                    if r.reason & usn::REASON_FILE_DELETE != 0 {
                        reason = reason.color(deleted);
                    }
                    if !same {
                        reason = reason.weak();
                    }
                    ui.horizontal(|ui| {
                        ui.set_height(row_h);
                        let ts = RichText::new(mft::format_filetime(r.timestamp)).monospace();
                        let resp = ui
                            .add(
                                egui::Button::selectable(false, if same { ts } else { ts.weak() })
                                    .frame_when_inactive(false),
                            )
                            .on_hover_text(format!(
                                "USN {} · {} · seq {}\nClick to open in the journal view",
                                r.usn, r.name, r.file_seq
                            ));
                        ui.add(egui::Label::new(reason).truncate());
                        if resp.clicked() {
                            open = Some(Some(i as usize));
                        }
                    });
                }
            });
        open
    }

    pub(super) fn journal_rebuild(&mut self) {
        if self.journal.is_some() && self.jv.paths_dirty {
            self.jv.paths_dirty = false;
            if let Some(j) = &mut self.journal {
                resolve_paths(j, self.file.as_ref());
                self.jtree.rebuild(j);
            }
            self.refresh_journal_links();
            if self.file.is_some() {
                self.view_dirty = true;
            }
        }
        let Some(j) = &mut self.journal else { return };
        let tree = &self.jtree;
        let jv = &mut self.jv;
        jv.dirty = false;
        jv.view.clear();
        let matcher = Matcher::new(&jv.filter);
        let mask = jv.reason.mask();
        for (i, r) in j.records.iter().enumerate() {
            if r.reason & mask == 0 {
                continue;
            }
            if tree.folder.is_some_and(|f| !tree.contains(i, f)) {
                continue;
            }
            if jv.ref_filter.is_some_and(|f| r.file_record != f) {
                continue;
            }
            let is_dir = r.file_attributes & 0x10 != 0;
            match jv.kind {
                KindFilter::Files if is_dir => continue,
                KindFilter::Dirs if !is_dir => continue,
                _ => {}
            }
            if !matcher.matches(&r.name_lc, &r.path_lc) {
                continue;
            }
            jv.view.push(i as u32);
        }
        let (col, asc) = (jv.sort_col, jv.sort_asc);
        let recs = &j.records;
        jv.view.sort_by(|&a, &b| {
            let o = jcompare(&recs[a as usize], &recs[b as usize], col);
            if asc { o } else { o.reverse() }
        });
        if let Some(sel) = jv.selected {
            jv.scroll_to_row = jv.view.iter().position(|&r| r as usize == sel);
        }
    }

    pub(super) fn journal_filter_bar(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        let jv = &mut self.jv;
        ui.label("Filter:");
        changed |= ui
            .add(
                egui::TextEdit::singleline(&mut jv.filter)
                    .hint_text("name, *.exe or *\\path\\*")
                    .desired_width(320.0),
            )
            .on_hover_text(search::SEARCH_HELP)
            .changed();
        if !jv.filter.is_empty() && ui.small_button("✖").clicked() {
            jv.filter.clear();
            changed = true;
        }
        ui.separator();
        for (v, label) in [
            (KindFilter::All, "All"),
            (KindFilter::Files, "Files"),
            (KindFilter::Dirs, "Dirs"),
        ] {
            changed |= ui
                .selectable_value(&mut jv.kind, v, label)
                .on_hover_text("Uses the directory attribute recorded in each journal entry")
                .changed();
        }
        ui.separator();
        egui::ComboBox::from_id_salt("reason_filter")
            .selected_text(jv.reason.label())
            .width(200.0)
            .show_ui(ui, |ui| {
                for (r, label) in ReasonFilter::ALL {
                    changed |= ui.selectable_value(&mut jv.reason, r, label).changed();
                }
            });
        if let Some(f) = jv.ref_filter {
            ui.separator();
            ui.label(RichText::new(format!("Only MFT record #{f}")).strong());
            if ui.small_button("✖").on_hover_text("Clear record filter").clicked() {
                jv.ref_filter = None;
                changed = true;
            }
        }
        if changed {
            jv.dirty = true;
        }
    }

    pub(super) fn journal_status(&self, ui: &mut egui::Ui) {
        let Some(j) = &self.journal else {
            if self.usn_max.is_some() {
                ui.label("$Max loaded — open the matching $J to see journal entries");
            }
            return;
        };
        let (first, last) = (j.records.first(), j.records.last());
        let mut s = format!("{} shown · {} records", self.jv.view.len(), j.records.len());
        if let (Some(a), Some(b)) = (first, last) {
            s.push_str(&format!(
                " · USN {}–{} · {} to {}",
                a.usn,
                b.usn,
                mft::format_filetime(a.timestamp),
                mft::format_filetime(b.timestamp)
            ));
        }
        if j.skipped_bytes > 0 {
            s.push_str(&format!(" · {} unparseable bytes skipped", j.skipped_bytes));
        }
        ui.label(s);
        if self.file.is_none() {
            ui.separator();
            ui.label(
                RichText::new("Load the $MFT too for full paths")
                    .color(ui.visuals().warn_fg_color),
            );
        }
    }

    /// The `$Max` header, shown above the journal table.
    pub(super) fn journal_max_strip(&self, ui: &mut egui::Ui) {
        let Some((path, m)) = &self.usn_max else { return };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("$Max").strong())
                .on_hover_text(path.display().to_string());
            let mib = |v: u64| format!("{:.1} MiB", v as f64 / (1024.0 * 1024.0));
            ui.label(format!("Max size {}", mib(m.maximum_size)));
            ui.label("·");
            ui.label(format!("Allocation delta {}", mib(m.allocation_delta)));
            ui.label("·");
            ui.label(format!("Lowest valid USN {}", m.lowest_valid_usn));
            ui.label("·");
            ui.label(format!(
                "Journal ID {:#X} (created {})",
                m.journal_id,
                mft::format_filetime(m.journal_id)
            ));
            if let Some(j) = &self.journal
                && let Some(first) = j.records.first()
                    && first.usn < m.lowest_valid_usn {
                        ui.colored_label(
                            ui.visuals().warn_fg_color,
                            "· some records predate the lowest valid USN",
                        );
                    }
        });
        ui.separator();
    }

    pub(super) fn journal_table(&mut self, ui: &mut egui::Ui) {
        let Some(j) = &self.journal else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Drop or open a $J ($UsnJrnl) file to view the change journal")
                        .size(20.0)
                        .weak(),
                );
            });
            return;
        };

        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 4.0;
        let deleted = deleted_color(ui);
        let created = if ui.visuals().dark_mode {
            Color32::from_rgb(120, 210, 120)
        } else {
            Color32::from_rgb(20, 120, 40)
        };
        let renamed = ui.visuals().warn_fg_color;

        let mut clicked: Option<usize> = None;
        let mut sort_clicked: Option<JCol> = None;
        let mut copy_text: Option<String> = None;
        let mut only_file: Option<u64> = None;
        let mut show_mft: Option<u64> = None;
        let mut go_folder: Option<usize> = None;
        let jv = &mut self.jv;
        let selected = jv.selected;
        let (sort_col, sort_asc) = (jv.sort_col, jv.sort_asc);
        let have_mft = self.file.is_some();

        egui::ScrollArea::horizontal().id_salt("jscroll").show(ui, |ui| {
            let mut table = TableBuilder::new(ui)
                .id_salt("journal_table")
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .min_scrolled_height(0.0)
                .auto_shrink([false, false]);
            for (i, (_, _, w)) in JCOLUMNS.iter().enumerate() {
                let col = Column::initial(*w).at_least(30.0).clip(true);
                table = table.column(if i == JCOLUMNS.len() - 1 {
                    col.resizable(false)
                } else {
                    col
                });
            }
            if let Some(r) = jv.scroll_to_row.take() {
                table = table.scroll_to_row(r, None);
            }
            table
                .header(text_height + 4.0, |mut header| {
                    for (c, label, _) in JCOLUMNS {
                        header.col(|ui| {
                            let arrow = match (*c == sort_col, sort_asc) {
                                (true, true) => " ⏶",
                                (true, false) => " ⏷",
                                _ => "",
                            };
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(format!("{label}{arrow}")).strong(),
                                    )
                                    .frame(false),
                                )
                                .clicked()
                            {
                                sort_clicked = Some(*c);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(text_height, jv.view.len(), |mut row| {
                        let idx = jv.view[row.index()] as usize;
                        let r = &j.records[idx];
                        row.set_selected(selected == Some(idx));
                        let color = if r.reason & usn::REASON_FILE_DELETE != 0 {
                            Some(deleted)
                        } else if r.reason & usn::REASON_FILE_CREATE != 0 {
                            Some(created)
                        } else if r.reason & usn::REASON_RENAME != 0 {
                            Some(renamed)
                        } else {
                            None
                        };
                        for (c, _, _) in JCOLUMNS {
                            row.col(|ui| {
                                let mut t = RichText::new(jcell(r, *c));
                                if matches!(c, JCol::Name | JCol::Reason)
                                    && let Some(col) = color {
                                        t = t.color(col);
                                    }
                                if matches!(
                                    c,
                                    JCol::Usn | JCol::FileRef | JCol::ParentRef | JCol::Offset
                                ) {
                                    t = t.monospace();
                                }
                                ui.add(egui::Label::new(t).truncate().selectable(false));
                            });
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            clicked = Some(idx);
                        }
                        if resp.double_clicked() {
                            go_folder = Some(idx);
                        }
                        resp.context_menu(|ui| {
                            if ui.button("🗁 Go to folder in tree").clicked() {
                                go_folder = Some(idx);
                                ui.close();
                            }
                            if ui.button("Only entries for this file").clicked() {
                                only_file = Some(r.file_record);
                                ui.close();
                            }
                            if have_mft && ui.button("Show file in $MFT").clicked() {
                                show_mft = Some(r.file_record);
                                ui.close();
                            }
                            ui.separator();
                            if ui.button("Copy resolved path").clicked() {
                                copy_text = Some(r.path.clone());
                                ui.close();
                            }
                            if ui.button("Copy row (tab separated)").clicked() {
                                let cells: Vec<String> =
                                    JCOLUMNS.iter().map(|(c, _, _)| jcell(r, *c)).collect();
                                copy_text = Some(cells.join("\t"));
                                ui.close();
                            }
                        });
                    });
                });
        });

        if let Some(t) = copy_text {
            ui.ctx().copy_text(t);
        }
        if let Some(c) = sort_clicked {
            if jv.sort_col == c {
                jv.sort_asc = !jv.sort_asc;
            } else {
                jv.sort_col = c;
                jv.sort_asc = true;
            }
            jv.dirty = true;
        }
        if let Some(i) = clicked {
            jv.selected = Some(i);
        }
        if let Some(f) = only_file {
            jv.ref_filter = Some(f);
            jv.dirty = true;
        }
        if let Some(rec) = show_mft {
            self.show_in_mft(rec as usize);
        }
        if let Some(i) = go_folder {
            self.journal_go_to_folder(i);
        }
    }

    /// Switches to the MFT view with `rec` selected and visible.
    pub(super) fn show_in_mft(&mut self, rec: usize) {
        let Some(file) = &self.file else { return };
        if rec >= file.entries.len() {
            self.status_msg = Some(format!("Record #{rec} is beyond the end of the $MFT"));
            return;
        }
        self.active = ViewKind::Mft;
        self.selected = None;
        self.select(rec);
        if !self.view.iter().any(|&r| r as usize == rec) {
            self.folder = None;
            self.filter = format!("#{rec}");
            self.view_dirty = true;
        } else {
            self.scroll_to_row = self.view.iter().position(|&r| r as usize == rec);
        }
    }

    pub(super) fn journal_details(&mut self, ui: &mut egui::Ui) {
        let (Some(j), Some(idx)) = (&self.journal, self.jv.selected) else { return };
        let Some(r) = j.records.get(idx) else { return };
        let mut close = false;
        let mut only_file = false;
        let mut show_mft = false;
        let mut go_folder = false;
        ui.horizontal(|ui| {
            ui.heading(format!("USN {}", r.usn));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("✖").on_hover_text("Close details").clicked();
            });
        });
        ui.label(RichText::new(&r.name).strong());
        ui.horizontal(|ui| {
            go_folder = ui.button("🗁 Go to folder").clicked();
            only_file = ui.button("Only this file's entries").clicked();
            if self.file.is_some() {
                show_mft = ui.button("Show in $MFT").clicked();
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            egui::Grid::new("usn_detail")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    kv(ui, "Resolved path", r.path.clone());
                    kv(ui, "Timestamp (UTC)", mft::format_filetime(r.timestamp));
                    kv(ui, "Reason", format!("0x{:08X}", r.reason));
                    kv(ui, "", usn::reason_text(r.reason));
                    kv(ui, "File reference", format!("#{} seq {}", r.file_record, r.file_seq));
                    kv(ui, "Parent reference", format!("#{} seq {}", r.parent_record, r.parent_seq));
                    kv(ui, "File attributes", mft::file_attr_long(r.file_attributes));
                    kv(ui, "Source info", usn::source_info_text(r.source_info));
                    kv(ui, "Security id", r.security_id.to_string());
                    kv(ui, "Version", format!("{}.{}", r.major, r.minor));
                    kv(ui, "Offset in $J", format!("0x{:X}", r.offset));
                    kv(ui, "Record length", r.length.to_string());
                });
            if let Some(m) = &self.file
                && let Some(e) = m.entries.get(r.file_record as usize) {
                    ui.add_space(8.0);
                    ui.strong("Current $MFT record");
                    let note = if e.sequence == r.file_seq {
                        if e.in_use { "same file, still present" } else { "same file, now deleted" }
                    } else {
                        "record has been reused by a different file"
                    };
                    egui::Grid::new("usn_mft").num_columns(2).striped(true).show(ui, |ui| {
                        kv(ui, "Status", note);
                        kv(ui, "Sequence", e.sequence.to_string());
                        kv(ui, "Path", e.path.clone());
                    });
                }
            ui.add_space(8.0);
            ui.strong("Raw record");
            egui::ScrollArea::horizontal().id_salt("usn_hex").show(ui, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(hex_string(j.record_bytes(r))).monospace())
                        .extend(),
                )
            });
        });

        if close {
            self.jv.selected = None;
        }
        if only_file {
            self.jv.ref_filter = Some(r.file_record);
            self.jv.dirty = true;
        }
        if show_mft {
            let rec = r.file_record as usize;
            self.show_in_mft(rec);
        }
        if go_folder {
            self.journal_go_to_folder(idx);
        }
    }

    pub(super) fn journal_keyboard(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::T)) {
            self.tree_open = !self.tree_open;
        }
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        if ctx.input(|i| i.key_pressed(Key::Backspace)) {
            self.journal_folder_up();
        }
        if self.jv.view.is_empty() {
            return;
        }
        let delta: isize = ctx.input(|i| {
            if i.key_pressed(Key::ArrowDown) {
                1
            } else if i.key_pressed(Key::ArrowUp) {
                -1
            } else if i.key_pressed(Key::PageDown) {
                25
            } else if i.key_pressed(Key::PageUp) {
                -25
            } else if i.key_pressed(Key::Home) {
                isize::MIN / 2
            } else if i.key_pressed(Key::End) {
                isize::MAX / 2
            } else {
                0
            }
        });
        if delta == 0 {
            return;
        }
        let jv = &mut self.jv;
        let cur = jv
            .selected
            .and_then(|s| jv.view.iter().position(|&r| r as usize == s))
            .unwrap_or(0) as isize;
        let next = cur.saturating_add(delta).clamp(0, jv.view.len() as isize - 1) as usize;
        jv.selected = Some(jv.view[next] as usize);
        jv.scroll_to_row = Some(next);
    }

    pub(super) fn export_journal_csv(&mut self) {
        let Some(j) = &self.journal else { return };
        let Some(dest) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("usn_journal.csv")
            .save_file()
        else {
            return;
        };
        let res = (|| -> std::io::Result<()> {
            let mut w = std::io::BufWriter::new(std::fs::File::create(&dest)?);
            let header: Vec<&str> = JCOLUMNS.iter().map(|c| c.1).collect();
            writeln!(w, "{}", header.join(","))?;
            for &i in &self.jv.view {
                let r = &j.records[i as usize];
                let row: Vec<String> = JCOLUMNS
                    .iter()
                    .map(|(c, _, _)| csv_escape(&jcell(r, *c)))
                    .collect();
                writeln!(w, "{}", row.join(","))?;
            }
            w.flush()
        })();
        self.status_msg = Some(match res {
            Ok(()) => format!("Exported {} rows to {}", self.jv.view.len(), dest.display()),
            Err(e) => format!("Export failed: {e}"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn journal_paths_via_mft() {
        let (Ok(jraw), Ok(mraw)) = (std::fs::read("samples/$J"), std::fs::read("samples/$MFT")) else {
            return;
        };
        let mft = MftFile::load(mraw, &AtomicUsize::new(0));
        let mut j = UsnJournal::load(jraw, &AtomicUsize::new(0));
        resolve_paths(&mut j, Some(&mft));
        let unresolved = j.records.iter().filter(|r| r.path.starts_with("[#")).count();
        println!("journal records={} unresolved={unresolved}", j.records.len());
        for r in j.records.iter().step_by(50_000) {
            println!("{} {}", usn::reason_text(r.reason), r.path);
        }
        let mut tree = super::super::journal_tree::JournalTree::default();
        tree.rebuild(&j);
        let root = &tree.nodes[0];
        println!(
            "tree folders={} root total={} creates={} deletes={}",
            tree.nodes.len(),
            root.total,
            root.creates,
            root.deletes
        );
        assert_eq!(
            (root.total + tree.nodes[1].total) as usize,
            j.records.len(),
            "every record lands in exactly one folder"
        );
        let mut top: Vec<_> = root.children.iter().map(|&c| &tree.nodes[c as usize]).collect();
        top.sort_by_key(|n| std::cmp::Reverse(n.total));
        for n in top.iter().take(4) {
            println!("  {} total={} deletes={}", n.path, n.total, n.deletes);
        }

        resolve_paths(&mut j, None);
        let unresolved = j.records.iter().filter(|r| r.path.starts_with("[#")).count();
        println!("without mft unresolved={unresolved}");
    }
}
