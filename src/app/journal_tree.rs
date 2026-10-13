//! Folder tree for the USN journal view, built from resolved record paths so
//! it also contains folders that no longer exist in the `$MFT`.

use std::collections::HashMap;

use super::*;
use crate::usn::{self, UsnJournal};

pub(super) const JROOT: u32 = 0;
/// Pseudo node holding paths whose parent chain could not be resolved.
pub(super) const JUNRESOLVED: u32 = 1;

pub(super) struct JNode {
    pub name: String,
    pub path: String,
    pub parent: u32,
    /// Child folders, sorted by name.
    pub children: Vec<u32>,
    /// Journal records whose parent is exactly this folder.
    pub direct: u32,
    /// Records anywhere in this subtree.
    pub total: u32,
    pub creates: u32,
    pub deletes: u32,
}

impl JNode {
    fn new(name: &str, path: &str, parent: u32) -> Self {
        Self {
            name: name.to_string(),
            path: path.to_string(),
            parent,
            children: Vec::new(),
            direct: 0,
            total: 0,
            creates: 0,
            deletes: 0,
        }
    }
}

pub(super) struct JournalTree {
    pub nodes: Vec<JNode>,
    /// Folder node of each journal record (parallel to `journal.records`).
    pub record_dir: Vec<u32>,
    pub expanded: HashSet<u32>,
    pub rows: Vec<TreeRow>,
    pub rows_dirty: bool,
    pub scroll_to: Option<usize>,
    pub folder: Option<u32>,
    pub recursive: bool,
    pub by_activity: bool,
    pub find: String,
    pub hits: Vec<u32>,
    /// Lowercase folder path -> node.
    index: HashMap<String, u32>,
}

impl Default for JournalTree {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            record_dir: Vec::new(),
            expanded: HashSet::from([JROOT]),
            rows: Vec::new(),
            rows_dirty: true,
            scroll_to: None,
            folder: None,
            recursive: true,
            by_activity: false,
            find: String::new(),
            hits: Vec::new(),
            index: HashMap::new(),
        }
    }
}

fn split_parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('\\') {
        Some((parent, name)) => (parent, name),
        None => ("", path),
    }
}

impl JournalTree {
    /// Rebuilds the folder structure, keeping view settings.
    pub fn rebuild(&mut self, journal: &UsnJournal) {
        self.nodes = vec![
            JNode::new("\\ (root)", "\\", JROOT),
            JNode::new("[Unresolved parents]", "", JUNRESOLVED),
        ];
        let mut index: HashMap<String, u32> = HashMap::new();
        index.insert("\\".into(), JROOT);

        /// Node for directory path `dir`, creating it and any missing
        /// ancestors. Iterative: crafted paths can be thousands of levels deep.
        fn node_for(
            dir: &str,
            nodes: &mut Vec<JNode>,
            index: &mut HashMap<String, u32>,
        ) -> u32 {
            let mut missing = Vec::new();
            let mut cur = dir;
            let mut parent = loop {
                if cur.is_empty() || cur == "\\" {
                    break JROOT;
                }
                if let Some(&id) = index.get(&cur.to_lowercase()) {
                    break id;
                }
                missing.push(cur);
                match split_parent(cur) {
                    ("", _) if cur.starts_with('[') => break JUNRESOLVED,
                    ("", _) => break JROOT,
                    (parent_path, _) => cur = parent_path,
                }
            };
            for dir in missing.into_iter().rev() {
                let id = nodes.len() as u32;
                nodes.push(JNode::new(split_parent(dir).1, dir, parent));
                nodes[parent as usize].children.push(id);
                index.insert(dir.to_lowercase(), id);
                parent = id;
            }
            parent
        }

        self.record_dir = Vec::with_capacity(journal.records.len());
        for r in &journal.records {
            let (dir, _) = split_parent(&r.path);
            let dir_id = node_for(dir, &mut self.nodes, &mut index);
            self.record_dir.push(dir_id);
            if r.file_attributes & 0x10 != 0 {
                // Make sure directories show up even with no records inside.
                node_for(&r.path, &mut self.nodes, &mut index);
            }
            let n = &mut self.nodes[dir_id as usize];
            n.direct += 1;
            if r.reason & usn::REASON_FILE_CREATE != 0 {
                n.creates += 1;
            }
            if r.reason & usn::REASON_FILE_DELETE != 0 {
                n.deletes += 1;
            }
        }

        // Parents always precede children, so a reverse pass rolls up totals.
        for n in &mut self.nodes {
            n.total = n.direct;
        }
        for id in (2..self.nodes.len()).rev() {
            let (parent, total, c, d) = {
                let n = &self.nodes[id];
                (n.parent as usize, n.total, n.creates, n.deletes)
            };
            let p = &mut self.nodes[parent];
            p.total += total;
            p.creates += c;
            p.deletes += d;
        }

        let names: Vec<String> = self.nodes.iter().map(|n| n.name.to_lowercase()).collect();
        for n in &mut self.nodes {
            n.children.sort_by(|a, b| names[*a as usize].cmp(&names[*b as usize]));
        }
        self.index = index;
        self.folder = None;
        self.rows_dirty = true;
        self.refresh_hits();
    }

    pub fn node_by_path(&self, path: &str) -> Option<u32> {
        self.index.get(&path.to_lowercase()).copied()
    }

    fn refresh_hits(&mut self) {
        self.hits.clear();
        let m = Matcher::new(&self.find);
        if m.is_empty() {
            return;
        }
        for (id, n) in self.nodes.iter().enumerate().skip(2) {
            if m.matches(&n.name.to_lowercase(), &n.path.to_lowercase()) {
                self.hits.push(id as u32);
                if self.hits.len() >= TREE_HIT_CAP {
                    break;
                }
            }
        }
        if self.by_activity {
            self.hits
                .sort_by_key(|h| std::cmp::Reverse(self.nodes[*h as usize].total));
        }
    }

    pub fn contains(&self, record: usize, folder: u32) -> bool {
        let mut n = self.record_dir[record];
        if !self.recursive {
            return n == folder;
        }
        loop {
            if n == folder {
                return true;
            }
            let p = self.nodes[n as usize].parent;
            if p == n {
                return false;
            }
            n = p;
        }
    }

    fn ancestors(&self, node: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut n = node;
        loop {
            let p = self.nodes[n as usize].parent;
            if p == n {
                break;
            }
            chain.push(p);
            n = p;
        }
        chain.reverse();
        chain
    }

    fn flatten(&mut self) {
        self.rows_dirty = false;
        self.rows.clear();
        if self.nodes.is_empty() {
            return;
        }
        let mut stack = Vec::new();
        if self.nodes[JUNRESOLVED as usize].total > 0 {
            stack.push(TreeRow { node: JUNRESOLVED, depth: 0, parent: JUNRESOLVED });
        }
        stack.push(TreeRow { node: JROOT, depth: 0, parent: JROOT });
        while let Some(row) = stack.pop() {
            self.rows.push(row);
            if !self.expanded.contains(&row.node) {
                continue;
            }
            let mut kids = self.nodes[row.node as usize].children.clone();
            if self.by_activity {
                kids.sort_by_key(|k| std::cmp::Reverse(self.nodes[*k as usize].total));
            }
            for &c in kids.iter().rev() {
                stack.push(TreeRow { node: c, depth: row.depth + 1, parent: row.node });
            }
        }
    }

    fn reveal(&mut self, node: u32) {
        let ancestors = self.ancestors(node);
        self.expanded.extend(ancestors);
        self.flatten();
        self.scroll_to = self.rows.iter().position(|r| r.node == node);
    }
}

impl MftApp {
    pub(super) fn set_journal_folder(&mut self, folder: Option<u32>) {
        if self.jtree.folder != folder {
            self.jtree.folder = folder;
            self.jv.dirty = true;
        }
        if let Some(f) = folder {
            self.jtree.reveal(f);
            self.tree_open = true;
        }
    }

    /// Opens the folder containing journal record `idx`.
    pub(super) fn journal_go_to_folder(&mut self, idx: usize) {
        if let Some(&dir) = self.jtree.record_dir.get(idx) {
            self.set_journal_folder(Some(dir));
            self.jv.selected = Some(idx);
        }
    }

    pub(super) fn journal_folder_up(&mut self) {
        let Some(f) = self.jtree.folder else { return };
        let p = self.jtree.nodes[f as usize].parent;
        if p != f {
            self.set_journal_folder(Some(p));
        }
    }

    pub(super) fn journal_tree_panel(&mut self, ui: &mut egui::Ui) {
        let t = &mut self.jtree;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong("Folders");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("⊟").on_hover_text("Collapse all").clicked() {
                    t.expanded = HashSet::from([JROOT]);
                    t.rows_dirty = true;
                }
                if ui
                    .checkbox(&mut t.by_activity, "Busiest first")
                    .on_hover_text("Sort folders by number of journal entries")
                    .changed()
                {
                    t.rows_dirty = true;
                    t.refresh_hits();
                }
            });
        });
        if search::find_box(ui, &mut t.find, "folders") {
            t.refresh_hits();
        }
        ui.separator();
        if !t.find.trim().is_empty() {
            self.journal_find_results(ui);
            return;
        }
        if t.rows_dirty {
            t.flatten();
        }

        let deleted = deleted_color(ui);
        let warn = ui.visuals().warn_fg_color;
        let weak = ui.visuals().weak_text_color();
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let mut scroll = egui::ScrollArea::both()
            .id_salt("jtree_scroll")
            .auto_shrink(false);
        if let Some(i) = t.scroll_to.take() {
            let step = row_h + ui.spacing().item_spacing.y;
            let offset = (i as f32 * step - ui.available_height() / 3.0).max(0.0);
            scroll = scroll.vertical_scroll_offset(offset);
        }

        let mut toggle: Option<u32> = None;
        let mut open: Option<u32> = None;
        let current = t.folder;
        scroll.show_rows(ui, row_h, t.rows.len(), |ui, range| {
            for row in &t.rows[range] {
                let node = row.node;
                let n = &t.nodes[node as usize];
                let expandable = !n.children.is_empty();
                ui.horizontal(|ui| {
                    ui.set_height(row_h);
                    ui.add_space(row.depth as f32 * 14.0);
                    if expandable {
                        let icon = if t.expanded.contains(&node) { "⏷" } else { "⏵" };
                        if ui.add(egui::Button::new(icon).frame(false).small()).clicked() {
                            toggle = Some(node);
                        }
                    } else {
                        ui.add_space(ui.spacing().icon_width);
                    }
                    let text = if node == JUNRESOLVED {
                        RichText::new(format!("⚠ {}", n.name)).color(warn)
                    } else {
                        RichText::new(format!("🗀 {}", n.name))
                    };
                    let resp = ui
                        .add(
                            egui::Button::selectable(current == Some(node), text)
                                .frame_when_inactive(false),
                        )
                        .on_hover_text(format!(
                            "{}\n{} entries in subtree ({} here)\n{} creates, {} deletes",
                            if n.path.is_empty() { &n.name } else { &n.path },
                            n.total,
                            n.direct,
                            n.creates,
                            n.deletes
                        ));
                    ui.label(RichText::new(n.total.to_string()).small().color(weak));
                    if n.deletes > 0 {
                        ui.label(RichText::new(format!("−{}", n.deletes)).small().color(deleted))
                            .on_hover_text("File deletions in this subtree");
                    }
                    if resp.clicked() {
                        open = Some(node);
                    }
                    if resp.double_clicked() && expandable {
                        toggle = Some(node);
                    }
                });
            }
        });

        if let Some(n) = toggle {
            if !t.expanded.remove(&n) {
                t.expanded.insert(n);
            }
            t.rows_dirty = true;
        }
        if let Some(n) = open
            && self.jtree.folder != Some(n) {
                self.jtree.folder = Some(n);
                self.jv.dirty = true;
            }
    }

    fn journal_find_results(&mut self, ui: &mut egui::Ui) {
        let t = &self.jtree;
        search::hits_header(ui, t.hits.len(), TREE_HIT_CAP);
        let deleted = deleted_color(ui);
        let weak = ui.visuals().weak_text_color();
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let mut picked: Option<u32> = None;
        egui::ScrollArea::both()
            .id_salt("jtree_hits")
            .auto_shrink(false)
            .show_rows(ui, row_h, t.hits.len(), |ui, range| {
                for &id in &t.hits[range] {
                    let n = &t.nodes[id as usize];
                    ui.horizontal(|ui| {
                        ui.set_height(row_h);
                        let resp = ui
                            .add(
                                egui::Button::selectable(false, format!("🗀 {}", n.name))
                                    .frame_when_inactive(false),
                            )
                            .on_hover_text(format!(
                                "{}
{} entries, {} creates, {} deletes",
                                n.path, n.total, n.creates, n.deletes
                            ));
                        ui.label(RichText::new(n.total.to_string()).small().color(weak));
                        if n.deletes > 0 {
                            ui.label(RichText::new(format!("−{}", n.deletes)).small().color(deleted));
                        }
                        ui.add(egui::Label::new(RichText::new(&n.path).weak().small()).truncate());
                        if resp.clicked() {
                            picked = Some(id);
                        }
                    });
                }
            });
        if let Some(id) = picked {
            self.jtree.find.clear();
            self.jtree.hits.clear();
            self.set_journal_folder(Some(id));
        }
    }

    pub(super) fn journal_breadcrumb(&mut self, ui: &mut egui::Ui) {
        if self.journal.is_none() || self.jtree.nodes.is_empty() {
            return;
        }
        let mut go: Option<Option<u32>> = None;
        let mut to_mft: Option<String> = None;
        let has_mft = self.file.is_some();
        let t = &mut self.jtree;
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let Some(f) = t.folder else {
                ui.label(RichText::new("🗀 All entries").strong());
                ui.label(RichText::new("  — pick a folder in the tree to narrow down").weak());
                return;
            };
            let parent = t.nodes[f as usize].parent;
            if ui
                .add_enabled(parent != f, egui::Button::new("⬆").small())
                .on_hover_text("Up one level (Backspace)")
                .clicked()
            {
                go = Some(Some(parent));
            }
            ui.add_space(4.0);
            let mut crumbs = t.ancestors(f);
            crumbs.push(f);
            for (i, &c) in crumbs.iter().enumerate() {
                if i > 0 {
                    ui.label(RichText::new(" › ").weak());
                }
                let name = match c {
                    JROOT => "\\",
                    _ => t.nodes[c as usize].name.as_str(),
                };
                let last = i == crumbs.len() - 1;
                let text = if last { RichText::new(name).strong() } else { RichText::new(name) };
                if ui.add(egui::Button::new(text).frame(false)).clicked() && !last {
                    go = Some(Some(c));
                }
            }
            ui.add_space(16.0);
            if ui.checkbox(&mut t.recursive, "Include subfolders").changed() {
                self.jv.dirty = true;
            }
            if ui.small_button("✖ Show all").clicked() {
                go = Some(None);
            }
            if has_mft && f != JUNRESOLVED && !t.nodes[f as usize].path.starts_with('[') {
                ui.add_space(8.0);
                if ui
                    .small_button("🗄 Open in MFT")
                    .on_hover_text("Browse this folder's current contents in the MFT view")
                    .clicked()
                {
                    to_mft = Some(t.nodes[f as usize].path.clone());
                }
            }
        });
        ui.separator();
        if let Some(g) = go {
            self.set_journal_folder(g);
        }
        if let Some(p) = to_mft {
            self.open_mft_folder(&p);
        }
    }
}
