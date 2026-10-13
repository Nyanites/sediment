use std::cmp::Ordering as CmpOrdering;
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use eframe::egui::{self, Color32, Key, RichText};
use egui_extras::{Column, TableBuilder};

use crate::extract;
use crate::mft::{self, AttrBody, Entry, MftFile, Record};
use crate::usn::{UsnJournal, UsnMax};

mod journal;
mod journal_tree;
mod nav;
mod pf;
mod search;

use search::Matcher;

// ---------------------------------------------------------------- columns

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Col {
    Record,
    Seq,
    Status,
    Name,
    Size,
    Attrs,
    SiCreated,
    SiModified,
    SiMftModified,
    SiAccessed,
    FnCreated,
    FnModified,
    FnMftModified,
    FnAccessed,
    Ads,
    Journal,
    Path,
}

const COLUMNS: &[(Col, &str, f32)] = &[
    (Col::Record, "Record", 70.0),
    (Col::Seq, "Seq", 45.0),
    (Col::Status, "Status", 90.0),
    (Col::Name, "Name", 220.0),
    (Col::Size, "Size", 90.0),
    (Col::Attrs, "Attr", 55.0),
    (Col::SiCreated, "SI Created", 200.0),
    (Col::SiModified, "SI Modified", 200.0),
    (Col::SiMftModified, "SI MFT Modified", 200.0),
    (Col::SiAccessed, "SI Accessed", 200.0),
    (Col::FnCreated, "FN Created", 200.0),
    (Col::FnModified, "FN Modified", 200.0),
    (Col::FnMftModified, "FN MFT Modified", 200.0),
    (Col::FnAccessed, "FN Accessed", 200.0),
    (Col::Ads, "ADS", 120.0),
    (Col::Journal, "USN entries", 85.0),
    (Col::Path, "Full Path", 500.0),
];

fn status_text(e: &Entry) -> &'static str {
    match (e.valid, e.in_use, e.is_dir) {
        (false, _, _) => "(empty)",
        (true, true, true) => "Dir",
        (true, true, false) => "File",
        (true, false, true) => "Deleted Dir",
        (true, false, false) => "Deleted",
    }
}

fn cell_text(e: &Entry, c: Col) -> String {
    match c {
        Col::Record => e.record.to_string(),
        Col::Seq => e.sequence.to_string(),
        Col::Status => status_text(e).to_string(),
        Col::Name => e.name.clone(),
        Col::Size => {
            if e.is_dir || !e.valid {
                String::new()
            } else {
                e.size.to_string()
            }
        }
        Col::Attrs => mft::file_attr_short(e.file_attributes),
        Col::SiCreated => mft::format_filetime(e.si.created),
        Col::SiModified => mft::format_filetime(e.si.modified),
        Col::SiMftModified => mft::format_filetime(e.si.mft_modified),
        Col::SiAccessed => mft::format_filetime(e.si.accessed),
        Col::FnCreated => mft::format_filetime(e.fn_times.created),
        Col::FnModified => mft::format_filetime(e.fn_times.modified),
        Col::FnMftModified => mft::format_filetime(e.fn_times.mft_modified),
        Col::FnAccessed => mft::format_filetime(e.fn_times.accessed),
        Col::Ads => e.ads.join(", "),
        Col::Journal => {
            if e.journal_count == 0 {
                String::new()
            } else {
                e.journal_count.to_string()
            }
        }
        Col::Path => {
            if e.base_record != 0 {
                format!("(extension of #{})", e.base_record)
            } else {
                e.path.clone()
            }
        }
    }
}

fn compare(a: &Entry, b: &Entry, c: Col) -> CmpOrdering {
    let ord = match c {
        Col::Record => a.record.cmp(&b.record),
        Col::Seq => a.sequence.cmp(&b.sequence),
        Col::Status => status_text(a).cmp(status_text(b)),
        Col::Name => a.name_lc.cmp(&b.name_lc),
        Col::Size => a.size.cmp(&b.size),
        Col::Attrs => a.file_attributes.cmp(&b.file_attributes),
        Col::SiCreated => a.si.created.cmp(&b.si.created),
        Col::SiModified => a.si.modified.cmp(&b.si.modified),
        Col::SiMftModified => a.si.mft_modified.cmp(&b.si.mft_modified),
        Col::SiAccessed => a.si.accessed.cmp(&b.si.accessed),
        Col::FnCreated => a.fn_times.created.cmp(&b.fn_times.created),
        Col::FnModified => a.fn_times.modified.cmp(&b.fn_times.modified),
        Col::FnMftModified => a.fn_times.mft_modified.cmp(&b.fn_times.mft_modified),
        Col::FnAccessed => a.fn_times.accessed.cmp(&b.fn_times.accessed),
        Col::Ads => a.ads.len().cmp(&b.ads.len()),
        Col::Journal => a.journal_count.cmp(&b.journal_count),
        Col::Path => a.path_lc.cmp(&b.path_lc),
    };
    ord.then(a.record.cmp(&b.record))
}

// ---------------------------------------------------------------- state

#[derive(Clone, Copy, PartialEq, Eq)]
enum StateFilter {
    All,
    Active,
    Deleted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KindFilter {
    All,
    Files,
    Dirs,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Summary,
    Attributes,
    Hex,
    Journal,
}

/// Pseudo tree node collecting records whose parent chain is broken.
const ORPHAN_NODE: u32 = u32::MAX;
const ROOT_NODE: u32 = mft::ROOT_RECORD as u32;
/// Most results the "find in tree" list will hold.
const TREE_HIT_CAP: usize = 5000;

#[derive(Clone, Copy)]
struct TreeRow {
    node: u32,
    depth: u16,
    parent: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewKind {
    Mft,
    Journal,
    Prefetch,
}

/// A file decoded by the loader thread, by detected type.
enum Loaded {
    Mft(MftFile),
    Journal(UsnJournal),
    Max(UsnMax),
    Prefetch(Vec<pf::PfEntry>),
}

fn is_prefetch(raw: &[u8]) -> bool {
    raw.len() >= 8 && (&raw[..3] == b"MAM" || &raw[4..8] == b"SCCA")
}

/// Works out what kind of artifact `raw` is and decodes it.
fn load_any(
    raw: Vec<u8>,
    path: &Path,
    progress: &AtomicUsize,
    total: &AtomicUsize,
) -> Result<Loaded, String> {
    if is_prefetch(&raw) {
        return Ok(Loaded::Prefetch(vec![pf::PfEntry::from_bytes(path.to_path_buf(), &raw)]));
    }
    if raw.len() >= 4 && (&raw[..4] == b"FILE" || &raw[..4] == b"BAAD") {
        let rs = MftFile::detect_record_size(&raw);
        if raw.len() < rs {
            return Err("File is smaller than one MFT record".into());
        }
        total.store(MftFile::record_count(raw.len(), rs), Ordering::Relaxed);
        return Ok(Loaded::Mft(MftFile::load(raw, progress)));
    }
    if let Some(m) = UsnMax::parse(&raw) {
        return Ok(Loaded::Max(m));
    }
    if UsnJournal::sniff(&raw) {
        total.store(raw.len(), Ordering::Relaxed);
        return Ok(Loaded::Journal(UsnJournal::load(raw, progress)));
    }
    Err("Unrecognized file: expected an $MFT, $UsnJrnl:$J, $UsnJrnl:$Max or a prefetch (.pf) file".into())
}

/// Runs a parser, turning a panic (a parser bug) into an error message
/// instead of taking the whole app down.
fn guard_parse<T>(
    path: &Path,
    parse: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(parse))
        .unwrap_or_else(|_| Err(format!("could not parse {}: internal error", path.display())))
}

struct Loading {
    path: PathBuf,
    progress: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    rx: mpsc::Receiver<Result<Loaded, String>>,
}

pub struct MftApp {
    file: Option<MftFile>,
    file_path: Option<PathBuf>,
    journal: Option<UsnJournal>,
    journal_path: Option<PathBuf>,
    usn_max: Option<(PathBuf, UsnMax)>,
    active: ViewKind,
    jv: journal::JournalView,
    jtree: journal_tree::JournalTree,
    pf: pf::PrefetchView,
    /// Lowercase path -> MFT record, built on first use by the prefetch view.
    mft_path_index: Option<std::collections::HashMap<String, u32>>,
    /// Journal record indices for the selected MFT record.
    mft_journal_hits: Vec<u32>,
    history: nav::History,
    loading: Vec<Loading>,
    error: Option<String>,
    status_msg: Option<String>,

    filter: String,
    state_filter: StateFilter,
    kind_filter: KindFilter,
    show_empty: bool,
    only_ads: bool,
    only_timestomp: bool,

    view: Vec<u32>,
    view_dirty: bool,
    sort_col: Col,
    sort_asc: bool,

    selected: Option<usize>,
    selected_record: Option<Record>,
    scroll_to_row: Option<usize>,
    tab: DetailTab,

    tree_open: bool,
    tree_show_files: bool,
    tree_expanded: HashSet<u32>,
    tree_rows: Vec<TreeRow>,
    tree_dirty: bool,
    tree_scroll_to: Option<usize>,
    tree_find: String,
    tree_hits: Vec<u32>,
    /// Folder the table is scoped to (a record number or `ORPHAN_NODE`).
    folder: Option<u32>,
    recursive: bool,
}

impl MftApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Vec<PathBuf>) -> Self {
        let mut app = Self {
            file: None,
            file_path: None,
            journal: None,
            journal_path: None,
            usn_max: None,
            active: ViewKind::Mft,
            jv: journal::JournalView::default(),
            jtree: journal_tree::JournalTree::default(),
            pf: pf::PrefetchView::default(),
            mft_path_index: None,
            mft_journal_hits: Vec::new(),
            history: nav::History::default(),
            loading: Vec::new(),
            error: None,
            status_msg: None,
            filter: String::new(),
            state_filter: StateFilter::All,
            kind_filter: KindFilter::All,
            show_empty: false,
            only_ads: false,
            only_timestomp: false,
            view: Vec::new(),
            view_dirty: true,
            sort_col: Col::Record,
            sort_asc: true,
            selected: None,
            selected_record: None,
            scroll_to_row: None,
            tab: DetailTab::Summary,
            tree_open: true,
            tree_show_files: false,
            tree_expanded: HashSet::new(),
            tree_rows: Vec::new(),
            tree_dirty: true,
            tree_scroll_to: None,
            tree_find: String::new(),
            tree_hits: Vec::new(),
            folder: None,
            recursive: false,
        };
        for p in initial {
            app.open(p, &cc.egui_ctx);
        }
        app
    }

    fn open(&mut self, path: PathBuf, ctx: &egui::Context) {
        if path.is_dir() {
            let (pf, other) = pf::scan_folder(&path);
            if pf.is_empty() && other.is_empty() {
                self.status_msg = Some(format!(
                    "Nothing to open in {}: no $MFT, $J, $Max or .pf files",
                    path.display()
                ));
            }
            for p in other {
                self.open(p, ctx);
            }
            if !pf.is_empty() {
                self.open_prefetch_batch(pf, ctx);
            }
            return;
        }
        let progress = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let (p2, t2, path2, ctx2) = (progress.clone(), total.clone(), path.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = std::fs::read(&path2)
                .map_err(|e| format!("Failed to read {}: {e}", path2.display()))
                .and_then(|raw| {
                    guard_parse(&path2, || {
                        load_any(raw, &path2, &p2, &t2)
                            .map_err(|e| format!("{}: {e}", path2.display()))
                    })
                });
            let _ = tx.send(result);
            ctx2.request_repaint();
        });
        self.loading.push(Loading {
            path,
            progress,
            total,
            rx,
        });
        self.error = None;
    }

    fn open_dialog(&mut self, ctx: &egui::Context) {
        let picked = rfd::FileDialog::new()
            .add_filter("All files", &["*"])
            .add_filter("Prefetch files", &["pf"])
            .pick_files()
            .unwrap_or_default();
        let (pf, other): (Vec<_>, Vec<_>) = picked.into_iter().partition(|p| {
            p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pf"))
        });
        for p in other {
            self.open(p, ctx);
        }
        if !pf.is_empty() {
            self.open_prefetch_batch(pf, ctx);
        }
    }

    /// Parses many prefetch files on one background thread.
    fn open_prefetch_batch(&mut self, paths: Vec<PathBuf>, ctx: &egui::Context) {
        let progress = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(paths.len()));
        let (tx, rx) = mpsc::channel();
        let label = paths
            .first()
            .and_then(|p| p.parent())
            .map(|d| d.join(format!("{} prefetch files", paths.len())))
            .unwrap_or_default();
        let (p2, ctx2) = (progress.clone(), ctx.clone());
        std::thread::spawn(move || {
            let entries = paths
                .into_iter()
                .enumerate()
                .map(|(i, p)| {
                    p2.store(i, Ordering::Relaxed);
                    pf::PfEntry::load(p)
                })
                .collect();
            let _ = tx.send(Ok(Loaded::Prefetch(entries)));
            ctx2.request_repaint();
        });
        self.loading.push(Loading { path: label, progress, total, rx });
        self.error = None;
    }

    fn poll_loading(&mut self) {
        let mut finished = Vec::new();
        self.loading.retain(|l| match l.rx.try_recv() {
            Ok(res) => {
                finished.push((l.path.clone(), res));
                false
            }
            Err(mpsc::TryRecvError::Empty) => true,
            Err(mpsc::TryRecvError::Disconnected) => {
                finished.push((l.path.clone(), Err("Loader thread crashed".into())));
                false
            }
        });
        for (path, res) in finished {
            match res {
                Ok(Loaded::Mft(file)) => {
                    self.file_path = Some(path);
                    self.file = Some(file);
                    self.selected = None;
                    self.selected_record = None;
                    self.view_dirty = true;
                    self.folder = None;
                    self.tree_expanded = HashSet::from([ROOT_NODE]);
                    self.tree_dirty = true;
                    self.tree_find.clear();
                    self.tree_hits.clear();
                    self.history = nav::History::default();
                    self.jv.paths_dirty = true;
                    self.jv.dirty = true;
                    self.pf.invalidate_links();
                    self.mft_path_index = None;
                    if self.journal.is_none() && self.pf.entries.is_empty() {
                        self.active = ViewKind::Mft;
                    }
                }
                Ok(Loaded::Journal(j)) => {
                    self.journal_path = Some(path);
                    self.journal = Some(j);
                    self.jv = journal::JournalView::default();
                    self.jtree = journal_tree::JournalTree::default();
                    self.history = nav::History::default();
                    self.pf.invalidate_links();
                    self.active = ViewKind::Journal;
                }
                Ok(Loaded::Prefetch(entries)) => {
                    let failed: Vec<String> = entries
                        .iter()
                        .filter_map(|e| e.result.as_ref().err().map(|err| format!("{}: {err}", e.name())))
                        .collect();
                    if entries.len() == 1 && failed.len() == 1 {
                        self.error = Some(failed[0].clone());
                    }
                    self.pf.add(entries);
                    self.active = ViewKind::Prefetch;
                }
                Ok(Loaded::Max(m)) => {
                    self.usn_max = Some((path, m));
                    self.active = ViewKind::Journal;
                }
                Err(e) => self.error = Some(e),
            }
        }
    }

    fn rebuild_view(&mut self) {
        self.view_dirty = false;
        self.view.clear();
        let Some(file) = &self.file else { return };
        let matcher = Matcher::new(&self.filter);
        let record_jump = self
            .filter
            .trim()
            .strip_prefix('#')
            .and_then(|n| n.trim().parse::<u64>().ok());

        let (folder, recursive) = (self.folder, self.recursive);
        for e in &file.entries {
            if let Some(f) = folder
                && !in_folder(&file.entries, e, f, recursive) {
                    continue;
                }
            if let Some(r) = record_jump {
                if e.record == r {
                    self.view.push(e.record as u32);
                }
                continue;
            }
            if !e.valid && !self.show_empty {
                continue;
            }
            match self.state_filter {
                StateFilter::Active if !e.in_use => continue,
                StateFilter::Deleted if e.in_use || !e.valid => continue,
                _ => {}
            }
            match self.kind_filter {
                KindFilter::Files if e.is_dir => continue,
                KindFilter::Dirs if !e.is_dir => continue,
                _ => {}
            }
            if self.only_ads && e.ads.is_empty() {
                continue;
            }
            if self.only_timestomp && !e.timestomp_suspect() {
                continue;
            }
            if !matcher.matches(&e.name_lc, &e.path_lc) {
                continue;
            }
            self.view.push(e.record as u32);
        }

        let (col, asc) = (self.sort_col, self.sort_asc);
        let entries = &file.entries;
        self.view.sort_by(|&a, &b| {
            let o = compare(&entries[a as usize], &entries[b as usize], col);
            if asc { o } else { o.reverse() }
        });
        if let Some(sel) = self.selected {
            self.scroll_to_row = self.view.iter().position(|&r| r as usize == sel);
        }
    }

    fn select(&mut self, record: usize) {
        if self.selected == Some(record) {
            return;
        }
        self.selected = Some(record);
        self.selected_record = self.file.as_ref().map(|f| f.parse_record(record));
        self.refresh_mft_journal_hits();
    }

    fn export_csv(&mut self) {
        let Some(file) = &self.file else { return };
        let Some(dest) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("mft_export.csv")
            .save_file()
        else {
            return;
        };
        let res = (|| -> std::io::Result<()> {
            let mut w = std::io::BufWriter::new(std::fs::File::create(&dest)?);
            let header: Vec<&str> = COLUMNS.iter().map(|c| c.1).collect();
            writeln!(w, "{}", header.join(","))?;
            for &r in &self.view {
                let e = &file.entries[r as usize];
                let row: Vec<String> = COLUMNS
                    .iter()
                    .map(|(c, _, _)| csv_escape(&cell_text(e, *c)))
                    .collect();
                writeln!(w, "{}", row.join(","))?;
            }
            w.flush()
        })();
        self.status_msg = Some(match res {
            Ok(()) => format!("Exported {} rows to {}", self.view.len(), dest.display()),
            Err(e) => format!("Export failed: {e}"),
        });
    }
}

fn is_tree_node(e: &Entry) -> bool {
    e.valid && e.has_fn && e.base_record == 0
}

/// Whether `e` lives in `folder` (directly, or anywhere below it when
/// `recursive`).
fn in_folder(entries: &[Entry], e: &Entry, folder: u32, recursive: bool) -> bool {
    if !is_tree_node(e) || e.record == mft::ROOT_RECORD as u64 {
        return false;
    }
    if e.parent_idx.is_none() && folder == ORPHAN_NODE {
        return true;
    }
    if !recursive {
        return e.parent_indices().any(|p| p == folder);
    }
    e.parent_indices().any(|start| {
        let mut cur = start;
        for _ in 0..4096 {
            if cur == folder {
                return true;
            }
            match entries[cur as usize].parent_idx {
                Some(p) => cur = p,
                None => return folder == ORPHAN_NODE && cur != ROOT_NODE,
            }
        }
        false
    })
}

/// Tree ancestors of `rec`, top-down, excluding `rec` itself. Records not
/// under the root start with `ORPHAN_NODE`.
fn ancestors(entries: &[Entry], rec: u32) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut cur = rec;
    while let Some(p) = entries[cur as usize].parent_idx {
        if chain.contains(&p) || chain.len() > 4096 {
            break;
        }
        chain.push(p);
        cur = p;
    }
    if cur != ROOT_NODE {
        chain.push(ORPHAN_NODE);
    }
    chain.reverse();
    chain
}

fn deleted_color(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(240, 120, 120)
    } else {
        Color32::from_rgb(180, 30, 30)
    }
}

/// Quotes a CSV cell. Cells a spreadsheet would run as a formula get a
/// leading `'`, since file names and paths come from untrusted evidence.
fn csv_escape(s: &str) -> String {
    let formula = s.starts_with(['=', '+', '-', '@', '\t', '\r']);
    if formula || s.contains([',', '"', '\n', '\r']) {
        let quote = if formula { "'" } else { "" };
        format!("\"{quote}{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------- UI

impl eframe::App for MftApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_loading();

        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        for p in dropped {
            self.open(p, &ctx);
        }

        if self.view_dirty {
            self.rebuild_view();
        }
        if self.tree_dirty {
            self.rebuild_tree();
        }
        if self.jv.dirty || self.jv.paths_dirty {
            self.journal_rebuild();
        }

        self.top_bar(ui);
        self.status_bar(ui);
        match self.active {
            ViewKind::Mft => {
                if self.file.is_some() {
                    let mut open = self.tree_open;
                    egui::Panel::left("tree")
                        .resizable(true)
                        .default_size(320.0)
                        .min_size(180.0)
                        .show_collapsible(ui, &mut open, |ui| self.tree_panel(ui));
                    self.tree_open = open;
                }
                if self.selected_record.is_some() {
                    egui::Panel::right("details")
                        .resizable(true)
                        .default_size(520.0)
                        .min_size(300.0)
                        .show(ui, |ui| self.details(ui));
                }
                egui::CentralPanel::default().show(ui, |ui| {
                    self.breadcrumb(ui);
                    self.table(ui);
                });
                self.keyboard_nav(&ctx);
            }
            ViewKind::Journal => {
                if self.journal.is_some() {
                    let mut open = self.tree_open;
                    egui::Panel::left("journal_tree")
                        .resizable(true)
                        .default_size(320.0)
                        .min_size(180.0)
                        .show_collapsible(ui, &mut open, |ui| self.journal_tree_panel(ui));
                    self.tree_open = open;
                }
                if self.jv.selected.is_some() && self.journal.is_some() {
                    egui::Panel::right("journal_details")
                        .resizable(true)
                        .default_size(520.0)
                        .min_size(300.0)
                        .show(ui, |ui| self.journal_details(ui));
                }
                egui::CentralPanel::default().show(ui, |ui| {
                    self.journal_max_strip(ui);
                    self.journal_breadcrumb(ui);
                    self.journal_table(ui);
                });
                self.journal_keyboard(&ctx);
            }
            ViewKind::Prefetch => {
                if !self.pf.entries.is_empty() {
                    let mut open = self.tree_open;
                    egui::Panel::left("pf_list")
                        .resizable(true)
                        .default_size(280.0)
                        .min_size(180.0)
                        .show_collapsible(ui, &mut open, |ui| self.pf_side_list(ui));
                    self.tree_open = open;
                }
                egui::CentralPanel::default().show(ui, |ui| self.pf_main_view(ui));
                self.pf_keyboard(&ctx);
            }
        }

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_overlay"),
            ));
            let rect = ctx.content_rect();
            painter.rect_filled(rect, 0.0, Color32::from_black_alpha(160));
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Drop $MFT, $J, $Max, .pf files or folders to open",
                egui::FontId::proportional(24.0),
                Color32::WHITE,
            );
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::O)) {
            self.open_dialog(&ctx);
        }

        self.nav_input(&ctx);
        self.nav_track();

        if !self.loading.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}

impl MftApp {
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                self.nav_buttons(ui);
                ui.separator();
                if ui
                    .button("📂 Open…")
                    .on_hover_text("Open $MFT, $J, $Max and/or .pf files (Ctrl+O, multi-select allowed)")
                    .clicked()
                {
                    self.open_dialog(ui.ctx());
                }
                let can_export = match self.active {
                    ViewKind::Mft => self.file.is_some() && !self.view.is_empty(),
                    ViewKind::Journal => self.journal.is_some(),
                    ViewKind::Prefetch => self.pf.selected.is_some(),
                };
                if ui
                    .add_enabled(can_export, egui::Button::new("💾 Export CSV…"))
                    .on_hover_text("Export the currently filtered & sorted rows")
                    .clicked()
                {
                    match self.active {
                        ViewKind::Mft => self.export_csv(),
                        ViewKind::Prefetch => self.export_pf_csv(),
                        ViewKind::Journal => self.export_journal_csv(),
                    }
                }
                ui.separator();
                let name = |p: &Option<PathBuf>| {
                    p.as_ref()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().into_owned())
                };
                let mft_label = match name(&self.file_path) {
                    Some(n) => format!("🗄 MFT — {n}"),
                    None => "🗄 MFT".to_string(),
                };
                let jr_label = match name(&self.journal_path) {
                    Some(n) => format!("🕘 USN Journal — {n}"),
                    None if self.usn_max.is_some() => "🕘 USN Journal — $Max only".to_string(),
                    None => "🕘 USN Journal".to_string(),
                };
                ui.selectable_value(&mut self.active, ViewKind::Mft, mft_label)
                    .on_hover_text(
                        self.file_path
                            .as_ref()
                            .map_or("No $MFT loaded".into(), |p| p.display().to_string()),
                    );
                ui.selectable_value(&mut self.active, ViewKind::Journal, jr_label)
                    .on_hover_text(
                        self.journal_path
                            .as_ref()
                            .map_or("No $J loaded".into(), |p| p.display().to_string()),
                    );
                let pf_label = match self.pf.entries.len() {
                    0 => "⚙ Prefetch".to_string(),
                    n => format!("⚙ Prefetch ({n})"),
                };
                ui.selectable_value(&mut self.active, ViewKind::Prefetch, pf_label)
                    .on_hover_text("Prefetch (.pf) files: evidence of execution");
                {
                    ui.separator();
                    if ui
                        .selectable_label(self.tree_open, "🗀 Tree")
                        .on_hover_text("Show/hide the side panel (Ctrl+T)")
                        .clicked()
                    {
                        self.tree_open = !self.tree_open;
                    }
                }
            });
            ui.add_space(2.0);
            if self.active == ViewKind::Prefetch {
                ui.horizontal(|ui| self.pf_filter_bar(ui));
                ui.add_space(4.0);
                return;
            }
            if self.active == ViewKind::Journal {
                ui.horizontal(|ui| self.journal_filter_bar(ui));
                ui.add_space(4.0);
                return;
            }
            ui.horizontal(|ui| {
                let mut changed = false;
                ui.label("Filter:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("name, *.exe, *\\path\\*, or #record")
                        .desired_width(320.0),
                );
                changed |= resp.changed();
                if !self.filter.is_empty() && ui.small_button("✖").clicked() {
                    self.filter.clear();
                    changed = true;
                }
                ui.separator();
                for (v, label) in [
                    (StateFilter::All, "All"),
                    (StateFilter::Active, "Active"),
                    (StateFilter::Deleted, "Deleted"),
                ] {
                    changed |= ui.selectable_value(&mut self.state_filter, v, label).changed();
                }
                ui.separator();
                for (v, label) in [
                    (KindFilter::All, "All"),
                    (KindFilter::Files, "Files"),
                    (KindFilter::Dirs, "Dirs"),
                ] {
                    changed |= ui.selectable_value(&mut self.kind_filter, v, label).changed();
                }
                ui.separator();
                changed |= ui.checkbox(&mut self.only_ads, "Has ADS").changed();
                changed |= ui
                    .checkbox(&mut self.only_timestomp, "SI < FN created")
                    .on_hover_text(
                        "$STANDARD_INFORMATION creation time earlier than $FILE_NAME creation time \
                         — a common sign of timestomping",
                    )
                    .changed();
                changed |= ui
                    .checkbox(&mut self.show_empty, "Show empty records")
                    .changed();
                if changed {
                    self.view_dirty = true;
                }
            });
            ui.add_space(4.0);
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if !self.loading.is_empty() {
                    for l in &self.loading {
                        let total = l.total.load(Ordering::Relaxed);
                        let done = l.progress.load(Ordering::Relaxed);
                        let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
                        ui.spinner();
                        ui.label(format!(
                            "Loading {}",
                            l.path.file_name().unwrap_or_default().to_string_lossy()
                        ));
                        ui.add(egui::ProgressBar::new(frac).show_percentage().desired_width(160.0));
                    }
                } else if self.active == ViewKind::Prefetch {
                    self.pf_status(ui);
                } else if self.active == ViewKind::Journal {
                    self.journal_status(ui);
                } else if let Some(f) = &self.file {
                    let total = f.entries.len();
                    let active = f.entries.iter().filter(|e| e.in_use).count();
                    let deleted = f.entries.iter().filter(|e| e.valid && !e.in_use).count();
                    ui.label(format!(
                        "{} shown · {total} records ({active} active, {deleted} deleted) · {} B/record",
                        self.view.len(),
                        f.record_size
                    ));
                }
                if let Some(err) = &self.error {
                    ui.separator();
                    ui.colored_label(ui.visuals().error_fg_color, err);
                } else if let Some(msg) = &self.status_msg {
                    ui.separator();
                    ui.label(msg);
                }
            });
        });
    }

    fn keyboard_nav(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::T)) {
            self.tree_open = !self.tree_open;
        }
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        if ctx.input(|i| i.key_pressed(Key::Backspace)) {
            self.folder_up();
        }
        if ctx.input(|i| i.key_pressed(Key::Enter))
            && let (Some(sel), Some(file)) = (self.selected, &self.file) {
                let e = &file.entries[sel];
                if e.is_dir && is_tree_node(e) {
                    self.set_folder(Some(sel as u32));
                    self.reveal_in_tree(sel as u32);
                }
            }
        if self.view.is_empty() {
            return;
        }
        let (down, up, pgdn, pgup, home, end) = ctx.input(|i| {
            (
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::PageDown),
                i.key_pressed(Key::PageUp),
                i.key_pressed(Key::Home),
                i.key_pressed(Key::End),
            )
        });
        let delta: isize = if down {
            1
        } else if up {
            -1
        } else if pgdn {
            25
        } else if pgup {
            -25
        } else if home {
            isize::MIN / 2
        } else if end {
            isize::MAX / 2
        } else {
            return;
        };
        let cur = self
            .selected
            .and_then(|s| self.view.iter().position(|&r| r as usize == s))
            .unwrap_or(0) as isize;
        let next = (cur.saturating_add(delta)).clamp(0, self.view.len() as isize - 1) as usize;
        self.select(self.view[next] as usize);
        self.scroll_to_row = Some(next);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let Some(file) = &self.file else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Drop $MFT / $J / $Max / .pf files or folders here, or click Open…")
                        .size(20.0)
                        .weak(),
                );
            });
            return;
        };

        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 4.0;
        let deleted_color = deleted_color(ui);
        let dir_color = if ui.visuals().dark_mode {
            Color32::from_rgb(130, 180, 255)
        } else {
            Color32::from_rgb(20, 80, 180)
        };
        let warn_color = ui.visuals().warn_fg_color;

        let mut clicked: Option<usize> = None;
        let mut sort_clicked: Option<Col> = None;
        let mut copy_text: Option<String> = None;
        let mut navigate: Option<u32> = None;
        let mut reveal: Option<u32> = None;
        let mut to_journal: Option<u64> = None;
        let has_journal = self.journal.is_some();
        let selected = self.selected;
        let (sort_col, sort_asc) = (self.sort_col, self.sort_asc);
        let view = &self.view;

        egui::ScrollArea::horizontal().show(ui, |ui| {
            let mut table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .min_scrolled_height(0.0)
                .auto_shrink([false, false]);
            for (i, (_, _, w)) in COLUMNS.iter().enumerate() {
                let col = Column::initial(*w).at_least(30.0).clip(true);
                table = table.column(if i == COLUMNS.len() - 1 {
                    col.resizable(false)
                } else {
                    col
                });
            }
            if let Some(r) = self.scroll_to_row.take() {
                table = table.scroll_to_row(r, None);
            }

            table
                .header(text_height + 4.0, |mut header| {
                    for (c, label, _) in COLUMNS {
                        header.col(|ui| {
                            let arrow = if *c == sort_col {
                                if sort_asc { " ⏶" } else { " ⏷" }
                            } else {
                                ""
                            };
                            let resp = ui.add(
                                egui::Button::new(RichText::new(format!("{label}{arrow}")).strong())
                                    .frame(false),
                            );
                            if resp.clicked() {
                                sort_clicked = Some(*c);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(text_height, view.len(), |mut row| {
                        let rec = view[row.index()] as usize;
                        let e = &file.entries[rec];
                        row.set_selected(selected == Some(rec));
                        let base_color = if !e.in_use && e.valid {
                            Some(deleted_color)
                        } else if e.is_dir {
                            Some(dir_color)
                        } else {
                            None
                        };
                        for (c, _, _) in COLUMNS {
                            row.col(|ui| {
                                let mut t = RichText::new(cell_text(e, *c));
                                let color = match c {
                                    Col::SiCreated if e.timestomp_suspect() => Some(warn_color),
                                    Col::Name | Col::Status | Col::Path => base_color,
                                    _ => None,
                                };
                                if let Some(col) = color {
                                    t = t.color(col);
                                }
                                if matches!(c, Col::Record | Col::Seq | Col::Size | Col::Journal) {
                                    t = t.monospace();
                                }
                                ui.add(egui::Label::new(t).truncate().selectable(false));
                            });
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            clicked = Some(rec);
                        }
                        if resp.double_clicked() && e.is_dir && is_tree_node(e) {
                            navigate = Some(rec as u32);
                        }
                        resp.context_menu(|ui| {
                            if is_tree_node(e) {
                                if e.is_dir && ui.button("🗁 Open folder").clicked() {
                                    navigate = Some(rec as u32);
                                    ui.close();
                                }
                                if ui.button("⬆ Go to containing folder").clicked() {
                                    navigate = Some(e.parent_idx.unwrap_or(ORPHAN_NODE));
                                    clicked = Some(rec);
                                    ui.close();
                                }
                                if ui.button("🗁 Reveal in tree").clicked() {
                                    reveal = Some(rec as u32);
                                    ui.close();
                                }
                                if has_journal
                                    && ui
                                        .add_enabled(
                                            e.journal_count > 0,
                                            egui::Button::new(format!(
                                                "🕘 Show in USN journal ({})",
                                                e.journal_count
                                            )),
                                        )
                                        .clicked()
                                {
                                    to_journal = Some(rec as u64);
                                    ui.close();
                                }
                                ui.separator();
                            }
                            if ui.button("Copy full path").clicked() {
                                copy_text = Some(e.path.clone());
                                ui.close();
                            }
                            if ui.button("Copy name").clicked() {
                                copy_text = Some(e.name.clone());
                                ui.close();
                            }
                            if ui.button("Copy row (tab separated)").clicked() {
                                let cells: Vec<String> =
                                    COLUMNS.iter().map(|(c, _, _)| cell_text(e, *c)).collect();
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
            if self.sort_col == c {
                self.sort_asc = !self.sort_asc;
            } else {
                self.sort_col = c;
                self.sort_asc = true;
            }
            self.view_dirty = true;
        }
        if let Some(r) = clicked {
            self.select(r);
        }
        if let Some(f) = navigate {
            self.set_folder(Some(f));
            self.reveal_in_tree(f);
        }
        if let Some(r) = reveal {
            self.reveal_in_tree(r);
        }
        if let Some(r) = to_journal {
            self.open_journal_for(r, None);
        }
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        let (Some(rec), Some(file), Some(idx)) = (&self.selected_record, &self.file, self.selected)
        else {
            return;
        };
        let entry = &file.entries[idx];

        let mut close = false;
        let mut reveal = false;
        let mut show_journal = false;
        let mut extract = false;
        let mut open_journal: Option<Option<usize>> = None;
        ui.horizontal(|ui| {
            ui.heading(format!("Record #{idx}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("✖").on_hover_text("Close details").clicked();
                if extract::streams(rec).iter().any(|s| s.data.is_some()) {
                    extract = ui
                        .button("📦 Extract")
                        .on_hover_text(format!(
                            "Save the resident $DATA content (and ADS) held in this record                              to a ZIP with the password \"{}\"",
                            extract::PASSWORD
                        ))
                        .clicked();
                }
                if is_tree_node(entry) {
                    reveal = ui.button("🗁 Reveal").on_hover_text("Reveal in tree").clicked();
                }
                if self.journal.is_some() {
                    show_journal = ui
                        .button("🕘 Journal")
                        .on_hover_text("Show USN journal entries for this record")
                        .clicked();
                }
            });
        });
        if !entry.name.is_empty() {
            ui.label(RichText::new(&entry.name).strong());
        }
        let loaded_by = self.prefetch_users_of(idx as u64, entry.sequence);
        let mut open_pf: Option<(usize, usize)> = None;
        if !loaded_by.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("⚙ Loaded by").color(ui.visuals().warn_fg_color))
                    .on_hover_text("Prefetch files that reference this exact MFT record");
                for (pf_idx, file_idx, exe) in &loaded_by {
                    if ui.small_button(exe).on_hover_text("Open in the Prefetch view").clicked() {
                        open_pf = Some((*pf_idx, *file_idx));
                    }
                }
            });
        }
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, DetailTab::Summary, "Summary");
            ui.selectable_value(&mut self.tab, DetailTab::Attributes, "Attributes");
            ui.selectable_value(&mut self.tab, DetailTab::Hex, "Hex");
            let label = if self.journal.is_some() {
                format!("🕘 Journal ({})", self.mft_journal_hits.len())
            } else {
                "🕘 Journal".to_string()
            };
            ui.selectable_value(&mut self.tab, DetailTab::Journal, label)
                .on_hover_text("USN journal entries for this MFT record");
        });
        ui.separator();

        match self.tab {
            DetailTab::Summary => summary_tab(ui, rec, entry, idx, file),
            DetailTab::Attributes => attributes_tab(ui, rec),
            DetailTab::Hex => hex_view(ui, &rec.data, "hex_record"),
            DetailTab::Journal => {
                if let Some(i) = self.mft_journal_tab(ui, idx, rec.sequence) {
                    open_journal = Some(i);
                }
            }
        }
        if close {
            self.selected = None;
            self.selected_record = None;
        }
        if reveal {
            self.reveal_in_tree(idx as u32);
        }
        if show_journal {
            open_journal = Some(None);
        }
        if extract {
            self.extract_selected();
        }
        if let Some((p, f)) = open_pf {
            self.show_in_prefetch(p, f);
        }
        if let Some(sel) = open_journal {
            self.open_journal_for(idx as u64, sel);
        }
    }
}

// ---------------------------------------------------------------- tree

impl MftApp {
    fn node_children(file: &MftFile, node: u32) -> &[u32] {
        if node == ORPHAN_NODE {
            &file.orphans
        } else {
            &file.children[node as usize]
        }
    }

    fn node_expandable(&self, file: &MftFile, node: u32) -> bool {
        if node == ORPHAN_NODE {
            !file.orphans.is_empty()
        } else if self.tree_show_files {
            !file.children[node as usize].is_empty()
        } else {
            file.subdir_count[node as usize] > 0
        }
    }

    /// Flattens the expanded part of the tree into rows for virtual scrolling.
    fn rebuild_tree(&mut self) {
        self.tree_dirty = false;
        self.tree_rows.clear();
        let Some(file) = &self.file else { return };
        let mut stack: Vec<TreeRow> = Vec::new();
        if !file.orphans.is_empty() {
            stack.push(TreeRow { node: ORPHAN_NODE, depth: 0, parent: ORPHAN_NODE });
        }
        if file.entries.len() > mft::ROOT_RECORD {
            stack.push(TreeRow { node: ROOT_NODE, depth: 0, parent: ROOT_NODE });
        }
        while let Some(row) = stack.pop() {
            self.tree_rows.push(row);
            if !self.tree_expanded.contains(&row.node) {
                continue;
            }
            for &c in Self::node_children(file, row.node).iter().rev() {
                if self.tree_show_files || file.entries[c as usize].is_dir {
                    stack.push(TreeRow { node: c, depth: row.depth + 1, parent: row.node });
                }
            }
        }
    }

    fn set_folder(&mut self, folder: Option<u32>) {
        if self.folder != folder {
            self.folder = folder;
            self.view_dirty = true;
        }
    }

    fn parent_folder(&self, f: u32) -> Option<u32> {
        let file = self.file.as_ref()?;
        if f == ORPHAN_NODE || f == ROOT_NODE {
            return None;
        }
        Some(file.entries[f as usize].parent_idx.unwrap_or(ORPHAN_NODE))
    }

    fn folder_up(&mut self) {
        if let Some(up) = self.folder.and_then(|f| self.parent_folder(f)) {
            self.set_folder(Some(up));
            self.reveal_in_tree(up);
        }
    }

    /// Expands every ancestor of `rec` and scrolls the tree to it.
    fn reveal_in_tree(&mut self, rec: u32) {
        let Some(file) = &self.file else { return };
        if rec != ORPHAN_NODE {
            self.tree_expanded.extend(ancestors(&file.entries, rec));
            if !file.entries[rec as usize].is_dir {
                self.tree_show_files = true;
            }
        }
        self.tree_open = true;
        self.rebuild_tree();
        self.tree_scroll_to = self.tree_rows.iter().position(|r| r.node == rec);
    }

    fn refresh_tree_hits(&mut self) {
        self.tree_hits.clear();
        let Some(file) = &self.file else { return };
        let m = Matcher::new(&self.tree_find);
        if m.is_empty() {
            return;
        }
        self.tree_hits.extend(
            file.entries
                .iter()
                .filter(|e| is_tree_node(e) && (e.is_dir || self.tree_show_files))
                .filter(|e| m.matches(&e.name_lc, &e.path_lc))
                .map(|e| e.record as u32)
                .take(TREE_HIT_CAP),
        );
    }

    fn tree_find_results(&mut self, ui: &mut egui::Ui) {
        let Some(file) = &self.file else { return };
        search::hits_header(ui, self.tree_hits.len(), TREE_HIT_CAP);
        let deleted = deleted_color(ui);
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let mut picked: Option<u32> = None;
        egui::ScrollArea::both()
            .id_salt("tree_hits")
            .auto_shrink(false)
            .show_rows(ui, row_h, self.tree_hits.len(), |ui, range| {
                for &rec in &self.tree_hits[range] {
                    let e = &file.entries[rec as usize];
                    let icon = if e.is_dir { "🗀" } else { "🗋" };
                    let mut text = RichText::new(format!("{icon} {}", e.name));
                    if !e.in_use {
                        text = text.color(deleted);
                    }
                    ui.horizontal(|ui| {
                        ui.set_height(row_h);
                        let resp = ui
                            .add(egui::Button::selectable(false, text).frame_when_inactive(false))
                            .on_hover_text(format!("#{}  {}", e.record, e.path));
                        ui.add(egui::Label::new(RichText::new(&e.path).weak().small()).truncate());
                        if resp.clicked() {
                            picked = Some(rec);
                        }
                    });
                }
            });
        if let Some(rec) = picked {
            let e = &file.entries[rec as usize];
            let folder = if e.is_dir { rec } else { e.parent_idx.unwrap_or(ORPHAN_NODE) };
            self.tree_find.clear();
            self.set_folder(Some(folder));
            self.select(rec as usize);
            self.reveal_in_tree(rec);
            self.scroll_to_row = None;
        }
    }

    fn tree_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong("Folders");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("⊟").on_hover_text("Collapse all").clicked() {
                    self.tree_expanded = HashSet::from([ROOT_NODE]);
                    self.tree_dirty = true;
                }
                if ui
                    .checkbox(&mut self.tree_show_files, "Files")
                    .on_hover_text("Show and find files in the tree too")
                    .changed()
                {
                    self.tree_dirty = true;
                    self.refresh_tree_hits();
                }
            });
        });
        let what = if self.tree_show_files { "folders & files" } else { "folders" };
        if search::find_box(ui, &mut self.tree_find, what) {
            self.refresh_tree_hits();
        }
        ui.separator();
        if !self.tree_find.trim().is_empty() {
            self.tree_find_results(ui);
            return;
        }
        let Some(file) = &self.file else { return };

        let deleted_color = deleted_color(ui);
        let warn_color = ui.visuals().warn_fg_color;
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let mut scroll = egui::ScrollArea::both()
            .id_salt("tree_scroll")
            .auto_shrink(false);
        if let Some(i) = self.tree_scroll_to.take() {
            let step = row_h + ui.spacing().item_spacing.y;
            let offset = (i as f32 * step - ui.available_height() / 3.0).max(0.0);
            scroll = scroll.vertical_scroll_offset(offset);
        }

        let mut toggle: Option<u32> = None;
        let mut open_folder: Option<u32> = None;
        let mut select_file: Option<(u32, u32)> = None;
        let (folder, selected) = (self.folder, self.selected);

        scroll.show_rows(ui, row_h, self.tree_rows.len(), |ui, range| {
            for row in &self.tree_rows[range] {
                let node = row.node;
                let expandable = self.node_expandable(file, node);
                let expanded = self.tree_expanded.contains(&node);
                ui.horizontal(|ui| {
                    ui.set_height(row_h);
                    ui.add_space(row.depth as f32 * 14.0);
                    if expandable {
                        let icon = if expanded { "⏷" } else { "⏵" };
                        if ui.add(egui::Button::new(icon).frame(false).small()).clicked() {
                            toggle = Some(node);
                        }
                    } else {
                        ui.add_space(ui.spacing().icon_width);
                    }

                    let (text, is_dir, hover) = if node == ORPHAN_NODE {
                        (
                            RichText::new(format!("⚠ [Orphan] ({})", file.orphans.len()))
                                .color(warn_color),
                            true,
                            "Records whose parent directory no longer matches".to_string(),
                        )
                    } else {
                        let e = &file.entries[node as usize];
                        let name = if node == ROOT_NODE { "\\ (root)" } else { &e.name };
                        let icon = if e.is_dir { "🗀" } else { "🗋" };
                        let mut text = RichText::new(format!("{icon} {name}"));
                        if !e.in_use {
                            text = text.color(deleted_color);
                        }
                        let mut hover = format!("#{}  {}", e.record, e.path);
                        if e.is_dir {
                            hover.push_str(&format!(
                                "\n{} subfolders, {} entries",
                                file.subdir_count[node as usize],
                                file.children[node as usize].len()
                            ));
                        }
                        (text, e.is_dir, hover)
                    };
                    let current = if is_dir {
                        folder == Some(node)
                    } else {
                        selected == Some(node as usize)
                    };
                    let resp = ui
                        .add(egui::Button::selectable(current, text).frame_when_inactive(false))
                        .on_hover_text(hover);
                    if resp.clicked() {
                        if is_dir {
                            open_folder = Some(node);
                        } else {
                            select_file = Some((node, row.parent));
                        }
                    }
                    if resp.double_clicked() && expandable {
                        toggle = Some(node);
                    }
                });
            }
        });

        if let Some(n) = toggle {
            if !self.tree_expanded.remove(&n) {
                self.tree_expanded.insert(n);
            }
            self.tree_dirty = true;
        }
        if let Some(f) = open_folder {
            self.set_folder(Some(f));
            if f != ORPHAN_NODE {
                self.select(f as usize);
            }
        }
        if let Some((r, parent)) = select_file {
            self.set_folder(Some(parent));
            self.select(r as usize);
        }
    }

    fn breadcrumb(&mut self, ui: &mut egui::Ui) {
        let up = self.folder.and_then(|f| self.parent_folder(f));
        let Some(file) = &self.file else { return };
        let mut go: Option<Option<u32>> = None;
        let mut to_journal: Option<String> = None;
        let has_journal = self.journal.is_some();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let Some(f) = self.folder else {
                ui.label(RichText::new("🗀 All records").strong());
                ui.label(RichText::new("  — pick a folder in the tree to browse it").weak());
                return;
            };
            if ui
                .add_enabled(up.is_some(), egui::Button::new("⬆").small())
                .on_hover_text("Up one level (Backspace)")
                .clicked()
            {
                go = Some(up);
            }
            ui.add_space(4.0);
            let mut crumbs = if f == ORPHAN_NODE {
                Vec::new()
            } else {
                ancestors(&file.entries, f)
            };
            crumbs.push(f);
            for (i, &c) in crumbs.iter().enumerate() {
                if i > 0 {
                    ui.label(RichText::new(" › ").weak());
                }
                let name = match c {
                    ORPHAN_NODE => "[Orphan]",
                    ROOT_NODE => "\\",
                    n => file.entries[n as usize].name.as_str(),
                };
                let last = i == crumbs.len() - 1;
                let text = if last {
                    RichText::new(name).strong()
                } else {
                    RichText::new(name)
                };
                if ui.add(egui::Button::new(text).frame(false)).clicked() && !last {
                    go = Some(Some(c));
                }
            }
            ui.add_space(16.0);
            if ui.checkbox(&mut self.recursive, "Include subfolders").changed() {
                self.view_dirty = true;
            }
            if ui.small_button("✖ Show all").clicked() {
                go = Some(None);
            }
            if has_journal && f != ORPHAN_NODE {
                ui.add_space(8.0);
                if ui
                    .small_button("🕘 Journal activity here")
                    .on_hover_text("Open this folder in the USN journal view")
                    .clicked()
                {
                    to_journal = Some(file.entries[f as usize].path.clone());
                }
            }
        });
        ui.separator();
        if let Some(g) = go {
            self.set_folder(g);
            if let Some(f) = g {
                self.reveal_in_tree(f);
            }
        }
        if let Some(path) = to_journal {
            self.open_journal_folder(&path);
        }
    }
}

fn kv(ui: &mut egui::Ui, k: &str, v: impl Into<String>) {
    ui.label(RichText::new(k).weak());
    ui.add(egui::Label::new(RichText::new(v.into()).monospace()).wrap());
    ui.end_row();
}

fn times_grid(ui: &mut egui::Ui, id: &str, t: &mft::Timestamps) {
    egui::Grid::new(id).num_columns(2).striped(true).show(ui, |ui| {
        kv(ui, "Created", mft::format_filetime(t.created));
        kv(ui, "Modified", mft::format_filetime(t.modified));
        kv(ui, "MFT Modified", mft::format_filetime(t.mft_modified));
        kv(ui, "Accessed", mft::format_filetime(t.accessed));
    });
}

fn summary_tab(ui: &mut egui::Ui, rec: &Record, e: &Entry, idx: usize, file: &MftFile) {
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        egui::Grid::new("summary")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                kv(ui, "Full path", e.path.clone());
                kv(ui, "Status", status_text(e));
                kv(
                    ui,
                    "Signature",
                    String::from_utf8_lossy(&rec.signature).into_owned(),
                );
                kv(ui, "Fixup", if rec.fixup_ok { "OK" } else { "MISMATCH (torn write?)" });
                kv(ui, "Offset in file", format!("0x{:X}", idx * file.record_size));
                kv(ui, "Sequence", rec.sequence.to_string());
                kv(ui, "Record # (header)", rec.record_number_field.to_string());
                kv(ui, "$LogFile LSN", rec.lsn.to_string());
                kv(ui, "Flags", format!("0x{:04X}", rec.flags));
                kv(ui, "Hard links", rec.link_count.to_string());
                kv(ui, "Next attr id", rec.next_attr_id.to_string());
                kv(ui, "Used / alloc", format!("{} / {}", rec.used_size, rec.alloc_size));
                kv(
                    ui,
                    "Base record",
                    if rec.base_record == 0 {
                        "(this is a base record)".to_string()
                    } else {
                        format!("#{} seq {}", rec.base_record, rec.base_seq)
                    },
                );
                kv(ui, "Parent", format!("#{} seq {}", e.parent_record, e.parent_seq));
                for l in &e.links {
                    kv(ui, "Hard link", l.path.clone());
                }
                kv(ui, "Size", e.size.to_string());
                kv(ui, "File attributes", mft::file_attr_long(e.file_attributes));
                if !e.ads.is_empty() {
                    kv(ui, "Alt. data streams", e.ads.join(", "));
                }
            });

        if e.timestomp_suspect() {
            ui.add_space(6.0);
            ui.colored_label(
                ui.visuals().warn_fg_color,
                "⚠ $SI creation time precedes $FN creation time (possible timestomping)",
            );
        }

        ui.add_space(8.0);
        ui.strong("$STANDARD_INFORMATION");
        times_grid(ui, "si_times", &e.si);
        ui.add_space(8.0);
        ui.strong("$FILE_NAME (preferred name)");
        times_grid(ui, "fn_times", &e.fn_times);
    });
}

impl MftApp {
    fn extract_selected(&mut self) {
        let (Some(rec), Some(idx)) = (&self.selected_record, self.selected) else {
            return;
        };
        let Some(zip) = extract::resident_zip(rec, idx) else { return };
        let Some(dest) = rfd::FileDialog::new()
            .add_filter("ZIP", &["zip"])
            .set_file_name(extract::zip_file_name(rec, idx))
            .save_file()
        else {
            return;
        };
        self.status_msg = Some(match std::fs::write(&dest, zip) {
            Ok(()) => format!(
                "Extracted record #{idx} to {} (password: {})",
                dest.display(),
                extract::PASSWORD
            ),
            Err(e) => format!("Extract failed: {e}"),
        });
    }
}

fn attributes_tab(ui: &mut egui::Ui, rec: &Record) {
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        if rec.attributes.is_empty() {
            ui.label("No attributes (empty or invalid record).");
        }
        for (i, a) in rec.attributes.iter().enumerate() {
            let mut title = format!("0x{:X} {}", a.type_code, mft::attr_type_name(a.type_code));
            if !a.name.is_empty() {
                title.push_str(&format!(" \"{}\"", a.name));
            }
            if let Some(f) = a.file_name(&rec.data) {
                title.push_str(&format!(" — {} [{}]", f.name, mft::namespace_name(f.namespace)));
            }
            egui::CollapsingHeader::new(title)
                .id_salt(("attr", i))
                .default_open(true)
                .show(ui, |ui| attribute_body(ui, rec, a, i));
        }
    });
}

fn attribute_body(ui: &mut egui::Ui, rec: &Record, a: &mft::Attribute, i: usize) {
    egui::Grid::new(("attr_hdr", i))
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            kv(ui, "Offset / length", format!("0x{:X} / {}", a.offset, a.length));
            kv(ui, "Attribute id", a.id.to_string());
            kv(ui, "Flags", format!("0x{:04X}", a.flags));
            match &a.body {
                AttrBody::Resident { content_len, .. } => {
                    kv(ui, "Resident", format!("yes, {content_len} bytes"));
                }
                AttrBody::NonResident {
                    start_vcn,
                    last_vcn,
                    alloc_size,
                    real_size,
                    init_size,
                    ..
                } => {
                    kv(ui, "Resident", "no");
                    kv(ui, "VCN range", format!("{start_vcn} – {last_vcn}"));
                    kv(ui, "Real size", real_size.to_string());
                    kv(ui, "Allocated", alloc_size.to_string());
                    kv(ui, "Initialized", init_size.to_string());
                }
            }
            if let Some(si) = a.standard_info(&rec.data) {
                kv(ui, "Created", mft::format_filetime(si.times.created));
                kv(ui, "Modified", mft::format_filetime(si.times.modified));
                kv(ui, "MFT Modified", mft::format_filetime(si.times.mft_modified));
                kv(ui, "Accessed", mft::format_filetime(si.times.accessed));
                kv(ui, "File attributes", mft::file_attr_long(si.file_attributes));
                if let Some(v) = si.owner_id {
                    kv(ui, "Owner id", v.to_string());
                }
                if let Some(v) = si.security_id {
                    kv(ui, "Security id", v.to_string());
                }
                if let Some(v) = si.usn {
                    kv(ui, "USN", v.to_string());
                }
            }
            if let Some(f) = a.file_name(&rec.data) {
                kv(ui, "Name", f.name.clone());
                kv(ui, "Namespace", mft::namespace_name(f.namespace));
                kv(ui, "Parent", format!("#{} seq {}", f.parent_record, f.parent_seq));
                kv(ui, "Created", mft::format_filetime(f.times.created));
                kv(ui, "Modified", mft::format_filetime(f.times.modified));
                kv(ui, "MFT Modified", mft::format_filetime(f.times.mft_modified));
                kv(ui, "Accessed", mft::format_filetime(f.times.accessed));
                kv(ui, "Alloc / real size", format!("{} / {}", f.alloc_size, f.real_size));
                kv(ui, "Flags", mft::file_attr_long(f.flags));
            }
        });

    if a.type_code == mft::ATTR_DATA {
        ui.label(RichText::new(match a.body {
            AttrBody::Resident { .. } => "Content is in this record: 📦 Extract saves it.",
            AttrBody::NonResident { .. } => {
                "Content is in clusters on the volume, not in the $MFT, so it can't be extracted here."
            }
        }).weak());
    }
    match &a.body {
        AttrBody::NonResident { runs, .. } if !runs.is_empty() => {
            ui.add_space(4.0);
            ui.label(RichText::new(format!("Data runs ({})", runs.len())).weak());
            egui::Grid::new(("runs", i)).striped(true).show(ui, |ui| {
                ui.label(RichText::new("LCN").weak());
                ui.label(RichText::new("Clusters").weak());
                ui.end_row();
                for r in runs.iter().take(500) {
                    ui.monospace(r.lcn.map_or("sparse".into(), |l| l.to_string()));
                    ui.monospace(r.length.to_string());
                    ui.end_row();
                }
            });
            if runs.len() > 500 {
                ui.label(format!("… {} more runs", runs.len() - 500));
            }
        }
        AttrBody::Resident { .. }
            if a.type_code != mft::ATTR_STANDARD_INFORMATION
                && a.type_code != mft::ATTR_FILE_NAME =>
        {
            if let Some(c) = a.resident_content(&rec.data).filter(|c| !c.is_empty()) {
                ui.add_space(4.0);
                ui.label(RichText::new("Resident content").weak());
                egui::ScrollArea::horizontal()
                    .id_salt(("res_hex", i))
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(RichText::new(hex_string(c)).monospace()).extend())
                    });
            }
        }
        _ => {}
    }
}

fn hex_line(data: &[u8], offset: usize) -> String {
    let chunk = &data[offset..(offset + 16).min(data.len())];
    let mut s = format!("{offset:08X}  ");
    for i in 0..16 {
        match chunk.get(i) {
            Some(b) => s.push_str(&format!("{b:02X} ")),
            None => s.push_str("   "),
        }
        if i == 7 {
            s.push(' ');
        }
    }
    s.push(' ');
    for &b in chunk {
        s.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
    }
    s
}

fn hex_string(data: &[u8]) -> String {
    (0..data.len())
        .step_by(16)
        .map(|o| hex_line(data, o))
        .collect::<Vec<_>>()
        .join("\n")
}

fn hex_view(ui: &mut egui::Ui, data: &[u8], id: &str) {
    let row_h = egui::TextStyle::Monospace.resolve(ui.style()).size + 2.0;
    let lines = data.len().div_ceil(16);
    egui::ScrollArea::both()
        .id_salt(id)
        .auto_shrink(false)
        .show_rows(ui, row_h, lines, |ui, range| {
            for line in range {
                ui.add(
                    egui::Label::new(RichText::new(hex_line(data, line * 16)).monospace())
                        .extend(),
                );
            }
        });
}

pub fn file_args() -> Vec<PathBuf> {
    std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .filter(|p| Path::new(p).exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_tests::{mft_seed, mutate, usn_seed, Rng, ITERS};

    #[test]
    fn csv_neutralises_formulas() {
        assert_eq!(csv_escape("plain.txt"), "plain.txt");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        for s in ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"] {
            assert_eq!(csv_escape(s), format!("\"'{s}\""));
        }
        assert_eq!(
            csv_escape("=HYPERLINK(\"http://x\",\"y\")"),
            "\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\""
        );
    }

    #[test]
    fn parser_panic_becomes_error() {
        let r: Result<(), String> = guard_parse(Path::new("evil.pf"), || panic!("parser bug"));
        assert_eq!(r.unwrap_err(), "could not parse evil.pf: internal error");
        assert_eq!(guard_parse(Path::new("ok.pf"), || Ok(1)), Ok(1));
    }

    /// The journal folder tree is built without recursion, so a path
    /// thousands of folders deep cannot overflow the stack.
    #[test]
    fn journal_tree_deep_path() {
        let record = crate::usn::UsnRecord { path: r"\d".repeat(5000), ..Default::default() };
        let j = UsnJournal { raw: Vec::new(), records: vec![record], skipped_bytes: 0 };
        let nodes = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let mut tree = journal_tree::JournalTree::default();
                tree.rebuild(&j);
                tree.nodes.len()
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(nodes, 2 + 4999);
    }

    /// Fuzzed journals resolved against fuzzed `$MFT`s, then fed to the
    /// folder tree and the prefetch path index, as loading both does.
    #[test]
    fn fuzz_journal_against_mft() {
        let mut rng = Rng::new(0x5EED_0006);
        let jseed = usn_seed();
        for _ in 0..ITERS / 20 {
            let count = 4 + rng.below(16);
            let seed = mft_seed(&mut rng, count);
            let mft = MftFile::load(mutate(&mut rng, &seed), &AtomicUsize::new(0));
            let mut j = UsnJournal::load(mutate(&mut rng, &jseed), &AtomicUsize::new(0));
            for r in &mut j.records {
                r.file_record = rng.below(count + 2) as u64;
                r.file_seq = rng.below(3) as u16;
                r.parent_record = rng.below(count + 2) as u64;
                r.parent_seq = rng.below(3) as u16;
            }
            journal::resolve_paths(&mut j, Some(&mft));
            let mut tree = journal_tree::JournalTree::default();
            tree.rebuild(&j);
            let _ = pf::build_mft_path_index(&mft);
        }
    }
}
