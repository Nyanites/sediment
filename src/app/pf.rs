//! Prefetch view: executables that ran, what they loaded, and links from each
//! loaded file into the `$MFT` and USN journal.

use std::collections::HashMap;

use chrono::{DateTime, Local, Utc};

use super::*;
use crate::prefetch::{self, FileMetric, FileRef, Prefetch};
use crate::usn;

const RED: Color32 = Color32::from_rgb(220, 80, 80);
const ORANGE: Color32 = Color32::from_rgb(230, 160, 40);

pub(super) struct PfEntry {
    pub path: PathBuf,
    pub result: Result<Prefetch, String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

impl PfEntry {
    pub fn load(path: PathBuf) -> PfEntry {
        match std::fs::read(&path) {
            Ok(raw) => PfEntry::from_bytes(path, &raw),
            Err(e) => PfEntry::with_result(path, Err(format!("cannot read file: {e}"))),
        }
    }

    pub fn from_bytes(path: PathBuf, raw: &[u8]) -> PfEntry {
        let result = guard_parse(&path, || prefetch::parse(raw).map_err(|e| e.to_string()));
        PfEntry::with_result(path, result)
    }

    fn with_result(path: PathBuf, result: Result<Prefetch, String>) -> PfEntry {
        let path = std::path::absolute(&path).unwrap_or(path);
        let meta = std::fs::metadata(&path).ok();
        PfEntry {
            result,
            created: meta.as_ref().and_then(|m| m.created().ok()).map(DateTime::<Utc>::from),
            modified: meta.as_ref().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from),
            path,
        }
    }

    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }

    fn last_run(&self) -> Option<DateTime<Utc>> {
        self.result.as_ref().ok().and_then(|p| p.last_run_times.first().copied())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Overview,
    Files,
    Directories,
    Volumes,
    FileRefs,
    TraceChains,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ListSort {
    #[default]
    Name,
    LastRun,
    RunCount,
}

/// Where a prefetch file reference points in the loaded `$MFT`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnDisk {
    Present,
    Deleted,
    Reused,
    Missing,
    NotFound,
}

impl OnDisk {
    fn label(self) -> &'static str {
        match self {
            OnDisk::Present => "present",
            OnDisk::Deleted => "deleted",
            OnDisk::Reused => "record reused",
            OnDisk::Missing => "not in $MFT",
            OnDisk::NotFound => "not found",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            OnDisk::Present => "The same file (record and sequence match) is still in the $MFT",
            OnDisk::Deleted => "The record still describes this file, but it is marked deleted",
            OnDisk::Reused => "The MFT record now holds a different file (sequence number changed)",
            OnDisk::Missing => "The record number is beyond the end of the loaded $MFT",
            OnDisk::NotFound => "No file at this path in the loaded $MFT (deleted, renamed or never on this volume)",
        }
    }
}

/// How a loaded file maps onto the `$MFT`: by the stored file reference, or,
/// when the prefetch file has none (normal on Windows 10+), by its path.
#[derive(Clone, Copy)]
pub(super) struct Resolved {
    state: OnDisk,
    record: Option<u64>,
    by_path: bool,
}

impl Resolved {
    fn label(&self) -> String {
        if self.by_path {
            format!("{} (path)", self.state.label())
        } else {
            self.state.label().to_string()
        }
    }

    fn hint(&self) -> String {
        if self.by_path {
            format!(
                "{}\nMatched by path: this prefetch file does not store an MFT reference \
                 for the file (normal on Windows 10+).",
                self.state.hint()
            )
        } else {
            self.state.hint().to_string()
        }
    }

    fn color(&self, deleted: Color32) -> Option<Color32> {
        match self.state {
            OnDisk::Present => None,
            OnDisk::Deleted => Some(deleted),
            _ => Some(ORANGE),
        }
    }
}

/// `$MFT`-style lowercase path for a prefetch path, without volume prefix or
/// alternate data stream suffix.
fn pf_path_key(p: &str) -> String {
    let s = prefetch::strip_volume(p).to_lowercase();
    match s.rsplit_once('\\') {
        Some((dir, name)) => match name.split_once(':') {
            Some((n, _)) => format!("{dir}\\{n}"),
            None => s,
        },
        None => s,
    }
}

/// Lowercase full path -> MFT record, preferring in-use records.
pub(super) fn build_mft_path_index(file: &MftFile) -> HashMap<String, u32> {
    let mut idx: HashMap<String, u32> = HashMap::with_capacity(file.entries.len());
    for e in &file.entries {
        if !e.valid || e.base_record != 0 || e.path.is_empty() {
            continue;
        }
        // Hard links matter: System32 files are usually linked into WinSxS,
        // so their primary path is the WinSxS one.
        let paths = std::iter::once(e.path_lc.clone())
            .chain(e.links.iter().map(|l| l.path.to_lowercase()));
        for p in paths {
            match idx.get(&p) {
                Some(&r) if file.entries[r as usize].in_use => {}
                _ => {
                    idx.insert(p, e.record as u32);
                }
            }
        }
    }
    idx
}

/// Cross-artifact facts about the selected prefetch file, computed once per
/// selection because they need scans of the `$MFT` / journal.
#[derive(Default)]
struct Links {
    /// MFT record of the .pf file itself.
    pf_record: Option<u32>,
    /// Earliest journal FileCreate for the .pf file (≈ first run).
    pf_journal_created: Option<u64>,
    /// File references in the prefetch file that do not match the `$MFT`.
    mismatched: usize,
    checked: usize,
}

#[derive(Default)]
pub(super) struct PrefetchView {
    pub entries: Vec<PfEntry>,
    pub selected: Option<usize>,
    tab: Tab,
    /// Selected row in the loaded-files table (index into `Prefetch::files`).
    selected_file: Option<usize>,
    scroll_to_file: bool,
    filter: String,
    list_filter: String,
    list_sort: ListSort,
    local_time: bool,
    show_volume_prefix: bool,
    links: Option<(usize, Links)>,
}

impl PrefetchView {
    pub fn add(&mut self, entries: Vec<PfEntry>) {
        let mut last = None;
        for e in entries {
            let idx = match self.entries.iter().position(|x| x.path == e.path) {
                Some(i) => {
                    self.entries[i] = e;
                    i
                }
                None => {
                    self.entries.push(e);
                    self.entries.len() - 1
                }
            };
            last = Some(idx);
        }
        if last.is_some() {
            self.select(last);
        }
        self.links = None;
    }

    pub fn select(&mut self, idx: Option<usize>) {
        if self.selected != idx {
            self.selected = idx;
            self.selected_file = None;
            self.links = None;
        }
    }

    /// Forget cached cross-artifact results (an `$MFT` or journal changed).
    pub fn invalidate_links(&mut self) {
        self.links = None;
    }

    fn fmt_time(&self, t: &DateTime<Utc>) -> String {
        // FILETIME has 100ns resolution, i.e. 7 fractional digits.
        let frac = format!(".{:07}", t.timestamp_subsec_nanos() / 100);
        if self.local_time {
            let lt = t.with_timezone(&Local);
            format!("{}{frac} {}", lt.format("%Y-%m-%d %H:%M:%S"), lt.format("%:z"))
        } else {
            format!("{}{frac} UTC", t.format("%Y-%m-%d %H:%M:%S"))
        }
    }

    fn fmt_filetime(&self, ft: u64) -> String {
        prefetch::filetime_to_utc(ft).map_or_else(|| "—".into(), |t| self.fmt_time(&t))
    }

    fn display_path<'a>(&self, p: &'a str) -> &'a str {
        if self.show_volume_prefix {
            p
        } else {
            prefetch::strip_volume(p)
        }
    }
}

fn on_disk(file: &MftFile, r: FileRef) -> OnDisk {
    match file.entries.get(r.entry() as usize) {
        None => OnDisk::Missing,
        Some(e) if !e.valid => OnDisk::Missing,
        Some(e) if e.sequence == r.sequence() => {
            if e.in_use {
                OnDisk::Present
            } else {
                OnDisk::Deleted
            }
        }
        // A deleted record has its sequence bumped by one.
        Some(e) if !e.in_use && e.sequence == r.sequence().wrapping_add(1) => OnDisk::Deleted,
        Some(_) => OnDisk::Reused,
    }
}

impl MftApp {
    pub(super) fn resolve_pf_file(&self, f: &FileMetric) -> Option<Resolved> {
        let file = self.file.as_ref()?;
        if let Some(r) = f.file_reference.filter(|r| !r.is_empty()) {
            return Some(Resolved { state: on_disk(file, r), record: Some(r.entry()), by_path: false });
        }
        let rec = self.mft_path_index.as_ref()?.get(&pf_path_key(&f.filename)).copied();
        Some(match rec {
            Some(r) => Resolved {
                state: if file.entries[r as usize].in_use { OnDisk::Present } else { OnDisk::Deleted },
                record: Some(r as u64),
                by_path: true,
            },
            None => Resolved { state: OnDisk::NotFound, record: None, by_path: true },
        })
    }

    pub(super) fn ensure_mft_path_index(&mut self) {
        if self.mft_path_index.is_none() {
            self.mft_path_index = self.file.as_ref().map(build_mft_path_index);
        }
    }

    fn pf_links(&mut self) {
        let Some(sel) = self.pf.selected else { return };
        if self.pf.links.as_ref().is_some_and(|(s, _)| *s == sel) {
            return;
        }
        let mut links = Links::default();
        if let Some(Ok(pf)) = self.pf.entries.get(sel).map(|e| &e.result) {
            let name_lc = self.pf.entries[sel].name().to_lowercase();
            let pf_path = format!("\\windows\\prefetch\\{name_lc}");
            if let Some(file) = &self.file {
                links.pf_record = file
                    .entries
                    .iter()
                    .find(|e| e.base_record == 0 && e.path_lc == pf_path)
                    .map(|e| e.record as u32);
                let refs = pf
                    .files
                    .iter()
                    .filter_map(|f| f.file_reference)
                    .chain(pf.volumes.iter().flat_map(|v| v.file_references.iter().copied()));
                for r in refs {
                    if r.is_empty() {
                        continue;
                    }
                    links.checked += 1;
                    if matches!(on_disk(file, r), OnDisk::Reused | OnDisk::Missing) {
                        links.mismatched += 1;
                    }
                }
            }
            if let Some(j) = &self.journal {
                links.pf_journal_created = j
                    .records
                    .iter()
                    .filter(|r| r.reason & usn::REASON_FILE_CREATE != 0 && r.path_lc == pf_path)
                    .map(|r| r.timestamp)
                    .min();
            }
        }
        self.pf.links = Some((sel, links));
    }

    pub(super) fn pf_filter_bar(&mut self, ui: &mut egui::Ui) {
        let v = &mut self.pf;
        if ui
            .button("🗁 Open folder…")
            .on_hover_text("Load every prefetch file in a folder and its subfolders, e.g. C:\\Windows\\Prefetch")
            .clicked()
        {
            if let Some(dir) = rfd::FileDialog::new().set_directory(default_prefetch_dir()).pick_folder() {
                self.begin_open();
                self.open(dir, ui.ctx());
            }
            return;
        }
        ui.separator();
        ui.label("Time zone:");
        ui.selectable_value(&mut v.local_time, false, "UTC");
        ui.selectable_value(&mut v.local_time, true, "Local");
        ui.separator();
        ui.checkbox(&mut v.show_volume_prefix, "Show \\VOLUME{…} prefix")
            .on_hover_text("Prefetch stores paths with a volume device prefix instead of a drive letter");
        if ui
            .add_enabled(!v.entries.is_empty(), egui::Button::new("✖ Clear prefetch"))
            .clicked()
        {
            v.entries.clear();
            v.select(None);
        }
    }

    pub(super) fn pf_status(&self, ui: &mut egui::Ui) {
        let v = &self.pf;
        let failed = v.entries.iter().filter(|e| e.result.is_err()).count();
        let mut s = format!("{} prefetch file(s)", v.entries.len());
        if failed > 0 {
            s.push_str(&format!(" · {failed} failed to parse"));
        }
        ui.label(s);
        if self.file.is_none() && !v.entries.is_empty() {
            ui.separator();
            ui.label(
                RichText::new("Load the $MFT too to see which loaded files still exist")
                    .color(ui.visuals().warn_fg_color),
            );
        }
    }

    pub(super) fn pf_side_list(&mut self, ui: &mut egui::Ui) {
        let v = &mut self.pf;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong("Prefetch");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                egui::ComboBox::from_id_salt("pf_sort")
                    .selected_text(match v.list_sort {
                        ListSort::Name => "Name",
                        ListSort::LastRun => "Last run",
                        ListSort::RunCount => "Run count",
                    })
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut v.list_sort, ListSort::Name, "Name");
                        ui.selectable_value(&mut v.list_sort, ListSort::LastRun, "Last run");
                        ui.selectable_value(&mut v.list_sort, ListSort::RunCount, "Run count");
                    });
                ui.label(RichText::new("Sort").weak());
            });
        });
        search::find_box(ui, &mut v.list_filter, "executables");
        ui.separator();

        let matcher = Matcher::new(&v.list_filter);
        let det = &self.det;
        let only = det.filter();
        let dark = ui.visuals().dark_mode;
        let mut order: Vec<usize> = (0..v.entries.len())
            .filter(|&i| only.is_none_or(|f| f.contains(&crate::detect::Target::Prefetch(i as u32))))
            .filter(|&i| {
                let n = v.entries[i].name().to_lowercase();
                matcher.matches(&n, &n)
            })
            .collect();
        match v.list_sort {
            ListSort::Name => order.sort_by_key(|&i| v.entries[i].name().to_lowercase()),
            ListSort::LastRun => order.sort_by_key(|&i| std::cmp::Reverse(v.entries[i].last_run())),
            ListSort::RunCount => order.sort_by_key(|&i| {
                std::cmp::Reverse(v.entries[i].result.as_ref().map_or(0, |p| p.run_count))
            }),
        }

        let weak = ui.visuals().weak_text_color();
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let mut clicked = None;
        let mut remove = None;
        egui::ScrollArea::both()
            .id_salt("pf_list")
            .auto_shrink(false)
            .show_rows(ui, row_h, order.len(), |ui, range| {
                for &i in &order[range] {
                    let e = &v.entries[i];
                    let name = e.name();
                    let (text, extra) = match &e.result {
                        Ok(pf) if pf.known_tool().is_some() => {
                            (RichText::new(format!("⚠ {name}")).color(RED), pf.run_count.to_string())
                        }
                        Ok(pf) => (RichText::new(&name), pf.run_count.to_string()),
                        Err(_) => (RichText::new(format!("⚠ {name}")).color(RED), "error".into()),
                    };
                    let text = match det.color(crate::detect::Target::Prefetch(i as u32), dark) {
                        Some(c) => text.color(c),
                        None => text,
                    };
                    ui.horizontal(|ui| {
                        ui.set_height(row_h);
                        let hover = match &e.result {
                            Ok(pf) => format!(
                                "{}\nRun count {}{}{}",
                                e.path.display(),
                                pf.run_count,
                                e.last_run().map_or(String::new(), |t| format!(
                                    "\nLast run {}",
                                    t.format("%Y-%m-%d %H:%M:%S UTC")
                                )),
                                pf.known_tool().map_or(String::new(), |t| format!("\n⚠ {t}"))
                            ),
                            Err(err) => format!("{}\n{err}", e.path.display()),
                        };
                        let resp = ui
                            .add(egui::Button::selectable(v.selected == Some(i), text).frame_when_inactive(false))
                            .on_hover_text(hover);
                        ui.label(RichText::new(extra).small().color(weak));
                        if resp.clicked() {
                            clicked = Some(i);
                        }
                        resp.context_menu(|ui| {
                            if ui.button("Copy path").clicked() {
                                ui.ctx().copy_text(e.path.display().to_string());
                                ui.close();
                            }
                            if ui.button("Close").clicked() {
                                remove = Some(i);
                                ui.close();
                            }
                        });
                    });
                }
            });
        if clicked.is_some() {
            v.select(clicked);
        }
        if let Some(i) = remove {
            v.entries.remove(i);
            let sel = match v.selected {
                Some(s) if s == i => None,
                Some(s) if s > i => Some(s - 1),
                s => s,
            };
            v.selected = None;
            v.select(sel);
        }
    }

    pub(super) fn pf_main_view(&mut self, ui: &mut egui::Ui) {
        let Some(idx) = self.pf.selected.filter(|&i| i < self.pf.entries.len()) else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new(
                        "Open .pf files or a folder such as C:\\Windows\\Prefetch,\n\
                         or drag and drop prefetch files here.",
                    )
                    .size(18.0)
                    .weak(),
                );
            });
            return;
        };
        self.ensure_mft_path_index();
        self.pf_links();

        let entry = &self.pf.entries[idx];
        let pf = match &entry.result {
            Ok(pf) => pf.clone(),
            Err(e) => {
                ui.heading(entry.name());
                ui.label(entry.path.display().to_string());
                ui.add_space(8.0);
                ui.colored_label(RED, format!("Failed to parse: {e}"));
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.heading(RichText::new(&pf.executable).strong());
            ui.label(RichText::new(format!("{:08X}", pf.hash)).monospace().weak());
            if let Some(tool) = pf.known_tool() {
                ui.label(RichText::new(format!("⚠ {tool}")).color(RED));
            }
        });
        if let Some(exe) = pf.executable_path() {
            ui.label(RichText::new(self.pf.display_path(exe)).monospace().color(ORANGE));
        }
        ui.add_space(4.0);

        let dir_count: usize = pf.volumes.iter().map(|v| v.directories.len()).sum();
        let ref_count: usize = pf.volumes.iter().map(|v| v.file_references.len()).sum();
        ui.horizontal(|ui| {
            let tab = &mut self.pf.tab;
            ui.selectable_value(tab, Tab::Overview, "Overview");
            ui.selectable_value(tab, Tab::Files, format!("Loaded files ({})", pf.files.len()));
            ui.selectable_value(tab, Tab::Directories, format!("Directories ({dir_count})"));
            ui.selectable_value(tab, Tab::Volumes, format!("Volumes ({})", pf.volumes.len()));
            ui.selectable_value(tab, Tab::FileRefs, format!("File references ({ref_count})"));
            ui.selectable_value(tab, Tab::TraceChains, format!("Trace chains ({})", pf.trace_chains.len()));
        });
        ui.separator();

        if matches!(self.pf.tab, Tab::Files | Tab::Directories | Tab::FileRefs | Tab::TraceChains) {
            ui.horizontal(|ui| {
                ui.label("🔍");
                ui.add(
                    egui::TextEdit::singleline(&mut self.pf.filter)
                        .hint_text("Search…  (*.dll, *\\temp\\*)")
                        .desired_width(320.0),
                )
                .on_hover_text(search::SEARCH_HELP);
                if ui.small_button("✖").clicked() {
                    self.pf.filter.clear();
                }
            });
            ui.add_space(4.0);
        }

        match self.pf.tab {
            Tab::Overview => self.pf_overview(ui, &pf, idx),
            Tab::Files => {
                if let Some(f) = self.pf.selected_file.and_then(|i| pf.files.get(i)) {
                    let f = f.clone();
                    egui::Panel::bottom("pf_file_details")
                        .resizable(true)
                        .default_size(210.0)
                        .show(ui, |ui| self.pf_file_details(ui, &pf, &f));
                    // Keep the table's column lines from painting over the panel.
                    ui.shrink_clip_rect(ui.available_rect_before_wrap());
                }
                self.pf_files_table(ui, &pf);
            }
            Tab::Directories => self.pf_directories_table(ui, &pf),
            Tab::Volumes => self.pf_volumes_view(ui, &pf),
            Tab::FileRefs => self.pf_file_refs_table(ui, &pf),
            Tab::TraceChains => self.pf_trace_chains_table(ui, &pf),
        }
    }

    fn pf_overview(&mut self, ui: &mut egui::Ui, pf: &Prefetch, idx: usize) {
        let mut jump_to = None;
        let mut go_mft: Option<u64> = None;
        let mut go_journal: Option<u64> = None;
        let v = &self.pf;
        let entry = &v.entries[idx];
        let links = v.links.as_ref().filter(|(s, _)| *s == idx).map(|(_, l)| l);
        let mut det_click = None;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            det_click = self.detection_links(ui, crate::detect::Target::Prefetch(idx as u32));
            section(ui, "Execution", |ui| {
                kv(ui, "Executable", &pf.executable);
                if let Some(tool) = pf.known_tool() {
                    ui.label(RichText::new("Known tool").weak());
                    ui.label(RichText::new(format!("⚠ {tool}")).strong().color(RED));
                    ui.end_row();
                }
                let exe_path = pf.executable_path();
                kv(
                    ui,
                    "Executable path",
                    exe_path.map(|p| v.display_path(p)).unwrap_or("— (not in loaded-file list)"),
                );
                if let Some(local) = exe_path.and_then(|p| pf.local_path(p)) {
                    kv(ui, "Path on this machine", &local);
                }
                if let Some(dir) = exe_path.and_then(|p| v.display_path(p).rsplit_once('\\')) {
                    kv(ui, "Launched from", if dir.0.is_empty() { "\\" } else { dir.0 });
                }
                kv(ui, "Run count", pf.run_count.to_string());
                if pf.last_run_times.is_empty() {
                    kv(ui, "Last run", "—");
                }
                for (i, t) in pf.last_run_times.iter().enumerate() {
                    let label = if i == 0 { "Last run".to_string() } else { format!("Previous run {i}") };
                    kv(ui, &label, v.fmt_time(t));
                }
                if pf.run_count as usize > pf.last_run_times.len() && pf.last_run_times.len() == 8 {
                    note(ui, "Only the 8 most recent run times are stored.");
                }

                // Prefetch has no first-run field. Windows creates the .pf
                // file shortly after the first run, so its creation time is
                // the usual estimate, unless the file was copied.
                if let Some(t) = links.and_then(|l| l.pf_journal_created) {
                    kv(ui, "First run (estimate)", v.fmt_filetime(t));
                    note(ui, "From the USN journal: when this .pf file was created.");
                } else if let Some(created) = entry.created {
                    let last = pf.last_run_times.first();
                    if last.is_some_and(|l| created > *l + chrono::Duration::seconds(60)) {
                        kv(ui, "First run (estimate)", "— not available");
                        note(
                            ui,
                            "The .pf file was created after the last run, so it was copied \
                             and its creation time does not show the first run.",
                        );
                    } else {
                        kv(ui, "First run (estimate)", v.fmt_time(&created));
                        note(ui, "Based on the .pf file's creation time.");
                    }
                }
            });

            if self.file.is_some() || self.journal.is_some() {
                section(ui, "Cross-artifact", |ui| {
                    let exe = pf
                        .executable_path()
                        .and_then(|p| pf.files.iter().find(|f| f.filename == p));
                    if let Some(res) = exe.and_then(|f| self.resolve_pf_file(f)) {
                        ui.label(RichText::new("Executable in $MFT").weak());
                        ui.horizontal(|ui| {
                            let text = match res.record {
                                Some(r) => format!("#{r} · {}", res.label()),
                                None => res.label(),
                            };
                            let mut t = RichText::new(text).monospace();
                            if let Some(c) = res.color(deleted_color(ui)) {
                                t = t.color(c);
                            }
                            ui.label(t).on_hover_text(res.hint());
                            if let Some(r) = res.record {
                                if ui.small_button("🗄 Show").clicked() {
                                    go_mft = Some(r);
                                }
                                if self.journal.is_some() && ui.small_button("🕘 Journal").clicked() {
                                    go_journal = Some(r);
                                }
                            }
                        });
                        ui.end_row();
                    }
                    if let Some(l) = links
                        && self.file.is_some() {
                            ui.label(RichText::new("This .pf in $MFT").weak());
                            ui.horizontal(|ui| match l.pf_record {
                                Some(rec) => {
                                    ui.label(RichText::new(format!("#{rec}")).monospace());
                                    if ui.small_button("🗄 Show").clicked() {
                                        go_mft = Some(rec as u64);
                                    }
                                    if self.journal.is_some() && ui.small_button("🕘 Journal").clicked() {
                                        go_journal = Some(rec as u64);
                                    }
                                }
                                None => {
                                    ui.label(
                                        RichText::new("not found under \\Windows\\Prefetch").weak(),
                                    );
                                }
                            });
                            ui.end_row();
                            if l.checked > 0 {
                                kv(
                                    ui,
                                    "References matching $MFT",
                                    format!("{} of {}", l.checked - l.mismatched, l.checked),
                                );
                                if l.mismatched * 2 > l.checked {
                                    ui.label("");
                                    ui.label(
                                        RichText::new(
                                            "⚠ Most file references don't match the loaded $MFT: \
                                             this prefetch file is probably from a different system.",
                                        )
                                        .color(ORANGE),
                                    );
                                    ui.end_row();
                                }
                            }
                        }
                });
            }

            let caps = pf.capabilities();
            if !caps.is_empty() {
                section(ui, "Capabilities (from loaded libraries)", |ui| {
                    for (cap, dlls) in &caps {
                        kv(ui, cap, dlls.join(", "));
                    }
                });
            }

            section(ui, "Context", |ui| {
                let users = pf.user_accounts();
                kv(
                    ui,
                    "User profiles referenced",
                    &if users.is_empty() { "—".into() } else { users.join(", ") },
                );
                let domains = pf.domains();
                if !domains.is_empty() {
                    kv(ui, "AD domains (schema cache)", domains.join(", "));
                }
                for vol in &pf.volumes {
                    kv(ui, "Volume", format!("{}  (serial {:08X})", vol.device_path, vol.serial_number));
                }
                kv(ui, "Files loaded", pf.files.len().to_string());
                kv(
                    ui,
                    "Directories referenced",
                    pf.volumes.iter().map(|v| v.directories.len()).sum::<usize>().to_string(),
                );
            });

            let notable = pf.notable_files();
            egui::CollapsingHeader::new(
                RichText::new(format!("Notable files ({})", notable.len())).strong().size(15.0),
            )
            .default_open(true)
            .show(ui, |ui| {
                if notable.is_empty() {
                    ui.label(RichText::new("Nothing outside the usual system locations.").weak());
                }
                egui::Grid::new("notable").num_columns(2).spacing([24.0, 6.0]).striped(true).show(
                    ui,
                    |ui| {
                        for n in &notable {
                            let f = &pf.files[n.file_index];
                            let resp = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(v.display_path(&f.filename)).monospace().color(ORANGE),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_text("Click to show in Loaded files");
                            if resp.clicked() {
                                jump_to = Some(n.file_index);
                            }
                            ui.label(&n.reason);
                            ui.end_row();
                        }
                    },
                );
            });
            ui.add_space(6.0);

            section(ui, "Prefetch file", |ui| {
                kv(ui, "Path", entry.path.display().to_string());
                if let Some(t) = entry.created {
                    kv(ui, "File created", v.fmt_time(&t));
                }
                if let Some(t) = entry.modified {
                    kv(ui, "File modified", v.fmt_time(&t));
                }
                kv(
                    ui,
                    "Format version",
                    format!("{} ({})", pf.version, prefetch::windows_version_name(pf.version)),
                );
                kv(ui, "Signature", &pf.signature);
                kv(ui, "Prefetch hash", format!("{:08X}", pf.hash));
                kv(ui, "Compression", if pf.compressed { "MAM (Xpress Huffman)" } else { "None" });
                kv(ui, "Size on disk", format!("{} bytes", pf.compressed_size));
                kv(ui, "Decompressed size", format!("{} bytes", pf.file_size));
            });

            section(ui, "Section layout", |ui| {
                let rows = [
                    ("File metrics", pf.metrics_offset, pf.metrics_count, None),
                    ("Trace chains", pf.trace_chains_offset, pf.trace_chains_count, None),
                    ("Filename strings", pf.filename_strings_offset, 0, Some(pf.filename_strings_size)),
                    ("Volume info", pf.volumes_offset, pf.volumes_count, Some(pf.volumes_size)),
                ];
                for (name, off, count, size) in rows {
                    let mut s = format!("offset 0x{off:X}");
                    if count > 0 {
                        s.push_str(&format!(", {count} entries"));
                    }
                    if let Some(size) = size {
                        s.push_str(&format!(", {size} bytes"));
                    }
                    kv(ui, name, &s);
                }
            });
        });
        if let Some(i) = jump_to {
            self.pf.tab = Tab::Files;
            self.pf.filter.clear();
            self.pf.selected_file = Some(i);
            self.pf.scroll_to_file = true;
        }
        if let Some(r) = go_mft {
            self.show_in_mft(r as usize);
        }
        if let Some(r) = go_journal {
            self.open_journal_for(r, None);
        }
        if let Some(rule) = det_click {
            self.set_detection(Some(super::detections::Active::Rule(rule)));
        }
    }

    fn pf_file_details(&mut self, ui: &mut egui::Ui, pf: &Prefetch, f: &FileMetric) {
        let mut go_mft = false;
        let mut go_journal = false;
        let res = self.resolve_pf_file(f);
        let rec = res.and_then(|r| r.record);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.strong(format!("File #{}", f.index));
            if ui.small_button("📋 Copy path").clicked() {
                ui.ctx().copy_text(f.filename.clone());
            }
            if let (Some(res), Some(_)) = (res, rec) {
                go_mft = ui.small_button("🗄 Show in $MFT").on_hover_text(res.hint()).clicked();
            }
            if rec.is_some() && self.journal.is_some() {
                go_journal = ui
                    .small_button("🕘 Journal history")
                    .on_hover_text("USN journal entries for this MFT record")
                    .clicked();
            }
        });
        ui.add_space(4.0);
        let v = &self.pf;
        egui::ScrollArea::vertical().id_salt("pf_details_scroll").show(ui, |ui| {
            egui::Grid::new("pf_file_details_grid").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                let display = v.display_path(&f.filename);
                let (dir, name) = display.rsplit_once('\\').unwrap_or(("", display));
                kv(ui, "Full path", &f.filename);
                kv(ui, "Directory", if dir.is_empty() { "\\" } else { dir });
                kv(ui, "File name", name);
                kv(ui, "Flags", format!("0x{:08X}", f.flags));
                let mft = match f.file_reference {
                    Some(r) if !r.is_empty() => format!("entry {}, sequence {}", r.entry(), r.sequence()),
                    Some(_) => "— (not recorded in this file)".into(),
                    None => "— (not stored in format version 17)".into(),
                };
                kv(ui, "MFT reference", &mft);
                if let (Some(res), Some(file)) = (res, &self.file) {
                    kv(ui, "In loaded $MFT", res.label());
                    if let Some(e) = rec.and_then(|r| file.entries.get(r as usize)).filter(|e| e.valid) {
                        kv(ui, "MFT record", format!("#{} seq {}", e.record, e.sequence));
                        if matches!(res.state, OnDisk::Reused) {
                            kv(ui, "Record now holds", &e.path);
                        }
                        if e.journal_count > 0 {
                            kv(ui, "USN journal entries", e.journal_count.to_string());
                        }
                    }
                }
                let end = f.trace_chain_index + f.trace_chain_count;
                kv(
                    ui,
                    "Trace chain entries",
                    format!(
                        "{} entries (#{} – #{})",
                        f.trace_chain_count,
                        f.trace_chain_index,
                        end.saturating_sub(1)
                    ),
                );
                if let Some(u) = f.unknown_08 {
                    kv(ui, "Field +0x08 (undocumented)", u.to_string());
                }
                if let Some(n) = pf.notable_files().iter().find(|n| n.file_index == f.index) {
                    kv(ui, "Notable", &n.reason);
                }
            });
        });
        if let Some(r) = rec {
            if go_mft {
                self.show_in_mft(r as usize);
            }
            if go_journal {
                self.open_journal_for(r, None);
            }
        }
    }

    fn pf_files_table(&mut self, ui: &mut egui::Ui, pf: &Prefetch) {
        let v = &self.pf;
        let matcher = Matcher::new(&v.filter);
        let rows: Vec<&FileMetric> = pf
            .files
            .iter()
            .filter(|f| {
                let p = f.filename.to_lowercase();
                let name = p.rsplit('\\').next().unwrap_or(&p);
                matcher.matches(name, prefetch::strip_volume(&p))
            })
            .collect();
        let exe = pf.executable_path().map(str::to_string);
        let notable: Vec<usize> = pf.notable_files().iter().map(|n| n.file_index).collect();
        let mft = self.file.as_ref();
        let deleted = deleted_color(ui);

        let mut table = TableBuilder::new(ui)
            .id_salt("pf_files")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .auto_shrink([false, false])
            .column(Column::initial(40.0).at_least(30.0))
            .column(Column::initial(85.0).at_least(60.0))
            .column(Column::initial(75.0).at_least(50.0))
            .column(Column::initial(45.0).at_least(35.0));
        if mft.is_some() {
            table = table
                .column(Column::initial(105.0).at_least(60.0))
                .column(Column::initial(55.0).at_least(40.0));
        }
        table = table
            .column(Column::initial(110.0).at_least(60.0))
            .column(Column::remainder().at_least(200.0).clip(true));
        if v.scroll_to_file
            && let Some(pos) = rows.iter().position(|f| Some(f.index) == v.selected_file) {
                table = table.scroll_to_row(pos, Some(egui::Align::Center));
            }
        let mut clicked = None;
        table
            .header(22.0, |mut h| {
                h.col(|ui| _ = ui.strong("#"));
                h.col(|ui| _ = ui.strong("Flags"));
                h.col(|ui| _ = ui.strong("MFT entry"));
                h.col(|ui| _ = ui.strong("Seq"));
                if mft.is_some() {
                    h.col(|ui| {
                        ui.strong("In $MFT")
                            .on_hover_text("Whether the referenced file is still in the loaded $MFT");
                    });
                    h.col(|ui| {
                        ui.strong("USN").on_hover_text("USN journal entries for the MFT record");
                    });
                }
                h.col(|ui| {
                    ui.strong("Trace chains")
                        .on_hover_text("First trace chain entry index + number of entries");
                });
                h.col(|ui| _ = ui.strong("Path"));
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let f = rows[row.index()];
                    row.set_selected(v.selected_file == Some(f.index));
                    let (entry, seq) = ref_cols(f.file_reference);
                    row.col(|ui| plain(ui, f.index.to_string()));
                    row.col(|ui| plain(ui, RichText::new(format!("0x{:08X}", f.flags)).monospace()));
                    row.col(|ui| plain(ui, entry));
                    row.col(|ui| plain(ui, seq));
                    if let Some(file) = mft {
                        let res = self.resolve_pf_file(f);
                        row.col(|ui| {
                            let Some(res) = res else {
                                plain(ui, "—");
                                return;
                            };
                            let mut t = RichText::new(res.label());
                            if let Some(c) = res.color(deleted) {
                                t = t.color(c);
                            }
                            ui.add(egui::Label::new(t).selectable(false)).on_hover_text(res.hint());
                        });
                        row.col(|ui| {
                            let n = res
                                .and_then(|r| r.record)
                                .and_then(|r| file.entries.get(r as usize))
                                .map_or(0, |e| e.journal_count);
                            plain(ui, if n == 0 { String::new() } else { n.to_string() });
                        });
                    }
                    row.col(|ui| plain(ui, format!("{} + {}", f.trace_chain_index, f.trace_chain_count)));
                    row.col(|ui| {
                        let shown = v.display_path(&f.filename);
                        let text = if exe.as_deref() == Some(f.filename.as_str()) {
                            RichText::new(shown).strong().color(ORANGE)
                        } else if notable.contains(&f.index) {
                            RichText::new(shown).color(ORANGE)
                        } else {
                            RichText::new(shown)
                        };
                        path_label(ui, text, &f.filename);
                    });
                    if row.response().clicked() {
                        clicked = Some(f.index);
                    }
                });
            });
        self.pf.scroll_to_file = false;
        if let Some(i) = clicked {
            self.pf.selected_file = if self.pf.selected_file == Some(i) { None } else { Some(i) };
        }
    }

    fn pf_directories_table(&self, ui: &mut egui::Ui, pf: &Prefetch) {
        let v = &self.pf;
        let matcher = Matcher::new(&v.filter);
        let rows: Vec<(usize, &String)> = pf
            .volumes
            .iter()
            .enumerate()
            .flat_map(|(vi, vol)| vol.directories.iter().map(move |d| (vi, d)))
            .filter(|(_, d)| {
                let p = d.to_lowercase();
                let name = p.rsplit('\\').next().unwrap_or(&p);
                matcher.matches(name, prefetch::strip_volume(&p))
            })
            .collect();
        TableBuilder::new(ui)
            .id_salt("pf_dirs")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(60.0).at_least(40.0))
            .column(Column::remainder().clip(true))
            .header(22.0, |mut h| {
                h.col(|ui| _ = ui.strong("Volume"));
                h.col(|ui| _ = ui.strong("Directory"));
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let (vi, d) = rows[row.index()];
                    row.col(|ui| plain(ui, vi.to_string()));
                    row.col(|ui| path_label(ui, RichText::new(v.display_path(d)), d));
                });
            });
    }

    fn pf_volumes_view(&self, ui: &mut egui::Ui, pf: &Prefetch) {
        let v = &self.pf;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for (i, vol) in pf.volumes.iter().enumerate() {
                section(ui, &format!("Volume {i}"), |ui| {
                    kv(ui, "Device path", &vol.device_path);
                    kv(ui, "Serial number", format!("{:08X}", vol.serial_number));
                    kv(
                        ui,
                        "Creation time",
                        vol.creation_time.map(|t| v.fmt_time(&t)).unwrap_or_else(|| "—".into()),
                    );
                    kv(ui, "Directories", vol.directories.len().to_string());
                    kv(ui, "File references", vol.file_references.len().to_string());
                });
            }
        });
    }

    fn pf_file_refs_table(&mut self, ui: &mut egui::Ui, pf: &Prefetch) {
        let filter = self.pf.filter.to_lowercase();
        let rows: Vec<(usize, usize, FileRef)> = pf
            .volumes
            .iter()
            .enumerate()
            .flat_map(|(vi, vol)| vol.file_references.iter().enumerate().map(move |(ri, r)| (vi, ri, *r)))
            .filter(|(_, _, r)| filter.is_empty() || r.to_string().contains(&filter))
            .collect();
        let mft = self.file.as_ref();
        let deleted = deleted_color(ui);
        let mut go_mft = None;
        let mut table = TableBuilder::new(ui)
            .id_salt("pf_refs")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(60.0).at_least(40.0))
            .column(Column::initial(60.0).at_least(40.0))
            .column(Column::initial(110.0).at_least(60.0))
            .column(Column::initial(70.0).at_least(40.0))
            .column(Column::initial(170.0).at_least(60.0));
        if mft.is_some() {
            table = table.column(Column::remainder().clip(true));
        }
        table
            .header(22.0, |mut h| {
                h.col(|ui| _ = ui.strong("Volume"));
                h.col(|ui| _ = ui.strong("#"));
                h.col(|ui| _ = ui.strong("MFT entry"));
                h.col(|ui| _ = ui.strong("Seq"));
                h.col(|ui| _ = ui.strong("Raw"));
                if mft.is_some() {
                    h.col(|ui| _ = ui.strong("In $MFT"));
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let (vi, ri, r) = rows[row.index()];
                    row.col(|ui| plain(ui, vi.to_string()));
                    row.col(|ui| plain(ui, ri.to_string()));
                    row.col(|ui| plain(ui, r.entry().to_string()));
                    row.col(|ui| plain(ui, r.sequence().to_string()));
                    row.col(|ui| plain(ui, RichText::new(format!("0x{:016X}", r.raw)).monospace()));
                    if let Some(file) = mft {
                        row.col(|ui| {
                            if r.is_empty() {
                                plain(ui, "—");
                                return;
                            }
                            let state = on_disk(file, r);
                            let label = match file.entries.get(r.entry() as usize) {
                                Some(e) if e.valid && state != OnDisk::Missing => {
                                    format!("{} · {}", state.label(), e.path)
                                }
                                _ => state.label().to_string(),
                            };
                            let mut t = RichText::new(label);
                            if state == OnDisk::Deleted {
                                t = t.color(deleted);
                            } else if state != OnDisk::Present {
                                t = t.color(ORANGE);
                            }
                            let resp = ui
                                .add(egui::Label::new(t).truncate().sense(egui::Sense::click()))
                                .on_hover_text(format!("{}\nClick to show in the $MFT", state.hint()));
                            if resp.clicked() && state != OnDisk::Missing {
                                go_mft = Some(r.entry());
                            }
                        });
                    }
                });
            });
        if let Some(r) = go_mft {
            self.show_in_mft(r as usize);
        }
    }

    fn pf_trace_chains_table(&self, ui: &mut egui::Ui, pf: &Prefetch) {
        let v = &self.pf;
        let matcher = Matcher::new(&v.filter);
        let file_of = |t: &prefetch::TraceChain| t.file_index.and_then(|i| pf.files.get(i));
        let rows: Vec<&prefetch::TraceChain> = pf
            .trace_chains
            .iter()
            .filter(|t| {
                matcher.is_empty()
                    || file_of(t).is_some_and(|f| {
                        let p = f.filename.to_lowercase();
                        let name = p.rsplit('\\').next().unwrap_or(&p);
                        matcher.matches(name, prefetch::strip_volume(&p))
                    })
            })
            .collect();
        let has_next = pf.version < 30;
        let mut table = TableBuilder::new(ui)
            .id_salt("pf_chains")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(60.0).at_least(40.0));
        if has_next {
            table = table.column(Column::initial(80.0).at_least(40.0));
        }
        table
            .column(Column::initial(110.0).at_least(60.0))
            .column(Column::initial(55.0).at_least(40.0))
            .column(Column::initial(70.0).at_least(40.0))
            .column(Column::initial(75.0).at_least(40.0))
            .column(Column::remainder().clip(true))
            .header(22.0, |mut h| {
                h.col(|ui| _ = ui.strong("#"));
                if has_next {
                    h.col(|ui| _ = ui.strong("Next index"));
                }
                h.col(|ui| _ = ui.strong("Block load count"));
                h.col(|ui| _ = ui.strong("Flags"));
                h.col(|ui| _ = ui.strong("Unknown"));
                h.col(|ui| _ = ui.strong("Unknown 2"));
                h.col(|ui| _ = ui.strong("File"));
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let t = rows[row.index()];
                    row.col(|ui| plain(ui, t.index.to_string()));
                    if has_next {
                        row.col(|ui| {
                            plain(
                                ui,
                                match t.next_index {
                                    Some(0xFFFF_FFFF) | None => "—".to_string(),
                                    Some(n) => n.to_string(),
                                },
                            )
                        });
                    }
                    row.col(|ui| plain(ui, t.block_load_count.to_string()));
                    row.col(|ui| plain(ui, RichText::new(format!("0x{:02X}", t.flags)).monospace()));
                    row.col(|ui| plain(ui, RichText::new(format!("0x{:02X}", t.unknown)).monospace()));
                    row.col(|ui| plain(ui, RichText::new(format!("0x{:04X}", t.unknown2)).monospace()));
                    row.col(|ui| match file_of(t) {
                        Some(f) => path_label(ui, RichText::new(v.display_path(&f.filename)), &f.filename),
                        None => plain(ui, "—"),
                    });
                });
            });
    }

    pub(super) fn pf_keyboard(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::T)) {
            self.tree_open = !self.tree_open;
        }
        if ctx.egui_wants_keyboard_input() || self.pf.entries.is_empty() {
            return;
        }
        let delta: isize = ctx.input(|i| {
            if i.key_pressed(Key::ArrowDown) {
                1
            } else if i.key_pressed(Key::ArrowUp) {
                -1
            } else {
                0
            }
        });
        if delta != 0 && self.pf.tab != Tab::Files {
            let n = self.pf.entries.len() as isize;
            let cur = self.pf.selected.map_or(-1, |s| s as isize);
            let next = (cur + delta).clamp(0, n - 1) as usize;
            self.pf.select(Some(next));
        }
    }

    pub(super) fn export_pf_csv(&mut self) {
        let Some(PfEntry { path, result: Ok(pf), .. }) = self.pf.selected.and_then(|i| self.pf.entries.get(i))
        else {
            return;
        };
        let default_name = format!("{}.csv", path.file_stem().unwrap_or_default().to_string_lossy());
        let Some(out) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name(default_name)
            .save_file()
        else {
            return;
        };
        let mft = self.file.as_ref();
        let mut csv = String::from(
            "Index,Filename,Flags,MftEntry,MftSequence,InMft,TraceChainIndex,TraceChainCount\n",
        );
        for f in &pf.files {
            let r = f.file_reference.filter(|r| !r.is_empty());
            let (entry, seq) = r.map_or((String::new(), String::new()), |r| {
                (r.entry().to_string(), r.sequence().to_string())
            });
            let in_mft = match mft {
                Some(_) => self.resolve_pf_file(f).map(|r| r.label()).unwrap_or_default(),
                None => String::new(),
            };
            csv.push_str(&format!(
                "{},{},0x{:08X},{},{},{},{},{}\n",
                f.index,
                csv_escape(&f.filename),
                f.flags,
                entry,
                seq,
                in_mft,
                f.trace_chain_index,
                f.trace_chain_count,
            ));
        }
        self.status_msg = Some(match std::fs::write(&out, csv) {
            Ok(()) => format!("Exported {} rows to {}", pf.files.len(), out.display()),
            Err(e) => format!("Export failed: {e}"),
        });
    }

    /// MFT-side reverse lookup: prefetch files that loaded MFT record `rec`.
    pub(super) fn prefetch_users_of(&self, rec: u64, seq: u16) -> Vec<(usize, usize, String)> {
        let mut out = Vec::new();
        let path_lc = self
            .file
            .as_ref()
            .and_then(|f| f.entries.get(rec as usize))
            .map(|e| e.path_lc.as_str())
            .unwrap_or("");
        for (i, e) in self.pf.entries.iter().enumerate() {
            let Ok(pf) = &e.result else { continue };
            if let Some(f) = pf.files.iter().find(|f| match f.file_reference.filter(|r| !r.is_empty()) {
                Some(r) => r.entry() == rec && r.sequence() == seq,
                None => !path_lc.is_empty() && pf_path_key(&f.filename) == path_lc,
            }) {
                out.push((i, f.index, pf.executable.clone()));
            }
        }
        out
    }

    /// Opens prefetch file `pf_idx` on the loaded-files tab at `file_idx`.
    pub(super) fn show_in_prefetch(&mut self, pf_idx: usize, file_idx: usize) {
        self.active = ViewKind::Prefetch;
        self.pf.select(Some(pf_idx));
        self.pf.tab = Tab::Files;
        self.pf.filter.clear();
        self.pf.selected_file = Some(file_idx);
        self.pf.scroll_to_file = true;
    }
}

pub(super) fn default_prefetch_dir() -> PathBuf {
    let dir = PathBuf::from(r"C:\Windows\Prefetch");
    if dir.is_dir() { dir } else { std::env::current_dir().unwrap_or_default() }
}

fn ref_cols(r: Option<FileRef>) -> (String, String) {
    match r {
        Some(r) if !r.is_empty() => (r.entry().to_string(), r.sequence().to_string()),
        _ => ("—".into(), "—".into()),
    }
}

/// A non-interactive label, so clicks fall through to the table row.
fn plain(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) {
    ui.add(egui::Label::new(text).selectable(false));
}

fn path_label(ui: &mut egui::Ui, text: RichText, path: &str) {
    let resp = ui
        .add(egui::Label::new(text).truncate().selectable(false))
        .on_hover_text(path);
    resp.context_menu(|ui| {
        if ui.button("Copy path").clicked() {
            ui.ctx().copy_text(path.to_string());
            ui.close();
        }
    });
}

fn section(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).strong().size(15.0))
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new(title).num_columns(2).spacing([24.0, 6.0]).striped(true).show(ui, add);
        });
    ui.add_space(6.0);
}

/// A small explanatory line spanning the value column of a key/value grid.
fn note(ui: &mut egui::Ui, text: &str) {
    ui.label("");
    ui.label(RichText::new(text).small().weak().italics());
    ui.end_row();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn path_keys() {
        assert_eq!(
            pf_path_key(r"\VOLUME{01d9516}\USERS\BOB\DOWNLOADS\RUBEUS.EXE:ZONE.IDENTIFIER"),
            r"\users\bob\downloads\rubeus.exe"
        );
        assert_eq!(pf_path_key(r"\VOLUME{01d9516}\WINDOWS\SYSTEM32\NTDLL.DLL"), r"\windows\system32\ntdll.dll");
    }

    /// Loaded files resolve against an $MFT by path when the prefetch file
    /// has no per-file references (Windows 10+).
    #[test]
    fn resolves_against_sample_mft() {
        let (Ok(mraw), Ok(praw)) = (
            std::fs::read("samples/$MFT"),
            std::fs::read("samples/RUBEUS.EXE-5873E24B.pf"),
        ) else {
            return;
        };
        let mft = MftFile::load(mraw, &AtomicUsize::new(0));
        let index = build_mft_path_index(&mft);
        let pf = prefetch::parse(&praw).unwrap();
        let key = |name: &str| {
            pf.files
                .iter()
                .find(|f| f.filename.ends_with(name))
                .map(|f| pf_path_key(&f.filename))
                .unwrap()
        };
        // System libraries exist at the same path on any Windows install...
        let ntdll = index.get(&key(r"\SYSTEM32\NTDLL.DLL")).copied();
        assert!(ntdll.is_some_and(|r| mft.entries[r as usize].in_use));
        // ...but the attacker's download does not exist on this machine.
        assert!(!index.contains_key(&key(r"\RUBEUS.EXE")));
    }
}
