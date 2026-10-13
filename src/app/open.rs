//! Opening whole folders (a KAPE or Velociraptor collection, a Prefetch
//! folder) and the load report.
//!
//! A folder is walked on a background thread. Every file is identified by its
//! first bytes, so names don't matter, and only the files Sediment reads are
//! loaded. Whatever can't be read or parsed is listed in the load report
//! instead of stopping the rest.

use std::io::Read as _;

use super::*;
use crate::usn::UsnJournal;

/// Only this much of each file is read to identify it.
const SNIFF_BYTES: u64 = 1 << 20;
const MAX_DEPTH: usize = 24;
const MAX_FILES: usize = 250_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Mft,
    Journal,
    Max,
    Prefetch,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Mft => "$MFT",
            Kind::Journal => "$J",
            Kind::Max => "$Max",
            Kind::Prefetch => "prefetch",
        }
    }
}

/// What a folder scan decided to load.
#[derive(Default, Debug)]
pub(super) struct FolderPlan {
    pub dir: PathBuf,
    /// `$MFT`, `$J` and `$Max` files, loaded one by one.
    pub open: Vec<PathBuf>,
    pub prefetch: Vec<PathBuf>,
    /// Artifacts found but not loaded, and files that couldn't be read.
    pub not_loaded: Vec<(PathBuf, String)>,
    /// Files that aren't anything Sediment reads.
    pub other_files: usize,
    pub truncated: bool,
}

pub(super) enum Outcome {
    Loaded(String),
    Failed(String),
    NotLoaded(String),
}

pub(super) struct ReportItem {
    pub path: PathBuf,
    pub outcome: Outcome,
}

/// Identifies a file from its name, length and first bytes.
pub(super) fn classify(path: &Path, len: u64, head: &[u8]) -> Option<Kind> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if name.ends_with(".pf") || is_prefetch(head) {
        return Some(Kind::Prefetch);
    }
    if head.starts_with(b"FILE") || head.starts_with(b"BAAD") {
        // At least the 16 system records: rules out $MFTMirr's 4.
        let rs = MftFile::detect_record_size(head) as u64;
        return (len >= 16 * rs).then_some(Kind::Mft);
    }
    // $Max is any 32 bytes that parse, so it also needs a telling name.
    if len == 32 && name.contains("max") && UsnMax::parse(head).is_some() {
        return Some(Kind::Max);
    }
    let journal_name = name == "$j" || name.ends_with("$j") || (name.contains("usnjrnl") && !name.contains("max"));
    if len > 0 && (journal_name || UsnJournal::sniff_records(head, 3)) {
        return Some(Kind::Journal);
    }
    None
}

/// `path` relative to `root` when it is inside it, for display.
fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}

/// Number of leading path components two paths share.
fn shared_prefix(a: &Path, b: &Path) -> usize {
    a.components().zip(b.components()).take_while(|(x, y)| x == y).count()
}

/// Picks what to load from the identified files. Sediment shows one `$MFT`
/// and one journal at a time: the largest `$MFT` (usually the system
/// volume), and the `$J` and `$Max` that sit closest to it in the folder
/// tree, i.e. from the same volume of a multi-volume collection.
pub(super) fn plan(dir: PathBuf, found: Vec<(PathBuf, u64, Kind)>) -> FolderPlan {
    let mut p = FolderPlan { dir, ..Default::default() };
    let of = |k: Kind| -> Vec<(PathBuf, u64)> {
        let mut v: Vec<(PathBuf, u64)> = found.iter().filter(|f| f.2 == k).map(|f| (f.0.clone(), f.1)).collect();
        v.sort();
        v
    };
    let mfts = of(Kind::Mft);
    let anchor = mfts.iter().max_by_key(|(_, len)| *len).map(|(path, _)| path.clone());
    let pick = |cands: &[(PathBuf, u64)], near: Option<&Path>| -> Option<PathBuf> {
        cands
            .iter()
            .max_by_key(|(path, len)| (near.map_or(0, |a| shared_prefix(path, a)), *len))
            .map(|(path, _)| path.clone())
    };
    let journal = pick(&of(Kind::Journal), anchor.as_deref());
    let max = pick(&of(Kind::Max), journal.as_deref().or(anchor.as_deref()));
    for (kind, chosen) in [(Kind::Mft, &anchor), (Kind::Journal, &journal), (Kind::Max, &max)] {
        for (path, _) in of(kind) {
            if Some(&path) == chosen.as_ref() {
                p.open.push(path);
            } else {
                let why = format!(
                    "another {} was loaded ({}); Sediment shows one at a time, so open this one on its own to see it",
                    kind.label(),
                    chosen.as_ref().map(|c| relative(c, &p.dir)).unwrap_or_default()
                );
                p.not_loaded.push((path, why));
            }
        }
    }
    p.prefetch = of(Kind::Prefetch).into_iter().map(|(path, _)| path).collect();
    p
}

/// Walks `dir` (without following symlinks) and plans what to load.
pub(super) fn scan(dir: &Path, progress: &AtomicUsize) -> FolderPlan {
    let mut found = Vec::new();
    let mut unreadable = Vec::new();
    let (mut other, mut seen, mut truncated) = (0usize, 0usize, false);
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    'walk: while let Some((d, depth)) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) => {
                unreadable.push((d, format!("couldn't list this folder: {e}")));
                continue;
            }
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let path = e.path();
            // symlink_metadata: never follow links, so loops are impossible.
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.is_dir() {
                if depth + 1 < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            seen += 1;
            progress.store(seen, Ordering::Relaxed);
            if seen > MAX_FILES {
                truncated = true;
                break 'walk;
            }
            let mut head = Vec::new();
            match std::fs::File::open(&path).and_then(|f| f.take(SNIFF_BYTES).read_to_end(&mut head)) {
                Ok(_) => match classify(&path, meta.len(), &head) {
                    Some(k) => found.push((path, meta.len(), k)),
                    None => other += 1,
                },
                Err(err) => unreadable.push((path, format!("couldn't read: {err}"))),
            }
        }
    }
    let mut p = plan(dir.to_path_buf(), found);
    p.not_loaded.extend(unreadable);
    p.other_files = other;
    p.truncated = truncated;
    p
}

impl MftApp {
    /// Starts a fresh load report; call once per user open action.
    pub(super) fn begin_open(&mut self) {
        self.report.clear();
        self.report_root = None;
        self.error = None;
    }

    pub(super) fn open_folder_dialog(&mut self, ctx: &egui::Context) {
        if let Some(dir) = rfd::FileDialog::new().pick_folder() {
            self.begin_open();
            self.open(dir, ctx);
        }
    }

    pub(super) fn open_folder(&mut self, dir: PathBuf, ctx: &egui::Context) {
        let progress = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let (p2, dir2, ctx2) = (progress.clone(), dir.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = guard_parse(&dir2, || Ok(Loaded::Folder(scan(&dir2, &p2))));
            let _ = tx.send(result);
            ctx2.request_repaint();
        });
        self.loading.push(Loading { path: dir, progress, total: Arc::new(AtomicUsize::new(0)), rx });
    }

    /// Starts loading what a folder scan found.
    pub(super) fn apply_plan(&mut self, p: FolderPlan, ctx: &egui::Context) {
        let n = p.open.len() + p.prefetch.len();
        for path in p.open {
            self.open(path, ctx);
        }
        if !p.prefetch.is_empty() {
            self.open_prefetch_batch(p.prefetch, ctx);
        }
        self.report_root = Some(p.dir.clone());
        for (path, why) in p.not_loaded {
            self.report.push(ReportItem { path, outcome: Outcome::NotLoaded(why) });
        }
        let mut msg = if n == 0 {
            format!("Nothing to open in {}: no $MFT, $J, $Max or prefetch files", p.dir.display())
        } else {
            format!("Opening {n} file{} from {}", if n == 1 { "" } else { "s" }, p.dir.display())
        };
        if p.other_files > 0 {
            msg.push_str(&format!(" ({} other files ignored)", p.other_files));
        }
        if p.truncated {
            msg.push_str(&format!("; stopped after {MAX_FILES} files"));
        }
        self.status_msg = Some(msg);
        self.refresh_error_summary();
    }

    pub(super) fn report_loaded(&mut self, path: &Path, what: String) {
        self.report.push(ReportItem { path: path.to_path_buf(), outcome: Outcome::Loaded(what) });
    }

    pub(super) fn report_failed(&mut self, path: &Path, err: String) {
        // Loader errors already start with the path; the report shows it separately.
        let prefix = format!("{}: ", path.display());
        let err = err.strip_prefix(&prefix).map(str::to_string).unwrap_or(err);
        self.report.push(ReportItem { path: path.to_path_buf(), outcome: Outcome::Failed(err) });
        self.refresh_error_summary();
    }

    /// The status-bar error: the failure itself when there is one, a count otherwise.
    fn refresh_error_summary(&mut self) {
        let failed: Vec<&ReportItem> = self.report.iter().filter(|r| matches!(r.outcome, Outcome::Failed(_))).collect();
        self.error = match failed.as_slice() {
            [] => None,
            [one] => Some(format!(
                "{}: {}",
                one.path.file_name().unwrap_or_default().to_string_lossy(),
                match &one.outcome {
                    Outcome::Failed(e) => e.as_str(),
                    _ => "",
                }
            )),
            many => Some(format!("{} files couldn't be opened; the others loaded fine", many.len())),
        };
    }

    /// "Details" link for the status bar when anything failed or was left out.
    pub(super) fn report_link(&mut self, ui: &mut egui::Ui) {
        let problems = self.report.iter().filter(|r| !matches!(r.outcome, Outcome::Loaded(_))).count();
        if problems > 0 && ui.small_button("Details…").on_hover_text("What was opened, and what wasn't and why").clicked() {
            self.report_open = true;
        }
    }

    pub(super) fn report_window(&mut self, ctx: &egui::Context) {
        let mut open = self.report_open;
        egui::Window::new("Load report")
            .open(&mut open)
            .default_size([720.0, 420.0])
            .show(ctx, |ui| {
                let count = |f: fn(&Outcome) -> bool| self.report.iter().filter(|r| f(&r.outcome)).count();
                let (ok, failed, skipped) = (
                    count(|o| matches!(o, Outcome::Loaded(_))),
                    count(|o| matches!(o, Outcome::Failed(_))),
                    count(|o| matches!(o, Outcome::NotLoaded(_))),
                );
                if let Some(root) = &self.report_root {
                    ui.label(RichText::new(format!("In {}", root.display())).weak());
                }
                ui.label(format!("{ok} loaded · {failed} couldn't be parsed · {skipped} not loaded"));
                ui.separator();
                let mut rows: Vec<&ReportItem> = self.report.iter().collect();
                // Problems first.
                rows.sort_by_key(|r| match r.outcome {
                    Outcome::Failed(_) => 0,
                    Outcome::NotLoaded(_) => 1,
                    Outcome::Loaded(_) => 2,
                });
                let row_h = ui.text_style_height(&egui::TextStyle::Body) * 2.4;
                egui::ScrollArea::vertical().auto_shrink(false).show_rows(ui, row_h, rows.len(), |ui, range| {
                    for r in &rows[range] {
                        let (icon, color, text) = match &r.outcome {
                            Outcome::Loaded(t) => ("✔", ui.visuals().text_color(), t),
                            Outcome::Failed(t) => ("✖", ui.visuals().error_fg_color, t),
                            Outcome::NotLoaded(t) => ("–", ui.visuals().warn_fg_color, t),
                        };
                        let shown = match &self.report_root {
                            Some(root) => relative(&r.path, root),
                            None => r.path.display().to_string(),
                        };
                        ui.horizontal(|ui| {
                            ui.colored_label(color, icon);
                            ui.label(RichText::new(shown).monospace()).on_hover_text(r.path.display().to_string());
                        });
                        ui.indent(("why", r.path.as_os_str()), |ui| ui.colored_label(color, text));
                    }
                });
            });
        self.report_open = open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn identifies_by_content() {
        let mft = {
            let mut r = vec![0u8; 1024];
            r[..4].copy_from_slice(b"FILE");
            r[28..32].copy_from_slice(&1024u32.to_le_bytes());
            r
        };
        assert_eq!(classify(&p("whatever.bin"), 1024 * 300, &mft), Some(Kind::Mft));
        assert_eq!(classify(&p("$MFTMirr"), 4096, &mft), None, "too small to be an $MFT");
        let mut scca = vec![0u8; 64];
        scca[4..8].copy_from_slice(b"SCCA");
        assert_eq!(classify(&p("x"), 64, &scca), Some(Kind::Prefetch));
        assert_eq!(classify(&p("BROKEN.EXE-1234.pf"), 3, b"zzz"), Some(Kind::Prefetch), ".pf is loaded and its error reported");
        let mut max = [0u8; 32];
        max[0] = 1;
        assert_eq!(classify(&p("$UsnJrnl%3A$Max"), 32, &max), Some(Kind::Max));
        assert_eq!(classify(&p("notes.txt"), 32, &max), None, "a random 32-byte file is not $Max");
        assert_eq!(classify(&p("$UsnJrnl%3A$J"), 10, &[0; 10]), Some(Kind::Journal));
        assert_eq!(classify(&p("$J"), 10, &[0; 10]), Some(Kind::Journal));
        assert_eq!(classify(&p("random.dat"), 4096, &[0x41; 4096]), None);
    }

    #[test]
    fn plans_one_volume() {
        let found = vec![
            (p("/k/C/$MFT"), 900, Kind::Mft),
            (p("/k/D/$MFT"), 100, Kind::Mft),
            (p("/k/D/$Extend/$UsnJrnl%3A$J"), 5000, Kind::Journal),
            (p("/k/C/$Extend/$UsnJrnl%3A$J"), 10, Kind::Journal),
            (p("/k/C/$Extend/$UsnJrnl%3A$Max"), 32, Kind::Max),
            (p("/k/D/$Extend/$UsnJrnl%3A$Max"), 32, Kind::Max),
            (p("/k/C/Windows/prefetch/A.pf"), 9, Kind::Prefetch),
        ];
        let plan = plan(p("/k"), found);
        assert_eq!(
            plan.open,
            [p("/k/C/$MFT"), p("/k/C/$Extend/$UsnJrnl%3A$J"), p("/k/C/$Extend/$UsnJrnl%3A$Max")],
            "the journal from the same volume as the $MFT, not the bigger one"
        );
        assert_eq!(plan.prefetch, [p("/k/C/Windows/prefetch/A.pf")]);
        assert_eq!(plan.not_loaded.len(), 3);
        assert!(plan.not_loaded.iter().all(|(_, why)| why.contains("one at a time")));
    }

    #[test]
    fn scans_nested_folders_and_survives_junk() {
        let dir = std::env::temp_dir().join(format!("sediment-scan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pf_dir = dir.join("C").join("Windows").join("prefetch");
        std::fs::create_dir_all(&pf_dir).unwrap();
        std::fs::create_dir_all(dir.join("C").join("$Extend")).unwrap();
        let fixture = std::fs::read("tests/fixtures/EVIL.EXE-DEADBEEF.pf").unwrap();
        std::fs::write(pf_dir.join("EVIL.EXE-DEADBEEF.pf"), &fixture).unwrap();
        std::fs::write(pf_dir.join("TRUNCATED.EXE-00000000.pf"), &fixture[..40]).unwrap();
        std::fs::write(dir.join("C").join("$Extend").join("$UsnJrnl%3A$J"), [0u8; 64]).unwrap();
        std::fs::write(dir.join("C").join("SOFTWARE"), b"regf not ours").unwrap();
        std::fs::write(dir.join("readme.txt"), b"hello").unwrap();

        let plan = scan(&dir, &AtomicUsize::new(0));
        assert_eq!(plan.prefetch.len(), 2, "both .pf files are handed to the loader");
        assert_eq!(plan.open, [dir.join("C").join("$Extend").join("$UsnJrnl%3A$J")]);
        assert_eq!(plan.other_files, 2);

        // The truncated file fails on its own; the good one still parses.
        let entries: Vec<_> = plan.prefetch.iter().map(|p| pf::PfEntry::load(p.clone())).collect();
        assert_eq!(entries.iter().filter(|e| e.result.is_ok()).count(), 1);
        assert_eq!(entries.iter().filter(|e| e.result.is_err()).count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
