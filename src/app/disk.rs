//! Disk images: attaching the image (or live drive) a `$MFT` came from, or
//! loading the `$MFT` straight from an image, and the background jobs that
//! read file content from it: extraction and hashing.

use std::sync::atomic::{AtomicBool, AtomicU64};

use super::*;
use crate::image;
use crate::intel::{Hasher, Hashes, Service};
use crate::ntfs::{self, Volume};

/// What opening an image produced.
pub(super) struct ImageLoad {
    pub volume: Arc<Volume>,
    pub label: String,
    /// The image's own `$MFT`, when the loaded one isn't from this image.
    pub mft: Option<MftFile>,
    /// Other NTFS volumes in the image, not shown.
    pub others: Vec<String>,
}

enum Done {
    Extracted(Result<(PathBuf, extract::Extracted), String>),
    Hashed {
        record: usize,
        stream: String,
        /// A lookup to run once the hashes are known.
        then: Option<Service>,
        result: Result<(Hashes, Option<Vec<u8>>), String>,
    },
}

/// Something that was waiting for the disk image; it runs once the image is open.
#[derive(Clone, Copy)]
pub(super) enum NeedImage {
    Extract,
    Hash { record: usize, then: Option<Service> },
}

pub(super) struct Job {
    label: String,
    progress: Arc<AtomicU64>,
    total: u64,
    cancel: Arc<AtomicBool>,
    rx: mpsc::Receiver<Done>,
}

/// Opens an image on a background thread. `current` is the loaded `$MFT`'s
/// record size and first record, to find the volume it belongs to.
fn load_image(path: &Path, current: Option<(usize, Vec<u8>)>, progress: &AtomicUsize, total: &AtomicUsize) -> Result<Loaded, String> {
    let src: Arc<dyn image::Source> = Arc::from(image::open(path)?);
    let label = format!("{} ({})", path.file_name().unwrap_or(path.as_os_str()).to_string_lossy(), src.describe());
    let mut vols = ntfs::find_volumes(src);
    if vols.is_empty() {
        return Err("no NTFS volume found in this image".into());
    }
    let matching = current.and_then(|(rs, rec0)| {
        let rec0 = Record::parse(&rec0);
        vols.iter().position(|v| v.matches_record0(rs, &rec0))
    });
    let (pick, mft) = match matching {
        Some(i) => (i, None),
        None => {
            let i = (0..vols.len()).max_by_key(|&i| vols[i].size).expect("not empty");
            let raw = vols[i].read_mft(&AtomicU64::new(0))?;
            total.store(MftFile::record_count(raw.len(), vols[i].record_size), Ordering::Relaxed);
            (i, Some(MftFile::load(raw, progress)))
        }
    };
    let volume = Arc::new(vols.swap_remove(pick));
    let others = vols.iter().map(|v| v.describe()).collect();
    Ok(Loaded::Image(ImageLoad { volume, label, mft, others }))
}

/// Whether `path` is a disk or volume image (or a live drive), from its first
/// sector: an E01, an NTFS boot sector, or a partition table in a file named
/// like an image.
pub(super) fn is_disk_image(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\.\") || s.starts_with("/dev/") {
        return true;
    }
    let mut head = [0u8; 1024];
    let n = std::fs::File::open(path).and_then(|mut f| {
        use std::io::Read as _;
        f.read(&mut head)
    });
    let Ok(n) = n else { return false };
    let head = &head[..n];
    if head.starts_with(b"EVF\x09\x0d\x0a\xff\x00") || head.get(3..11) == Some(b"NTFS    ") {
        return true;
    }
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let image_name = matches!(ext.as_str(), "dd" | "raw" | "img" | "001" | "bin" | "e01");
    image_name && head.get(510..512) == Some(&[0x55, 0xAA])
}

/// Drive letters that exist, for "Open live drive".
#[cfg(windows)]
fn drive_letters() -> Vec<char> {
    ('C'..='Z').filter(|c| Path::new(&format!("{c}:\\")).exists()).collect()
}

impl MftApp {
    pub(super) fn image_menu(&mut self, ui: &mut egui::Ui) {
        let label = if self.volume.is_some() { "🖴 Image ✔" } else { "🖴 Image" };
        ui.menu_button(label, |ui| {
            match &self.volume {
                Some(v) => {
                    ui.label(RichText::new(&self.volume_label).strong());
                    ui.label(RichText::new(v.describe()).weak().small());
                    ui.label(RichText::new(format!("Image size: {} bytes", v.src.len())).weak().small());
                    if let Some(md5) = v.src.stored_md5() {
                        let hex: String = md5.iter().map(|b| format!("{b:02x}")).collect();
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Acquisition MD5: {hex}")).weak().small().monospace());
                            if ui.small_button("📋").on_hover_text("Copy").clicked() {
                                ui.ctx().copy_text(hex.clone());
                            }
                        });
                    }
                }
                None => {
                    ui.label(RichText::new(
                        "Open the disk image a $MFT came from to extract and hash files whose content \
                         isn't stored in the $MFT. With no $MFT loaded, the image's own is loaded.",
                    ).weak().small());
                }
            }
            ui.separator();
            if ui.button("Open disk image…").on_hover_text("E01 (EnCase), raw / dd, or split .001 images").clicked() {
                ui.close();
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Disk images", &["E01", "e01", "raw", "dd", "img", "001", "bin"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    self.begin_open();
                    self.open_image(p, ui.ctx());
                }
            }
            #[cfg(windows)]
            ui.menu_button("Open live drive", |ui| {
                ui.label(RichText::new("Reads the drive directly. Needs Sediment to run as administrator.").weak().small());
                for c in drive_letters() {
                    if ui.button(format!("{c}:")).clicked() {
                        ui.close();
                        self.begin_open();
                        self.open_image(PathBuf::from(format!(r"\\.\{c}:")), ui.ctx());
                    }
                }
            });
            if self.volume.is_some() && ui.button("Close image").clicked() {
                ui.close();
                self.volume = None;
                self.status_msg = Some("Image closed.".into());
            }
        });
    }

    pub(super) fn open_image(&mut self, path: PathBuf, ctx: &egui::Context) {
        let current = self.file.as_ref().map(|f| (f.record_size, f.record_bytes(0).to_vec()));
        let progress = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let (p2, t2, path2, ctx2) = (progress.clone(), total.clone(), path.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = guard_parse(&path2, || load_image(&path2, current, &p2, &t2));
            let _ = tx.send(result);
            ctx2.request_repaint();
        });
        self.loading.push(Loading { path, progress, total, rx });
    }

    pub(super) fn apply_image(&mut self, path: PathBuf, img: ImageLoad, ctx: &egui::Context) {
        let ImageLoad { volume, label, mft, others } = img;
        let loaded_own = mft.is_some();
        if let Some(file) = mft {
            self.install_mft(PathBuf::from(format!("{} › $MFT", path.display())), file);
        }
        self.report_loaded(&path, format!("disk image: {}", volume.describe()));
        for o in others {
            self.report.push(open::ReportItem {
                path: path.clone(),
                outcome: open::Outcome::NotLoaded(format!("also contains an {o}; Sediment shows one volume at a time")),
            });
        }
        self.status_msg = Some(if loaded_own {
            format!("Loaded the $MFT from {label}. Files can be extracted and hashed from it.")
        } else {
            format!("Attached {label} to the loaded $MFT. Files can be extracted and hashed from it.")
        });
        self.volume = Some(volume);
        self.volume_label = label.clone();
        for s in &mut self.selected_streams {
            s.hashing = false;
        }
        match self.after_image.take() {
            // The record numbers belong to the $MFT that was replaced.
            Some(_) if loaded_own => {
                self.status_msg = Some(format!(
                    "{label} isn't the image the loaded $MFT came from, so Sediment loaded the image's own $MFT; pick the file again."
                ));
            }
            Some(NeedImage::Extract) => self.extract_selected(ctx),
            Some(NeedImage::Hash { record, then }) => self.hash_file(record, then, ctx),
            None => {}
        }
    }

    /// Detaches the image when a `$MFT` from elsewhere is loaded.
    pub(super) fn check_volume_matches(&mut self) {
        if let (Some(v), Some(f)) = (&self.volume, &self.file)
            && !v.matches(f)
        {
            self.volume = None;
            self.status_msg = Some("Closed the disk image: the newly loaded $MFT isn't from it.".into());
        }
    }

    /// The Extract button: content in the `$MFT` needs nothing else; content
    /// in clusters needs the image.
    pub(super) fn extract_selected(&mut self, ctx: &egui::Context) {
        let Some(idx) = self.selected else { return };
        let recs = self.selected_file.clone();
        let streams = extract::streams(&recs);
        let needs_image = streams.iter().any(|s| s.data.is_none() && ntfs::content_size(&recs, s.name).unwrap_or(0) > 0);
        if needs_image && self.volume.is_none() {
            self.need_image = Some(NeedImage::Extract);
            return;
        }
        self.start_extract(idx, recs, ctx);
    }

    fn start_extract(&mut self, idx: usize, recs: Vec<Record>, ctx: &egui::Context) {
        let Some(dest) = rfd::FileDialog::new()
            .add_filter("ZIP", &["zip"])
            .set_file_name(extract::zip_file_name(&recs, idx))
            .save_file()
        else {
            return;
        };
        let vol = self.volume.clone();
        let total = extract::extract_size(&recs, vol.as_deref());
        let progress = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (p2, c2, ctx2) = (progress.clone(), cancel.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = guard_parse(&dest, || extract::extract_to(&dest, &recs, idx, vol.as_deref(), &p2, &c2))
                .map(|x| (dest, x));
            let _ = tx.send(Done::Extracted(result));
            ctx2.request_repaint();
        });
        self.jobs.push(Job { label: format!("Extracting record #{idx}"), progress, total, cancel, rx });
    }

    pub(super) fn hash_stream_from_image(&mut self, i: usize, ctx: &egui::Context) {
        let Some(record) = self.selected else { return };
        let Some(s) = self.selected_streams.get_mut(i) else { return };
        s.hashing = true;
        let (stream, size) = (s.name.clone(), s.size);
        let recs = self.selected_file.clone();
        self.spawn_hash(record, recs, stream, size, None, ctx);
    }

    /// Hashes a file's main stream: straight from the record when it is
    /// stored there, otherwise from its clusters in the disk image (asking
    /// for the image if none is open). `then` looks the result up.
    pub(super) fn hash_file(&mut self, record: usize, then: Option<Service>, ctx: &egui::Context) {
        let Some(file) = &self.file else { return };
        let Some(e) = file.entries.get(record) else { return };
        let recs = file.file_records(record);
        let (name, path) = (e.name.clone(), if e.path.is_empty() { e.name.clone() } else { e.path.clone() });
        let Some(size) = ntfs::content_size(&recs, "") else {
            self.status_msg = Some(format!("{name} has no file content to hash."));
            return;
        };
        let wof = matches!(ntfs::kind(&recs, ""), Some(ntfs::Kind::Wof));
        let in_record = if wof {
            None
        } else {
            extract::streams(&recs).into_iter().find(|s| s.name.is_empty()).and_then(|s| s.data).map(<[u8]>::to_vec)
        };
        let mut win = online::HashWin { record, name, path, size, hashes: None, data: None, hashing: false };
        match in_record {
            Some(d) => {
                let h = Hashes::of(&d);
                let sha256 = h.sha256.clone();
                win.hashes = Some(h);
                win.data = Some(d);
                self.online.hash_win = Some(win);
                if let Some(s) = then {
                    self.request_lookup(s, sha256, ctx);
                }
            }
            None if self.volume.is_some() => {
                win.hashing = true;
                self.online.hash_win = Some(win);
                self.spawn_hash(record, recs, String::new(), size, then, ctx);
            }
            None => self.need_image = Some(NeedImage::Hash { record, then }),
        }
    }

    fn spawn_hash(&mut self, record: usize, recs: Vec<Record>, stream: String, size: u64, then: Option<Service>, ctx: &egui::Context) {
        let Some(vol) = self.volume.clone() else { return };
        let progress = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (p2, c2, ctx2, name2) = (progress.clone(), cancel.clone(), ctx.clone(), stream);
        std::thread::spawn(move || {
            let result = guard_parse(Path::new(&name2), || {
                let mut h = Hasher::default();
                let mut keep = (size <= online::SUBMIT_MAX).then(Vec::new);
                ntfs::read_content(&vol, &recs, &name2, &mut |b| {
                    if c2.load(Ordering::Relaxed) {
                        return Err("cancelled".into());
                    }
                    h.update(b);
                    if let Some(k) = &mut keep {
                        k.extend_from_slice(b);
                    }
                    Ok(())
                }, &p2)?;
                Ok((h.finish(), keep))
            });
            let _ = tx.send(Done::Hashed { record, stream: name2, then, result });
            ctx2.request_repaint();
        });
        self.jobs.push(Job { label: format!("Hashing record #{record}"), progress, total: size, cancel, rx });
    }

    pub(super) fn poll_jobs(&mut self, ctx: &egui::Context) {
        let mut done = Vec::new();
        self.jobs.retain(|j| match j.rx.try_recv() {
            Ok(d) => {
                done.push(d);
                false
            }
            Err(mpsc::TryRecvError::Empty) => true,
            Err(mpsc::TryRecvError::Disconnected) => {
                done.push(Done::Extracted(Err(format!("{}: the job stopped unexpectedly", j.label))));
                false
            }
        });
        for d in done {
            match d {
                Done::Extracted(Ok((dest, x))) => {
                    let mut msg = format!(
                        "Extracted {} stream{} ({} bytes) to {} (password: {})",
                        x.files,
                        if x.files == 1 { "" } else { "s" },
                        x.bytes,
                        dest.display(),
                        extract::PASSWORD
                    );
                    if !x.skipped.is_empty() {
                        msg.push_str(&format!("; left out: {}", x.skipped.join("; ")));
                    }
                    self.status_msg = Some(msg);
                    self.error = None;
                }
                Done::Extracted(Err(e)) => self.error = Some(format!("Extract failed: {e}")),
                Done::Hashed { record, stream, then, result } => {
                    let current = self.selected == Some(record);
                    if let Some(s) = self.selected_streams.iter_mut().find(|s| current && s.name == stream) {
                        s.hashing = false;
                        if let Ok((h, data)) = &result {
                            s.hashes = Some(h.clone());
                            s.data = data.clone();
                        }
                    }
                    if let Some(w) = self.online.hash_win.as_mut().filter(|w| w.record == record && stream.is_empty()) {
                        w.hashing = false;
                        if let Ok((h, data)) = &result {
                            w.hashes = Some(h.clone());
                            w.data = data.clone();
                        }
                    }
                    match result {
                        Ok((h, _)) => {
                            if let Some(s) = then {
                                self.request_lookup(s, h.sha256, ctx);
                            }
                        }
                        Err(e) => self.error = Some(format!("Hashing failed: {e}")),
                    }
                }
            }
        }
    }

    pub(super) fn jobs_status(&self, ui: &mut egui::Ui) {
        for j in &self.jobs {
            let done = j.progress.load(Ordering::Relaxed);
            let frac = if j.total == 0 { 0.0 } else { done as f32 / j.total as f32 };
            ui.spinner();
            ui.label(&j.label);
            ui.add(egui::ProgressBar::new(frac.min(1.0)).show_percentage().desired_width(160.0));
            if ui.small_button("✖").on_hover_text("Cancel").clicked() {
                j.cancel.store(true, Ordering::Relaxed);
            }
            ui.separator();
        }
    }

    /// Asked when a file's content needs the disk image and none is open.
    pub(super) fn need_image_window(&mut self, ctx: &egui::Context) {
        let Some(need) = self.need_image else { return };
        let recs = match need {
            NeedImage::Extract => self.selected_file.clone(),
            NeedImage::Hash { record, .. } => self.file.as_ref().map(|f| f.file_records(record)).unwrap_or_default(),
        };
        let partial = matches!(need, NeedImage::Extract)
            && extract::streams(&recs).iter().any(|s| s.data.is_some_and(|d| !d.is_empty()));
        let mut choice = None;
        egui::Modal::new(egui::Id::new("need_image")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.heading("This file needs its disk image");
            let what = match need {
                NeedImage::Extract => "extract it",
                NeedImage::Hash { then: Some(_), .. } => "hash it and check it",
                NeedImage::Hash { then: None, .. } => "hash it",
            };
            ui.label(format!(
                "Its content isn't stored in the $MFT: NTFS keeps anything larger than about 700 bytes in \
                 clusters on the volume, and the $MFT only records where. Open the disk image (E01, raw/dd) \
                 or live drive this $MFT came from, and Sediment reads the content from there to {what}."
            ));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Open disk image…").clicked() {
                    choice = Some(1);
                }
                if partial && ui.button("Extract only what's in the $MFT").clicked() {
                    choice = Some(2);
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    choice = Some(0);
                }
            });
        });
        match choice {
            Some(1) => {
                self.need_image = None;
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Disk images", &["E01", "e01", "raw", "dd", "img", "001", "bin"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    self.after_image = Some(need);
                    self.begin_open();
                    self.open_image(p, ctx);
                }
            }
            Some(2) => {
                self.need_image = None;
                if let Some(idx) = self.selected {
                    self.start_extract(idx, recs, ctx);
                }
            }
            Some(_) => self.need_image = None,
            None => {}
        }
    }
}
