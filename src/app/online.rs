//! Online features: the daily update check and "Check for updates", the
//! settings window, and file hashes with VirusTotal / Triage pivots. Network
//! work runs on background threads and reports back over a channel.

use std::collections::HashMap;
use std::sync::mpsc;

use super::*;
use crate::intel::{self, Hashes, Service, Verdict};
use crate::settings::{self, Settings, TRIAGE_PUBLIC};
use crate::update::{self, Release};

const DAY: u64 = 24 * 60 * 60;
/// After a failed automatic check (e.g. offline), wait this long to retry.
const RETRY: u64 = 60 * 60;

/// One `$DATA` stream of the selected file.
pub(super) struct StreamInfo {
    /// Empty for the main stream, otherwise the ADS name.
    pub name: String,
    pub size: u64,
    pub hashes: Option<Hashes>,
    /// The content, when it is in the `$MFT` or small enough to submit.
    pub data: Option<Vec<u8>>,
    /// Being hashed from the disk image.
    pub hashing: bool,
}

/// The Hashes window: a file's main stream, hashed from the record or the image.
pub(super) struct HashWin {
    pub record: usize,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub hashes: Option<Hashes>,
    /// The content, when small enough to submit.
    pub data: Option<Vec<u8>>,
    pub hashing: bool,
}

/// Content up to this size is kept in memory after hashing, for submitting.
pub(super) const SUBMIT_MAX: u64 = 32 << 20;

impl StreamInfo {
    pub fn of_file(recs: &[Record]) -> Vec<StreamInfo> {
        recs.iter()
            .flat_map(|r| r.attributes.iter().filter(|a| a.type_code == mft::ATTR_DATA).map(move |a| (r, a)))
            .filter(|(_, a)| !matches!(a.body, AttrBody::NonResident { start_vcn, .. } if start_vcn != 0))
            .fold(Vec::new(), |mut out: Vec<StreamInfo>, (r, a)| {
                if !out.iter().any(|s| s.name == a.name) {
                    out.push(StreamInfo {
                        name: a.name.clone(),
                        size: a.data_size(),
                        hashes: a.resident_content(&r.data).map(Hashes::of),
                        data: a.resident_content(&r.data).map(<[u8]>::to_vec),
                        hashing: false,
                    });
                }
                out
            })
    }
}

enum Msg {
    UpdateChecked { manual: bool, result: Result<Release, String> },
    UpdateInstalled(Result<PathBuf, String>),
    Intel { service: Service, sha256: String, submit: bool, result: Result<Verdict, String> },
}

#[derive(Default)]
enum UpdateState {
    #[default]
    Idle,
    Checking { manual: bool },
    Available(Release),
    Installing(Release),
}

enum Job {
    Running,
    Done(Verdict),
    Failed(String),
}

struct PendingUpload {
    service: Service,
    file_name: String,
    data: Vec<u8>,
    sha256: String,
}

pub(super) struct Online {
    pub settings: Settings,
    pub settings_open: bool,
    tx: mpsc::Sender<Msg>,
    rx: mpsc::Receiver<Msg>,
    update: UpdateState,
    banner_closed: bool,
    last_attempt: u64,
    /// Lookup and submission results by (service, sha256, is_submission).
    jobs: HashMap<(Service, String, bool), Job>,
    confirm: Option<PendingUpload>,
    show_keys: bool,
    welcome_open: bool,
    pub hash_win: Option<HashWin>,
    /// A lookup waiting for its API key: (service, SHA-256).
    key_prompt: Option<(Service, String)>,
    private_triage: bool,
}

impl Default for Online {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut settings = Settings::load();
        // Keys typed into the first-run prompt are meant to stick (the box stays visible).
        if !settings.welcomed {
            settings.remember_keys = true;
        }
        Online {
            private_triage: settings.triage_api != TRIAGE_PUBLIC,
            welcome_open: !settings.welcomed,
            hash_win: None,
            key_prompt: None,
            settings,
            settings_open: false,
            tx,
            rx,
            update: UpdateState::Idle,
            banner_closed: false,
            last_attempt: 0,
            jobs: HashMap::new(),
            confirm: None,
            show_keys: false,
        }
    }
}

impl Online {
    fn spawn(&self, ctx: &egui::Context, work: impl FnOnce() -> Msg + Send + 'static) {
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(work());
            ctx.request_repaint();
        });
    }

    pub fn check_for_updates(&mut self, ctx: &egui::Context, manual: bool) {
        if matches!(self.update, UpdateState::Checking { .. } | UpdateState::Installing(_)) {
            return;
        }
        self.update = UpdateState::Checking { manual };
        self.last_attempt = settings::now();
        self.spawn(ctx, move || Msg::UpdateChecked { manual, result: update::latest() });
    }

    fn save(&mut self) -> Option<String> {
        self.settings.save().err().map(|e| format!("Couldn't save settings: {e}"))
    }

    fn key(&self, service: Service) -> &str {
        match service {
            Service::VirusTotal => &self.settings.virustotal_key,
            Service::Triage => &self.settings.triage_key,
        }
    }
}

impl MftApp {
    /// Call once per frame: applies finished network work and runs the
    /// daily update check.
    pub(super) fn online_tick(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.online.rx.try_recv() {
            match msg {
                Msg::UpdateChecked { manual, result } => {
                    self.online.update = UpdateState::Idle;
                    match result {
                        Ok(r) => {
                            self.online.settings.last_update_check = settings::now();
                            if let Some(e) = self.online.save() {
                                self.status_msg = Some(e);
                            }
                            if r.is_newer() && (manual || r.version != self.online.settings.skipped_version) {
                                self.online.banner_closed = false;
                                self.online.update = UpdateState::Available(r);
                            } else if manual {
                                self.status_msg = Some(format!("Sediment {} is the latest version.", update::CURRENT));
                            }
                        }
                        Err(e) if manual => self.status_msg = Some(format!("Update check failed: {e}")),
                        Err(_) => {}
                    }
                }
                Msg::UpdateInstalled(result) => {
                    let release = match std::mem::take(&mut self.online.update) {
                        UpdateState::Installing(r) => Some(r),
                        _ => None,
                    };
                    match result.and_then(|target| update::relaunch(&target, &self.open_paths())) {
                        Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => {
                            self.status_msg = Some(format!("Update failed: {e}"));
                            if let Some(r) = release {
                                self.online.update = UpdateState::Available(r);
                            }
                        }
                    }
                }
                Msg::Intel { service, sha256, submit, result } => {
                    let job = match result {
                        Ok(v) => Job::Done(v),
                        Err(e) => Job::Failed(e),
                    };
                    self.online.jobs.insert((service, sha256, submit), job);
                }
            }
        }
        let s = &self.online.settings;
        let now = settings::now();
        if s.check_updates
            && matches!(self.online.update, UpdateState::Idle)
            && now.saturating_sub(s.last_update_check) >= DAY
            && now.saturating_sub(self.online.last_attempt) >= RETRY
        {
            self.online.check_for_updates(ctx, false);
        }
    }

    /// Files to reopen after an update restarts the app.
    fn open_paths(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = [&self.file_path, &self.journal_path].into_iter().flatten().cloned().collect();
        v.extend(self.usn_max.iter().map(|(p, _)| p.clone()));
        v.extend(self.pf.entries.iter().map(|e| e.path.clone()));
        v
    }

    /// Status-bar text while a check the analyst started is running.
    pub(super) fn update_status(&self) -> Option<&'static str> {
        match self.online.update {
            UpdateState::Checking { manual: true } => Some("Checking for updates…"),
            _ => None,
        }
    }

    pub(super) fn help_menu(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("❓ Help", |ui| {
            let checking = matches!(self.online.update, UpdateState::Checking { .. });
            if ui.add_enabled(!checking, egui::Button::new("Check for updates…")).clicked() {
                self.online.check_for_updates(ui.ctx(), true);
                ui.close();
            }
            if ui.button("Settings…").clicked() {
                self.online.settings_open = true;
                ui.close();
            }
            ui.separator();
            ui.hyperlink_to("Website", "https://nyanites.github.io/sediment/");
            ui.hyperlink_to("Release notes", "https://github.com/Nyanites/sediment/releases");
            ui.hyperlink_to("Report a problem", "https://github.com/Nyanites/sediment/issues");
            ui.separator();
            ui.label(RichText::new(format!("Sediment {}", update::CURRENT)).weak());
        });
    }

    /// The "new version available" bar under the toolbar.
    pub(super) fn update_banner(&mut self, ui: &mut egui::Ui) {
        let (release, installing) = match &self.online.update {
            UpdateState::Available(r) if !self.online.banner_closed => (r.clone(), false),
            UpdateState::Installing(r) => (r.clone(), true),
            _ => return,
        };
        egui::Panel::top("update_banner").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⬆").color(ui.visuals().hyperlink_color));
                ui.label(format!("Sediment {} is available (you have {}).", release.version, update::CURRENT));
                if installing {
                    ui.spinner();
                    ui.label("Downloading and verifying…");
                    return;
                }
                if ui
                    .button("Install and restart")
                    .on_hover_text(
                        "Downloads the new version from GitHub, checks it against its published \
                         SHA-256 checksum, replaces this one and restarts. Open files are reopened.",
                    )
                    .clicked()
                {
                    self.online.update = UpdateState::Installing(release.clone());
                    let r = release.clone();
                    self.online.spawn(ui.ctx(), move || Msg::UpdateInstalled(update::install(&r)));
                }
                ui.hyperlink_to("What's new", &release.url);
                if ui.button("Skip this version").clicked() {
                    self.online.settings.skipped_version = release.version.clone();
                    self.online.update = UpdateState::Idle;
                    self.status_msg = self.online.save();
                }
                if ui.small_button("✖").on_hover_text("Remind me later").clicked() {
                    self.online.banner_closed = true;
                }
            });
        });
    }

    pub(super) fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.online.settings_open;
        let mut changed = false;
        let mut check_now = false;
        egui::Window::new("Settings")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .default_width(460.0)
            .show(ctx, |ui| {
                let o = &mut self.online;
                ui.heading("Updates");
                changed |= ui.checkbox(&mut o.settings.check_updates, "Check for updates once a day").changed();
                ui.horizontal(|ui| {
                    check_now = ui.button("Check now").clicked();
                    let last = o.settings.last_update_check;
                    let when = if last == 0 {
                        "never checked".to_string()
                    } else {
                        chrono::DateTime::from_timestamp(last as i64, 0)
                            .map(|t| format!("last checked {}", t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M")))
                            .unwrap_or_default()
                    };
                    ui.label(RichText::new(when).weak());
                });
                ui.label(
                    RichText::new("The check asks GitHub for the latest release and sends nothing else.")
                        .weak()
                        .small(),
                );

                ui.add_space(10.0);
                ui.heading("VirusTotal and Triage");
                ui.label(
                    RichText::new(
                        "Look up file hashes, or submit content, with your own API keys. \
                         Nothing is sent unless you click a lookup or submit button.",
                    )
                    .weak()
                    .small(),
                );
                egui::Grid::new("keys").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("VirusTotal API key");
                    changed |= ui.add_sized([300.0, 20.0], egui::TextEdit::singleline(&mut o.settings.virustotal_key).password(!o.show_keys))
                        .changed();
                    ui.end_row();
                    ui.label("Triage API key");
                    changed |= ui.add_sized([300.0, 20.0], egui::TextEdit::singleline(&mut o.settings.triage_key).password(!o.show_keys))
                        .changed();
                    ui.end_row();
                    ui.label("Triage server");
                    ui.horizontal(|ui| {
                        if ui.radio(!o.private_triage, "Public (tria.ge)").clicked() {
                            o.private_triage = false;
                            o.settings.triage_api = TRIAGE_PUBLIC.into();
                            changed = true;
                        }
                        if ui.radio(o.private_triage, "Private").clicked() && !o.private_triage {
                            o.private_triage = true;
                            o.settings.triage_api = "https://private.tria.ge/api".into();
                            changed = true;
                        }
                    });
                    ui.end_row();
                    if o.private_triage {
                        ui.label("Private API URL");
                        let r = ui.add_sized([300.0, 20.0], egui::TextEdit::singleline(&mut o.settings.triage_api));
                        if r.changed() && o.settings.triage_api.starts_with("https://") {
                            changed = true;
                        }
                        ui.end_row();
                    }
                });
                ui.checkbox(&mut o.show_keys, "Show keys");
                changed |= ui
                    .checkbox(&mut o.settings.remember_keys, "Remember API keys on this computer")
                    .on_hover_text(
                        "Saves the keys in Sediment's settings file in your user profile, readable \
                         only by your account. Without this they last until Sediment closes.",
                    )
                    .changed();
                ui.label(
                    RichText::new(
                        "Submitted files may be shared: VirusTotal makes uploads available to its \
                         paying customers, and samples on public Triage are visible to everyone.",
                    )
                    .color(ui.visuals().warn_fg_color)
                    .small(),
                );
            });
        self.online.settings_open = open;
        if changed {
            self.online.jobs.clear();
            self.status_msg = self.online.save();
        }
        if check_now {
            self.online.check_for_updates(ctx, true);
        }
    }

    /// The Content tab: each stream's size, hashes and pivots.
    pub(super) fn content_tab(&mut self, ui: &mut egui::Ui) {
        let file_name = extract::file_name(&self.selected_file).unwrap_or_else(|| "sample".into());
        let mut lookup: Option<(Service, String)> = None;
        let mut submit: Option<PendingUpload> = None;
        let mut hash_from_image: Option<usize> = None;
        let have_image = self.volume.is_some();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            if self.selected_streams.is_empty() {
                ui.label("This record has no data streams.");
            }
            for (i, s) in self.selected_streams.iter().enumerate() {
                let title = if s.name.is_empty() { "Main stream".to_string() } else { format!("Stream \"{}\"", s.name) };
                egui::CollapsingHeader::new(format!("{title} · {} bytes", s.size))
                    .id_salt(("stream", i))
                    .default_open(true)
                    .show(ui, |ui| {
                        if s.size == 0 {
                            ui.label(RichText::new("Empty.").weak());
                            return;
                        }
                        let Some(h) = &s.hashes else {
                            ui.label(RichText::new("The content is in clusters on the volume, not in the $MFT.").weak());
                            if s.hashing {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label("Hashing from the image…");
                                });
                            } else if have_image {
                                if ui.button("#️⃣ Hash from image").on_hover_text("Read the content from the disk image and hash it").clicked() {
                                    hash_from_image = Some(i);
                                }
                            } else {
                                ui.label(RichText::new("Open the disk image it came from (🖴 Image) to hash it.").weak());
                            }
                            return;
                        };
                        hash_grid(ui, ("hashes", i), h);
                        ui.add_space(4.0);
                        for service in [Service::VirusTotal, Service::Triage] {
                            let has_key = !self.online.key(service).trim().is_empty();
                            let no_key = format!("Add your {} API key in Help > Settings", service.name());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(service.name()).strong());
                                if ui
                                    .button("🔎 Look up hash")
                                    .on_hover_text(if has_key {
                                        "Search for this SHA-256 with your API key (sends only the hash)"
                                    } else {
                                        "Search for this SHA-256 (asks for your API key first)"
                                    })
                                    .clicked()
                                {
                                    lookup = Some((service, h.sha256.clone()));
                                }
                                if ui
                                    .button("🌐 Open in browser")
                                    .on_hover_text("Open the search page for this SHA-256; no key needed")
                                    .clicked()
                                {
                                    ui.ctx().open_url(egui::OpenUrl::new_tab(intel::browser_url(
                                        service,
                                        &h.sha256,
                                        &self.online.settings.triage_api,
                                    )));
                                }
                                let can_submit = has_key && s.data.is_some();
                                let why_not = if has_key {
                                    format!("Over {} MB: too large to submit from Sediment; use the browser instead", SUBMIT_MAX >> 20)
                                } else {
                                    no_key.clone()
                                };
                                if ui
                                    .add_enabled(can_submit, egui::Button::new("⬆ Submit…"))
                                    .on_hover_text("Upload the content for analysis (asks first)")
                                    .on_disabled_hover_text(why_not)
                                    .clicked()
                                    && let Some(data) = &s.data
                                {
                                    let name = if s.name.is_empty() { file_name.clone() } else { format!("{file_name}_{}", s.name) };
                                    submit = Some(PendingUpload {
                                        service,
                                        file_name: name,
                                        data: data.clone(),
                                        sha256: h.sha256.clone(),
                                    });
                                }
                            });
                            for submitted in [false, true] {
                                if let Some(job) = self.online.jobs.get(&(service, h.sha256.clone(), submitted)) {
                                    job_line(ui, job);
                                }
                            }
                        }
                    });
            }
        });
        if let Some((service, sha256)) = lookup {
            self.request_lookup(service, sha256, ui.ctx());
        }
        if submit.is_some() {
            self.online.confirm = submit;
        }
        if let Some(i) = hash_from_image {
            self.hash_stream_from_image(i, ui.ctx());
        }
    }

    /// First run: offers to set up VirusTotal / Triage keys, and says where
    /// to find the setting when skipped. Shown once either way.
    pub(super) fn welcome_window(&mut self, ctx: &egui::Context) {
        if !self.online.welcome_open || self.online.confirm.is_some() {
            return;
        }
        let mut done: Option<bool> = None;
        egui::Modal::new(egui::Id::new("welcome")).show(ctx, |ui| {
            let o = &mut self.online;
            ui.set_max_width(480.0);
            ui.heading("Welcome to Sediment");
            ui.label(
                "Sediment can look up file hashes on VirusTotal and Triage, or submit samples, \
                 with your own API keys. This is optional: everything else works without them.",
            );
            ui.add_space(8.0);
            egui::Grid::new("welcome_keys").num_columns(3).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("VirusTotal API key");
                ui.add_sized([260.0, 20.0], egui::TextEdit::singleline(&mut o.settings.virustotal_key).password(!o.show_keys));
                ui.hyperlink_to("Get a key", "https://www.virustotal.com/gui/my-apikey");
                ui.end_row();
                ui.label("Triage API key");
                ui.add_sized([260.0, 20.0], egui::TextEdit::singleline(&mut o.settings.triage_key).password(!o.show_keys));
                ui.hyperlink_to("Get a key", "https://tria.ge/account");
                ui.end_row();
            });
            ui.checkbox(&mut o.show_keys, "Show keys");
            ui.checkbox(&mut o.settings.remember_keys, "Remember API keys on this computer").on_hover_text(
                "Saves the keys in Sediment's settings file in your user profile, readable only by \
                 your account. Without this they last until Sediment closes.",
            );
            ui.label(
                RichText::new("Using a private Triage instance? Set its address in Help > Settings.")
                    .weak()
                    .small(),
            );
            ui.add_space(8.0);
            let any_key = !o.settings.virustotal_key.trim().is_empty() || !o.settings.triage_key.trim().is_empty();
            ui.horizontal(|ui| {
                if ui.add_enabled(any_key, egui::Button::new("Save keys")).clicked() {
                    done = Some(true);
                }
                if ui.button("Skip for now").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    done = Some(false);
                }
            });
            ui.label(RichText::new("You can add or change keys any time in Help > Settings.").weak().small());
        });
        let Some(saved) = done else { return };
        let o = &mut self.online;
        o.welcome_open = false;
        o.settings.welcomed = true;
        if !saved {
            o.settings.virustotal_key.clear();
            o.settings.triage_key.clear();
        }
        self.status_msg = o.save().or_else(|| {
            Some(if saved {
                "API keys set. Hash lookups are in a record's Content tab.".into()
            } else {
                "No API keys set. You can add them any time in Help > Settings.".into()
            })
        });
    }

    /// Looks a SHA-256 up, asking for the service's API key first if there is none.
    pub(super) fn request_lookup(&mut self, service: Service, sha256: String, ctx: &egui::Context) {
        if self.online.key(service).trim().is_empty() {
            self.online.key_prompt = Some((service, sha256));
            return;
        }
        let (key, api) = (self.online.key(service).to_string(), self.online.settings.triage_api.clone());
        self.online.jobs.insert((service, sha256.clone(), false), Job::Running);
        self.online.spawn(ctx, move || Msg::Intel { result: intel::lookup(service, &sha256, &key, &api), service, sha256, submit: false });
    }

    /// Asks for a missing API key, then runs the lookup that needed it.
    pub(super) fn key_prompt_window(&mut self, ctx: &egui::Context) {
        let Some((service, _)) = &self.online.key_prompt else { return };
        let service = *service;
        let mut done: Option<bool> = None;
        egui::Modal::new(egui::Id::new("key_prompt")).show(ctx, |ui| {
            let o = &mut self.online;
            ui.set_max_width(460.0);
            ui.heading(format!("{} API key", service.name()));
            ui.label(format!(
                "Checking a hash on {} needs your API key. Only the file's SHA-256 is sent.",
                service.name()
            ));
            ui.add_space(6.0);
            let key = match service {
                Service::VirusTotal => &mut o.settings.virustotal_key,
                Service::Triage => &mut o.settings.triage_key,
            };
            let resp = ui.add_sized([420.0, 20.0], egui::TextEdit::singleline(key).password(!o.show_keys).hint_text("API key"));
            resp.request_focus();
            let entered = !key.trim().is_empty();
            ui.horizontal(|ui| {
                ui.checkbox(&mut o.show_keys, "Show key");
                ui.hyperlink_to(
                    "Get a key",
                    match service {
                        Service::VirusTotal => "https://www.virustotal.com/gui/my-apikey",
                        Service::Triage => "https://tria.ge/account",
                    },
                );
            });
            ui.checkbox(&mut o.settings.remember_keys, "Remember API keys on this computer");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let enter = entered && ui.input(|i| i.key_pressed(Key::Enter));
                if ui.add_enabled(entered, egui::Button::new("Save and check")).clicked() || enter {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    done = Some(false);
                }
            });
            ui.label(RichText::new("Keys can be changed any time in Help > Settings.").weak().small());
        });
        match done {
            Some(true) => {
                let (service, sha256) = self.online.key_prompt.take().expect("checked above");
                self.online.settings.welcomed = true;
                self.status_msg = self.online.save();
                self.request_lookup(service, sha256, ctx);
            }
            Some(false) => self.online.key_prompt = None,
            None => {}
        }
    }

    /// The window opened by right-click > Get hashes / Check on ….
    pub(super) fn hash_window(&mut self, ctx: &egui::Context) {
        let Some(w) = &self.online.hash_win else { return };
        let mut open = true;
        let mut lookup: Option<(Service, String)> = None;
        let mut submit: Option<PendingUpload> = None;
        let mut show = false;
        egui::Window::new(format!("Hashes · {}", w.name))
            .id(egui::Id::new("hash_window"))
            .open(&mut open)
            .default_width(620.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(&w.path).monospace().weak());
                ui.horizontal(|ui| {
                    ui.label(format!("Record #{} · {} bytes", w.record, w.size));
                    if ui.small_button("Show record").clicked() {
                        show = true;
                    }
                });
                ui.separator();
                let Some(h) = &w.hashes else {
                    if w.hashing {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Reading the file from the disk image…");
                        });
                    } else {
                        ui.label("No hashes yet.");
                    }
                    return;
                };
                hash_grid(ui, "hash_window_grid", h);
                if ui.button("📋 Copy all").clicked() {
                    let all: Vec<String> = h.list().iter().map(|(k, v)| format!("{k}: {v}")).collect();
                    ui.ctx().copy_text(format!("{}\n{}", w.path, all.join("\n")));
                }
                ui.add_space(6.0);
                for service in [Service::VirusTotal, Service::Triage] {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(service.name()).strong());
                        if ui.button("🔎 Check").on_hover_text("Look up this SHA-256 (asks for your API key if needed)").clicked() {
                            lookup = Some((service, h.sha256.clone()));
                        }
                        if ui.button("🌐 Open in browser").on_hover_text("Search page for this SHA-256; no key needed").clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(intel::browser_url(service, &h.sha256, &self.online.settings.triage_api)));
                        }
                        let has_key = !self.online.key(service).trim().is_empty();
                        if let Some(data) = &w.data
                            && ui.add_enabled(has_key, egui::Button::new("⬆ Submit…")).on_disabled_hover_text("Add your API key first").clicked()
                        {
                            submit = Some(PendingUpload { service, file_name: w.name.clone(), data: data.clone(), sha256: h.sha256.clone() });
                        }
                    });
                    for submitted in [false, true] {
                        if let Some(job) = self.online.jobs.get(&(service, h.sha256.clone(), submitted)) {
                            job_line(ui, job);
                        }
                    }
                }
            });
        let record = w.record;
        if !open {
            self.online.hash_win = None;
        }
        if show {
            self.show_in_mft(record);
        }
        if let Some((service, sha256)) = lookup {
            self.request_lookup(service, sha256, ctx);
        }
        if submit.is_some() {
            self.online.confirm = submit;
        }
    }

    /// Asks before uploading anything, since submissions can be shared.
    pub(super) fn confirm_upload(&mut self, ctx: &egui::Context) {
        let Some(p) = &self.online.confirm else { return };
        let mut decision = None;
        egui::Modal::new(egui::Id::new("confirm_upload")).show(ctx, |ui| {
            ui.set_max_width(440.0);
            ui.heading(format!("Submit to {}?", p.service.name()));
            ui.label(format!("\"{}\", {} bytes, SHA-256 {}", p.file_name, p.data.len(), p.sha256));
            ui.add_space(6.0);
            let warning = match p.service {
                Service::VirusTotal => "VirusTotal shares uploaded files with its paying customers. \
                                        Don't submit anything confidential to your case or client.",
                Service::Triage if self.online.settings.triage_api == TRIAGE_PUBLIC => {
                    "Samples on public Triage (tria.ge) are visible to everyone. Don't submit anything \
                     confidential to your case or client."
                }
                Service::Triage => "The sample goes to your private Triage instance.",
            };
            ui.label(RichText::new(warning).color(ui.visuals().warn_fg_color));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Submit").clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                let p = self.online.confirm.take().expect("checked above");
                let (key, api) = (self.online.key(p.service).to_string(), self.online.settings.triage_api.clone());
                self.online.jobs.insert((p.service, p.sha256.clone(), true), Job::Running);
                self.online.spawn(ctx, move || Msg::Intel {
                    result: intel::submit(p.service, &p.file_name, &p.data, &key, &api),
                    service: p.service,
                    sha256: p.sha256,
                    submit: true,
                });
            }
            Some(false) => self.online.confirm = None,
            None => {}
        }
    }
}

/// Every hash of `h`, each with a copy button.
fn hash_grid(ui: &mut egui::Ui, id: impl std::hash::Hash + std::fmt::Debug, h: &Hashes) {
    egui::Grid::new(id).num_columns(3).show(ui, |ui| {
        for (k, v) in h.list() {
            ui.label(RichText::new(k).weak());
            // Read-only and selectable; SHA-512 scrolls within the field.
            let mut text = v;
            ui.add_sized([520.0, 20.0], egui::TextEdit::singleline(&mut text).font(egui::TextStyle::Monospace));
            if ui.small_button("📋").on_hover_text(format!("Copy {k}")).clicked() {
                ui.ctx().copy_text(v.to_string());
            }
            ui.end_row();
        }
    });
}

fn job_line(ui: &mut egui::Ui, job: &Job) {
    ui.horizontal_wrapped(|ui| match job {
        Job::Running => {
            ui.spinner();
            ui.label("Working…");
        }
        Job::Failed(e) => {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        Job::Done(v) => {
            let color = match v.level {
                2 => ui.visuals().error_fg_color,
                1 => ui.visuals().warn_fg_color,
                _ => ui.visuals().text_color(),
            };
            ui.colored_label(color, &v.summary);
            if let Some(link) = &v.link {
                ui.hyperlink_to("Open report", link);
            }
        }
    });
}
