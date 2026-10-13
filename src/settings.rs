//! User settings, saved as JSON in the per-user config folder:
//! `%APPDATA%\Sediment` on Windows, `~/Library/Application Support/Sediment`
//! on macOS and `$XDG_CONFIG_HOME/sediment` (or `~/.config/sediment`) on Linux.
//!
//! API keys are only written when the analyst ticks "remember". The file is
//! created readable by its owner only on macOS and Linux; on Windows the
//! per-user `%APPDATA%` folder is already private to the account.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const TRIAGE_PUBLIC: &str = "https://tria.ge/api";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Check GitHub for a new release once a day.
    pub check_updates: bool,
    /// Unix time of the last successful check.
    pub last_update_check: u64,
    /// A release the analyst chose to skip.
    pub skipped_version: String,
    pub remember_keys: bool,
    pub virustotal_key: String,
    pub triage_key: String,
    /// Triage API base: the public cloud or a private instance.
    pub triage_api: String,
    /// The first-run API key prompt has been answered.
    pub welcomed: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            check_updates: true,
            last_update_check: 0,
            skipped_version: String::new(),
            remember_keys: false,
            virustotal_key: String::new(),
            triage_key: String::new(),
            triage_api: TRIAGE_PUBLIC.into(),
            welcomed: false,
        }
    }
}

fn config_dir() -> Option<PathBuf> {
    let env = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        env("APPDATA").map(|d| d.join("Sediment"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Application Support/Sediment"))
    } else {
        env("XDG_CONFIG_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".config")))
            .map(|d| d.join("sediment"))
    }
}

fn path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("settings.json"))
}

impl Settings {
    pub fn load() -> Settings {
        let Some(p) = path() else { return Settings::default() };
        let mut s: Settings = std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if !s.triage_api.starts_with("https://") {
            s.triage_api = TRIAGE_PUBLIC.into();
        }
        s
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path().ok_or("no user config folder")?;
        let dir = p.parent().ok_or("no user config folder")?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let mut on_disk = self.clone();
        if !self.remember_keys {
            on_disk.virustotal_key.clear();
            on_disk.triage_key.clear();
        }
        let json = serde_json::to_vec_pretty(&on_disk).map_err(|e| e.to_string())?;
        let tmp = dir.join("settings.json.tmp");
        write_private(&tmp, &json).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
    }
}

#[cfg(unix)]
fn write_private(p: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::remove_file(p);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(p)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(p: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(p, data)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_take_defaults() {
        let s: Settings = serde_json::from_str(r#"{"check_updates": false}"#).unwrap();
        assert!(!s.check_updates);
        assert_eq!(s.triage_api, TRIAGE_PUBLIC);
    }
}
