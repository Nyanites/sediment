//! In-app updates from GitHub Releases.
//!
//! Flow: ask the GitHub API for the latest release → download this platform's
//! asset and the release's `SHA256SUMS.txt` → verify the checksum (and on
//! macOS the bundle identifier, version and code signature) → swap the new
//! build in next to the running one, keeping the old one until the swap
//! succeeds → relaunch. The only data sent is the request itself.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::net;

const REPO: &str = "Nyanites/sediment";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
#[cfg(target_os = "macos")]
const BUNDLE_ID: &str = "io.github.nyanites.sediment";

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
}

impl Release {
    pub fn is_newer(&self) -> bool {
        is_newer(&self.version, CURRENT)
    }
}

/// Asks GitHub for the latest published release.
pub fn latest() -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let r = net::send(&net::Request::get(&url).header("Accept", "application/vnd.github+json"))?;
    if r.status != 200 {
        return Err(format!("couldn't check for updates (GitHub answered HTTP {})", r.status));
    }
    parse_release(&r.body)
}

fn parse_release(body: &[u8]) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "unexpected reply from GitHub".to_string())?;
    let tag = v["tag_name"].as_str().unwrap_or_default();
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    if !valid_version(&version) {
        return Err(format!("unexpected release tag {tag:?}"));
    }
    Ok(Release {
        url: format!("https://github.com/{REPO}/releases/tag/v{version}"),
        version,
    })
}

fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Numeric comparison of dotted versions; pre-release suffixes (`-beta`) sort
/// before the plain version.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn parse(v: &str) -> (Vec<u64>, bool) {
        let (core, pre) = match v.split_once('-') {
            Some((c, _)) => (c, true),
            None => (v, false),
        };
        (core.split('.').map(|p| p.parse().unwrap_or(0)).collect(), pre)
    }
    let ((a, a_pre), (b, b_pre)) = (parse(candidate), parse(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    b_pre && !a_pre
}

/// The release asset for this build, if there is one.
fn asset_name() -> Option<&'static str> {
    use std::env::consts::{ARCH, OS};
    Some(match (OS, ARCH) {
        ("windows", "x86_64") => "sediment-windows-x86_64.exe",
        ("windows", "aarch64") => "sediment-windows-arm64.exe",
        ("macos", _) => "Sediment-macos.zip",
        ("linux", "x86_64") => "sediment-linux-x86_64",
        ("linux", "aarch64") => "sediment-linux-arm64",
        _ => return None,
    })
}

/// What gets replaced: the `.app` bundle on macOS, otherwise the executable.
fn install_target() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("can't locate the running program: {e}"))?;
    if cfg!(target_os = "macos") {
        let app = exe.ancestors().nth(3).map(Path::to_path_buf);
        return app
            .filter(|a| a.extension().is_some_and(|e| e == "app"))
            .ok_or_else(|| "Sediment isn't running from Sediment.app; update with the install command instead".into());
    }
    if exe.components().any(|c| c.as_os_str() == "target") {
        return Err("this is a development build; update it with cargo".into());
    }
    Ok(exe)
}

fn side_path(target: &Path, suffix: &str) -> Option<PathBuf> {
    let name = target.file_name()?.to_string_lossy();
    Some(target.with_file_name(format!(".{name}.{suffix}")))
}

/// Removes leftovers of a previous update. Call at startup.
pub fn cleanup() {
    let Ok(target) = install_target() else { return };
    for p in [side_path(&target, "old"), side_path(&target, "update")].into_iter().flatten() {
        if p.is_dir() {
            let _ = std::fs::remove_dir_all(&p);
        } else if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Downloads, verifies and installs `release` over the running build. On
/// success the caller should relaunch (`relaunch`) and quit.
pub fn install(release: &Release) -> Result<PathBuf, String> {
    if !valid_version(&release.version) {
        return Err("invalid version".into());
    }
    let asset = asset_name().ok_or("no release build for this platform")?;
    let target = install_target()?;
    let staging = side_path(&target, "update").ok_or("bad install location")?;
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&staging).map_err(|_| {
        format!(
            "can't write next to {}; update with the install command instead",
            target.display()
        )
    })?;
    let result = stage_and_swap(release, asset, &target, &staging);
    let _ = std::fs::remove_dir_all(&staging);
    result.map(|()| target)
}

fn stage_and_swap(release: &Release, asset: &str, target: &Path, staging: &Path) -> Result<(), String> {
    let base = format!("https://github.com/{REPO}/releases/download/v{}", release.version);
    let download = staging.join(asset);
    let sums = staging.join("SHA256SUMS.txt");
    net::download(&format!("{base}/SHA256SUMS.txt"), &sums)?;
    net::download(&format!("{base}/{asset}"), &download)?;

    let sums = std::fs::read_to_string(&sums).map_err(|e| e.to_string())?;
    let expected = expected_sum(&sums, asset).ok_or(format!("the release has no checksum for {asset}"))?;
    let data = std::fs::read(&download).map_err(|e| e.to_string())?;
    let actual = format!("{:x}", Sha256::digest(&data));
    if actual != expected {
        return Err("the download didn't match its published checksum; nothing was changed".into());
    }

    let new = if cfg!(target_os = "macos") { unpack_app(&download, staging, &release.version)? } else { download };
    #[cfg(unix)]
    if !cfg!(target_os = "macos") {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }

    // Park the running build (allowed while it runs, on every platform), move
    // the new one in, and put the old one back if that fails.
    let backup = side_path(target, "old").ok_or("bad install location")?;
    if backup.is_dir() {
        std::fs::remove_dir_all(&backup).map_err(|e| e.to_string())?;
    } else if backup.exists() {
        std::fs::remove_file(&backup).map_err(|e| e.to_string())?;
    }
    std::fs::rename(target, &backup).map_err(|e| format!("couldn't replace Sediment: {e}"))?;
    if let Err(e) = std::fs::rename(&new, target) {
        let _ = std::fs::rename(&backup, target);
        return Err(format!("couldn't replace Sediment: {e}"));
    }
    Ok(())
}

fn expected_sum(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let (hash, name) = (it.next()?, it.next()?);
        let ok = name.trim_start_matches('*') == asset && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
        ok.then(|| hash.to_ascii_lowercase())
    })
}

/// Unpacks `Sediment-macos.zip` and checks it is the expected, validly signed build.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn unpack_app(zip: &Path, staging: &Path, version: &str) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        let unpacked = staging.join("unpacked");
        run("/usr/bin/ditto", &["-x".as_ref(), "-k".as_ref(), zip.as_os_str(), unpacked.as_os_str()])?;
        let app = unpacked.join("Sediment.app");
        if !app.is_dir() {
            return Err("Sediment.app wasn't found in the download".into());
        }
        let plist = app.join("Contents/Info.plist");
        let value = |key: &str| -> Result<String, String> {
            run("/usr/bin/plutil", &["-extract".as_ref(), key.as_ref(), "raw".as_ref(), "-o".as_ref(), "-".as_ref(), plist.as_os_str()])
                .map(|s| s.trim().to_string())
        };
        let (id, ver) = (value("CFBundleIdentifier")?, value("CFBundleShortVersionString")?);
        if id != BUNDLE_ID || ver != version {
            return Err(format!("unexpected app in the download ({id} {ver})"));
        }
        run("/usr/bin/codesign", &["--verify".as_ref(), "--strict".as_ref(), "--deep".as_ref(), app.as_os_str()])
            .map_err(|_| "the downloaded app's code signature is invalid".to_string())?;
        Ok(app)
    }
    #[cfg(not(target_os = "macos"))]
    Err("not a macOS build".into())
}

#[cfg(target_os = "macos")]
fn run(cmd: &str, args: &[&std::ffi::OsStr]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("couldn't run {cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Starts the installed build as a new process with `files` to open (the
/// caller then quits).
pub fn relaunch(target: &Path, files: &[PathBuf]) -> Result<(), String> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/open");
        c.arg("-n").arg(target).arg("--args");
        c
    } else {
        Command::new(target)
    };
    cmd.args(files).spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert!(is_newer("0.1.3", "0.1.2"));
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(is_newer("0.1.10", "0.1.9"), "numeric, not string, comparison");
        assert!(!is_newer("0.1.2", "0.1.2"));
        assert!(!is_newer("0.1.1", "0.1.2"));
        assert!(is_newer("0.2.0", "0.2.0-beta"));
        assert!(!is_newer("0.2.0-beta", "0.2.0"));
    }

    #[test]
    fn rejects_odd_tags() {
        assert!(valid_version("0.1.3"));
        assert!(!valid_version("0.1.3; rm -rf"));
        assert!(!valid_version("../../x"));
        assert!(!valid_version(""));
        assert!(parse_release(br#"{"tag_name": "v../../evil"}"#).is_err());
        let r = parse_release(br#"{"tag_name": "v0.2.0"}"#).unwrap();
        assert_eq!((r.version.as_str(), r.url.as_str()), ("0.2.0", "https://github.com/Nyanites/sediment/releases/tag/v0.2.0"));
    }

    /// Downloads the latest release and swaps it over a dummy install:
    /// `cargo test -- --ignored live_update`.
    #[test]
    #[ignore]
    fn live_update() {
        let release = latest().expect("GitHub reachable");
        println!("latest release: {}", release.version);
        let asset = asset_name().unwrap();
        let dir = std::env::temp_dir().join(format!("sediment-update-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join(if cfg!(target_os = "macos") { "Sediment.app" } else { "sediment.bin" });
        if cfg!(target_os = "macos") {
            std::fs::create_dir(&target).unwrap();
        } else {
            std::fs::write(&target, b"old build").unwrap();
        }
        let staging = side_path(&target, "update").unwrap();
        std::fs::create_dir(&staging).unwrap();
        stage_and_swap(&release, asset, &target, &staging).unwrap();
        if !cfg!(target_os = "macos") {
            let new = std::fs::read(&target).unwrap();
            assert!(new.len() > 1_000_000, "the release build replaced the dummy");
            assert_eq!(std::fs::read(side_path(&target, "old").unwrap()).unwrap(), b"old build");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checksum_lookup() {
        let sums = "0beaccbbfbe3dc39d48b0508505a35f9b25cdc2adbe264953451bcdf9e9b3102  Sediment-macos.zip\n\
                    AA0D0F572CF3D3E10216722A6ED3EBA9AD70689C28CACAE140875C98AB4265FF *sediment-linux-x86_64\n\
                    nothex  sediment-linux-arm64\n";
        assert_eq!(expected_sum(sums, "Sediment-macos.zip").unwrap().len(), 64);
        assert!(expected_sum(sums, "sediment-linux-x86_64").unwrap().starts_with("aa0d0f"));
        assert!(expected_sum(sums, "sediment-linux-arm64").is_none());
        assert!(expected_sum(sums, "Sediment-macos").is_none());
    }
}
