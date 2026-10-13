//! HTTPS requests through the system `curl` (Windows 10+, macOS and most Linux
//! distributions ship it), so no HTTP or TLS code ships in the app.
//!
//! Secrets never appear on the command line, where other local users could
//! read them from the process list: headers and form fields go to curl as a
//! config file on stdin.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const USER_AGENT: &str = concat!("Sediment/", env!("CARGO_PKG_VERSION"));

pub struct Request<'a> {
    pub url: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    /// Multipart form fields; makes the request a POST.
    pub form: Vec<(&'a str, FormValue<'a>)>,
    pub timeout_secs: u32,
}

pub enum FormValue<'a> {
    Text(&'a str),
    File(&'a Path, &'a str),
}

impl<'a> Request<'a> {
    pub fn get(url: &'a str) -> Self {
        Request { url, headers: Vec::new(), form: Vec::new(), timeout_secs: 30 }
    }

    pub fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Bodies larger than this are cut off; nothing we ask for comes close.
const MAX_BODY: u64 = 64 * 1024 * 1024;

pub fn curl_path() -> PathBuf {
    #[cfg(windows)]
    {
        // The copy Windows ships, not whatever is first on PATH.
        if let Some(root) = std::env::var_os("SystemRoot") {
            let p = PathBuf::from(root).join("System32").join("curl.exe");
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("curl.exe")
    }
    #[cfg(not(windows))]
    {
        for p in ["/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"] {
            if Path::new(p).exists() {
                return PathBuf::from(p);
            }
        }
        PathBuf::from("curl")
    }
}

/// Quotes a value for a curl config file.
fn quote(s: &str) -> Result<String, String> {
    if s.chars().any(|c| c.is_control()) {
        return Err("value contains control characters".into());
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The curl config for `req`, written to curl's stdin.
fn config(req: &Request) -> Result<String, String> {
    let mut c = String::new();
    c.push_str(&format!("url = {}\n", quote(req.url)?));
    c.push_str(&format!("user-agent = {}\n", quote(USER_AGENT)?));
    for (k, v) in &req.headers {
        if !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("bad header name {k:?}"));
        }
        c.push_str(&format!("header = {}\n", quote(&format!("{k}: {v}"))?));
    }
    for (k, v) in &req.form {
        if !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(format!("bad form field {k:?}"));
        }
        match v {
            FormValue::Text(t) => c.push_str(&format!("form-string = {}\n", quote(&format!("{k}={t}"))?)),
            FormValue::File(path, name) => {
                let path = path.to_str().ok_or("temporary path is not valid UTF-8")?;
                // `;` and `"` would end curl's own field syntax.
                let name: String = name.chars().filter(|c| !matches!(c, ';' | '"' | ',')).collect();
                c.push_str(&format!("form = {}\n", quote(&format!("{k}=@\"{path}\";filename=\"{name}\""))?));
            }
        }
    }
    Ok(c)
}

pub fn send(req: &Request) -> Result<Response, String> {
    if !req.url.starts_with("https://") {
        return Err("only https URLs are allowed".into());
    }
    let cfg = config(req)?;
    let mut cmd = Command::new(curl_path());
    #[cfg(windows)]
    {
        // Without this, a GUI app flashes a console window for every request.
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .args(["--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https"])
        .args(["--tlsv1.2", "--max-filesize", &MAX_BODY.to_string()])
        .args(["--max-time", &req.timeout_secs.to_string()])
        .args(["--write-out", "\n%{http_code}", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't run curl ({e}); install curl to use online features"))?;
    child
        .stdin
        .take()
        .ok_or("couldn't talk to curl")?
        .write_all(cfg.as_bytes())
        .map_err(|e| format!("couldn't talk to curl: {e}"))?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim().trim_start_matches("curl: ");
        return Err(if err.is_empty() { "network request failed".into() } else { format!("network request failed: {err}") });
    }
    let mut body = out.stdout;
    let split = body.iter().rposition(|&b| b == b'\n').ok_or("unexpected curl output")?;
    let status = std::str::from_utf8(&body[split + 1..])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or("unexpected curl output")?;
    body.truncate(split);
    Ok(Response { status, body })
}

/// Downloads `url` to `to`, failing on any non-2xx status.
pub fn download(url: &str, to: &Path) -> Result<(), String> {
    let r = send(&Request { timeout_secs: 600, ..Request::get(url) })?;
    if !(200..300).contains(&r.status) {
        return Err(format!("download failed (HTTP {})", r.status));
    }
    std::fs::write(to, r.body).map_err(|e| format!("couldn't save the download: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_keeps_secrets_quoted() {
        let req = Request::get("https://example.com/a?b=c").header("x-apikey", "k\"ey\\1");
        let c = config(&req).unwrap();
        assert!(c.contains("header = \"x-apikey: k\\\"ey\\\\1\"\n"), "{c}");
        assert!(config(&Request::get("https://x").header("x", "a\nurl = https://evil")).is_err());
        assert!(config(&Request::get("https://x").header("a: b\nx", "v")).is_err());
    }

    #[test]
    fn form_file_names_cannot_break_out() {
        let p = Path::new("/tmp/f");
        let req = Request {
            form: vec![("file", FormValue::File(p, "a\";type=text/html;b.exe"))],
            ..Request::get("https://x")
        };
        let c = config(&req).unwrap();
        assert!(c.contains("filename=\\\"atype=text/htmlb.exe\\\""), "{c}");
    }

    #[test]
    fn refuses_plain_http() {
        assert!(send(&Request::get("http://example.com")).is_err());
    }
}
