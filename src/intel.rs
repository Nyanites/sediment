//! File hashes and threat-intel pivots: hash lookups on VirusTotal and
//! Triage (Recorded Future Sandbox), and sample submission, with the
//! analyst's own API keys. Nothing is sent unless the analyst asks.
//!
//! Content stored in the `$MFT` is hashed straight away; a larger file's
//! bytes are on the volume, so hashing it needs the disk image.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::net::{self, FormValue, Request};

#[derive(Clone, Debug, PartialEq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha224: String,
    pub sha256: String,
    pub sha384: String,
    pub sha512: String,
}

impl Hashes {
    pub fn of(data: &[u8]) -> Hashes {
        let mut h = Hasher::default();
        h.update(data);
        h.finish()
    }

    /// (algorithm name, hex digest), weakest first.
    pub fn list(&self) -> [(&'static str, &str); 6] {
        [
            ("MD5", &self.md5),
            ("SHA-1", &self.sha1),
            ("SHA-224", &self.sha224),
            ("SHA-256", &self.sha256),
            ("SHA-384", &self.sha384),
            ("SHA-512", &self.sha512),
        ]
    }
}

/// Computes every `Hashes` digest in one pass over content fed in pieces.
#[derive(Default)]
pub struct Hasher {
    md5: Md5,
    sha1: Sha1,
    sha224: Sha224,
    sha256: Sha256,
    sha384: Sha384,
    sha512: Sha512,
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
        self.sha224.update(data);
        self.sha256.update(data);
        self.sha384.update(data);
        self.sha512.update(data);
    }

    pub fn finish(self) -> Hashes {
        Hashes {
            md5: format!("{:x}", self.md5.finalize()),
            sha1: format!("{:x}", self.sha1.finalize()),
            sha224: format!("{:x}", self.sha224.finalize()),
            sha256: format!("{:x}", self.sha256.finalize()),
            sha384: format!("{:x}", self.sha384.finalize()),
            sha512: format!("{:x}", self.sha512.finalize()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    VirusTotal,
    Triage,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::VirusTotal => "VirusTotal",
            Service::Triage => "Triage",
        }
    }
}

/// What a lookup or submission found, ready to show.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub summary: String,
    /// Severity for colouring: 0 unknown/clean, 1 suspicious, 2 malicious.
    pub level: u8,
    pub link: Option<String>,
}

/// Search pages that need no API key, for pivoting in the browser.
pub fn browser_url(service: Service, sha256: &str, triage_api: &str) -> String {
    match service {
        Service::VirusTotal => format!("https://www.virustotal.com/gui/file/{sha256}"),
        Service::Triage => format!("{}/s?q=sha256%3A{sha256}", triage_web(triage_api)),
    }
}

fn triage_web(api: &str) -> &str {
    api.trim_end_matches('/').trim_end_matches("/api")
}

fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_key(key: &str) -> Result<&str, String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("no API key set (Settings)".into());
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the API key contains invalid characters".into());
    }
    Ok(key)
}

fn status_error(service: Service, status: u16) -> String {
    match status {
        401 | 403 => format!("{} rejected the API key (HTTP {status})", service.name()),
        429 => format!("{} quota exceeded; try again later", service.name()),
        _ => format!("{} answered HTTP {status}", service.name()),
    }
}

fn json(body: &[u8]) -> Result<serde_json::Value, String> {
    serde_json::from_slice(body).map_err(|_| "unexpected reply".to_string())
}

pub fn lookup(service: Service, sha256: &str, key: &str, triage_api: &str) -> Result<Verdict, String> {
    if !is_sha256(sha256) {
        return Err("not a SHA-256".into());
    }
    let key = check_key(key)?;
    match service {
        Service::VirusTotal => {
            let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
            let r = net::send(&Request::get(&url).header("x-apikey", key))?;
            match r.status {
                200 => vt_verdict(&json(&r.body)?, sha256),
                404 => Ok(not_found(service)),
                s => Err(status_error(service, s)),
            }
        }
        Service::Triage => {
            let api = triage_api.trim_end_matches('/');
            let url = format!("{api}/v0/search?query=sha256:{sha256}");
            let auth = format!("Bearer {key}");
            let r = net::send(&Request::get(&url).header("Authorization", &auth))?;
            if r.status != 200 {
                return Err(status_error(service, r.status));
            }
            let Some((id, count)) = triage_first(&json(&r.body)?) else {
                return Ok(not_found(service));
            };
            let overview = net::send(&Request::get(&format!("{api}/v0/samples/{id}/overview.json")).header("Authorization", &auth))
                .ok()
                .filter(|r| r.status == 200)
                .and_then(|r| json(&r.body).ok());
            Ok(triage_verdict(&id, count, overview.as_ref(), triage_api))
        }
    }
}

fn not_found(service: Service) -> Verdict {
    Verdict { summary: format!("Not found on {}", service.name()), level: 0, link: None }
}

fn vt_verdict(v: &serde_json::Value, sha256: &str) -> Result<Verdict, String> {
    let a = &v["data"]["attributes"];
    let stats = &a["last_analysis_stats"];
    let n = |k: &str| stats[k].as_u64().unwrap_or(0);
    if !stats.is_object() {
        return Err("unexpected reply from VirusTotal".into());
    }
    let (mal, sus) = (n("malicious"), n("suspicious"));
    let total = mal + sus + n("undetected") + n("harmless");
    let mut summary = format!("{mal}/{total} engines flag it as malicious");
    if sus > 0 {
        summary.push_str(&format!(", {sus} suspicious"));
    }
    if let Some(label) = a["popular_threat_classification"]["suggested_threat_label"].as_str() {
        summary.push_str(&format!(" · {}", clip(label)));
    }
    Ok(Verdict {
        summary,
        level: if mal >= 3 { 2 } else if mal + sus > 0 { 1 } else { 0 },
        link: Some(format!("https://www.virustotal.com/gui/file/{sha256}")),
    })
}

/// The first search hit's sample id and the number of hits.
fn triage_first(v: &serde_json::Value) -> Option<(String, usize)> {
    let hits = v["data"].as_array()?;
    let id = hits.first()?["id"].as_str()?;
    valid_id(id).then(|| (id.to_string(), hits.len()))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn triage_verdict(id: &str, count: usize, overview: Option<&serde_json::Value>, triage_api: &str) -> Verdict {
    let analysis = overview.map(|o| &o["analysis"]);
    let score = analysis.and_then(|a| a["score"].as_u64());
    let families: Vec<&str> = analysis
        .and_then(|a| a["family"].as_array())
        .map(|f| f.iter().filter_map(|x| x.as_str()).take(3).collect())
        .unwrap_or_default();
    let mut summary = format!("{count} analys{} found", if count == 1 { "is" } else { "es" });
    if let Some(s) = score {
        summary.push_str(&format!(" · score {s}/10"));
    }
    if !families.is_empty() {
        summary.push_str(&format!(" · {}", clip(&families.join(", "))));
    }
    Verdict {
        summary,
        level: match score {
            Some(8..) => 2,
            Some(4..) => 1,
            _ => 0,
        },
        link: Some(format!("{}/{id}", triage_web(triage_api))),
    }
}

/// Uploads `data` for analysis. Both services may share submissions with
/// other users (VirusTotal with its subscribers, public Triage with
/// everyone), which the UI makes the analyst confirm first.
pub fn submit(service: Service, name: &str, data: &[u8], key: &str, triage_api: &str) -> Result<Verdict, String> {
    let key = check_key(key)?;
    let dir = std::env::temp_dir().join(format!("sediment-upload-{}-{}", std::process::id(), crate::settings::now()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join("sample.bin");
    let result = std::fs::write(&file, data)
        .map_err(|e| format!("couldn't stage the upload: {e}"))
        .and_then(|()| send_sample(service, name, &file, key, triage_api, data));
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn send_sample(
    service: Service,
    name: &str,
    file: &std::path::Path,
    key: &str,
    triage_api: &str,
    data: &[u8],
) -> Result<Verdict, String> {
    let sha256 = Hashes::of(data).sha256;
    match service {
        Service::VirusTotal => {
            let req = Request {
                form: vec![("file", FormValue::File(file, name))],
                timeout_secs: 120,
                ..Request::get("https://www.virustotal.com/api/v3/files").header("x-apikey", key)
            };
            let r = net::send(&req)?;
            if r.status != 200 {
                return Err(status_error(service, r.status));
            }
            Ok(Verdict {
                summary: "Submitted to VirusTotal; results appear in a minute or two".into(),
                level: 0,
                link: Some(format!("https://www.virustotal.com/gui/file/{sha256}")),
            })
        }
        Service::Triage => {
            let api = triage_api.trim_end_matches('/');
            let url = format!("{api}/v0/samples");
            let auth = format!("Bearer {key}");
            let req = Request {
                form: vec![
                    ("file", FormValue::File(file, name)),
                    ("_json", FormValue::Text(r#"{"kind":"file","interactive":false}"#)),
                ],
                timeout_secs: 120,
                ..Request::get(&url).header("Authorization", &auth)
            };
            let r = net::send(&req)?;
            if !(200..300).contains(&r.status) {
                return Err(status_error(service, r.status));
            }
            let id = json(&r.body)?["id"].as_str().filter(|id| valid_id(id)).map(str::to_string);
            Ok(Verdict {
                summary: "Submitted to Triage; the analysis takes a few minutes".into(),
                level: 0,
                link: id.map(|id| format!("{}/{id}", triage_web(triage_api))),
            })
        }
    }
}

/// Keeps text from a remote service to a sane length for one line.
fn clip(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(80).collect();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hashes() {
        // FIPS 180 test vectors for "abc".
        let h = Hashes::of(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            h.sha384,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            h.sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        );
        // Fed in pieces, the same result.
        let mut p = Hasher::default();
        for c in b"abc".chunks(1) {
            p.update(c);
        }
        assert_eq!(p.finish(), h);
    }

    #[test]
    fn virustotal_reply() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":51,"suspicious":2,"undetected":14,"harmless":0},
            "popular_threat_classification":{"suggested_threat_label":"hacktool.rubeus"}}}}"#,
        )
        .unwrap();
        let sha = "a".repeat(64);
        let r = vt_verdict(&v, &sha).unwrap();
        assert_eq!(r.summary, "51/67 engines flag it as malicious, 2 suspicious · hacktool.rubeus");
        assert_eq!(r.level, 2);
        assert_eq!(r.link.unwrap(), format!("https://www.virustotal.com/gui/file/{sha}"));
        assert!(vt_verdict(&serde_json::json!({"error": {}}), &sha).is_err());
    }

    #[test]
    fn triage_reply() {
        let search: serde_json::Value =
            serde_json::from_str(r#"{"data":[{"id":"240521-abcdef","status":"reported"},{"id":"240101-x"}]}"#).unwrap();
        assert_eq!(triage_first(&search), Some(("240521-abcdef".into(), 2)));
        assert_eq!(triage_first(&serde_json::json!({"data": []})), None);
        assert_eq!(triage_first(&serde_json::json!({"data": [{"id": "../x"}]})), None);
        let overview: serde_json::Value =
            serde_json::from_str(r#"{"analysis":{"score":10,"family":["rubeus"]}}"#).unwrap();
        let v = triage_verdict("240521-abcdef", 2, Some(&overview), "https://tria.ge/api");
        assert_eq!(v.summary, "2 analyses found · score 10/10 · rubeus");
        assert_eq!((v.level, v.link.as_deref()), (2, Some("https://tria.ge/240521-abcdef")));
        let v = triage_verdict("x1", 1, None, "https://private.tria.ge/api/");
        assert_eq!((v.summary.as_str(), v.link.as_deref()), ("1 analysis found", Some("https://private.tria.ge/x1")));
    }

    /// Talks to the real services with a bogus key: both must answer, and
    /// reject it. `cargo test -- --ignored live_intel`.
    #[test]
    #[ignore]
    fn live_intel() {
        let sha = Hashes::of(b"abc").sha256;
        for s in [Service::VirusTotal, Service::Triage] {
            let e = lookup(s, &sha, "not-a-real-key", crate::settings::TRIAGE_PUBLIC).unwrap_err();
            println!("{}: {e}", s.name());
            assert!(e.contains("rejected the API key"), "{e}");
        }
    }

    #[test]
    fn browser_pivots() {
        let sha = "b".repeat(64);
        assert_eq!(browser_url(Service::Triage, &sha, "https://tria.ge/api"), format!("https://tria.ge/s?q=sha256%3A{sha}"));
        assert!(lookup(Service::VirusTotal, "nothex", "k", "").is_err());
        assert!(lookup(Service::VirusTotal, &sha, "  ", "").unwrap_err().contains("no API key"));
    }
}
