//! Parser for Windows Prefetch (.pf) files.
//!
//! Supports the SCCA format versions 17 (XP/2003), 23 (Vista/7), 26 (8/8.1)
//! and 30/31 (10/11). Windows 10+ prefetch files are wrapped in a "MAM"
//! container compressed with Xpress-Huffman, which is decompressed by the
//! pure-Rust decoder in `crate::xpress` on every platform. Other MAM
//! compression formats fall back to ntdll's `RtlDecompressBufferEx` on Windows.

use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ParseError(msg.into()))
}

#[derive(Debug, Clone)]
pub struct Prefetch {
    pub compressed: bool,
    pub compressed_size: usize,
    pub version: u32,
    pub signature: String,
    pub file_size: u32,
    pub executable: String,
    pub hash: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub run_count: u32,
    pub metrics_offset: u32,
    pub metrics_count: u32,
    pub trace_chains_offset: u32,
    pub trace_chains_count: u32,
    pub filename_strings_offset: u32,
    pub filename_strings_size: u32,
    pub volumes_offset: u32,
    pub volumes_count: u32,
    pub volumes_size: u32,
    pub files: Vec<FileMetric>,
    pub trace_chains: Vec<TraceChain>,
    pub volumes: Vec<Volume>,
}

#[derive(Debug, Clone)]
pub struct FileMetric {
    pub index: usize,
    /// Index of this file's first entry in the trace chain array.
    pub trace_chain_index: u32,
    /// Number of consecutive trace chain entries belonging to this file.
    pub trace_chain_count: u32,
    /// Undocumented field at +0x08 (version 23+); usually equals `trace_chain_count`.
    pub unknown_08: Option<u32>,
    pub filename: String,
    pub flags: u32,
    pub file_reference: Option<FileRef>,
}

#[derive(Debug, Clone, Copy)]
pub struct FileRef {
    pub raw: u64,
}

impl FileRef {
    pub fn entry(&self) -> u64 {
        self.raw & 0x0000_FFFF_FFFF_FFFF
    }
    pub fn sequence(&self) -> u16 {
        (self.raw >> 48) as u16
    }
    pub fn is_empty(&self) -> bool {
        self.raw == 0
    }
}

impl fmt::Display for FileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            f.write_str("-")
        } else {
            write!(f, "{}-{}", self.entry(), self.sequence())
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceChain {
    pub index: usize,
    /// Index of the file metric whose trace chain range contains this entry.
    pub file_index: Option<usize>,
    pub next_index: Option<u32>,
    pub block_load_count: u32,
    pub flags: u8,
    pub unknown: u8,
    pub unknown2: u16,
}

#[derive(Debug, Clone)]
pub struct Volume {
    pub device_path: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub serial_number: u32,
    pub file_references: Vec<FileRef>,
    pub directories: Vec<String>,
}

/// Converts a Windows FILETIME (100ns ticks since 1601-01-01) to UTC.
pub fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

struct Reader<'a> {
    data: &'a [u8],
    /// Bytes of strings and references still allowed to be decoded. Tables
    /// may point at the same region many times, so without a budget a small
    /// file could expand into gigabytes.
    budget: std::cell::Cell<usize>,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        // Every string and reference lives in its own part of the file, so
        // twice the file size is plenty for a well-formed one.
        Reader { data, budget: std::cell::Cell::new(data.len().saturating_mul(2)) }
    }
    fn charge(&self, bytes: usize) -> Result<()> {
        match self.budget.get().checked_sub(bytes) {
            Some(left) => {
                self.budget.set(left);
                Ok(())
            }
            None => err("string and reference tables overlap more than the file allows"),
        }
    }
    fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        off.checked_add(len)
            .and_then(|end| self.data.get(off..end))
            .ok_or_else(|| {
                ParseError(format!(
                    "read of {len} bytes at offset 0x{off:X} is out of bounds (file is {} bytes)",
                    self.data.len()
                ))
            })
    }
    fn u8(&self, off: usize) -> Result<u8> {
        Ok(self.slice(off, 1)?[0])
    }
    fn u16(&self, off: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.slice(off, 2)?.try_into().unwrap()))
    }
    fn u32(&self, off: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.slice(off, 4)?.try_into().unwrap()))
    }
    fn u64(&self, off: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.slice(off, 8)?.try_into().unwrap()))
    }
    /// Reads `chars` UTF-16 code units and stops at the first NUL.
    fn utf16(&self, off: usize, chars: usize) -> Result<String> {
        let bytes = self.slice(off, chars.saturating_mul(2))?;
        self.charge(bytes.len())?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>().0.iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

#[cfg(test)]
pub fn parse_file(path: &std::path::Path) -> Result<Prefetch> {
    let data = std::fs::read(path).map_err(|e| ParseError(format!("cannot read file: {e}")))?;
    parse(&data)
}

pub fn parse(raw: &[u8]) -> Result<Prefetch> {
    if raw.len() < 8 {
        return err("file is too small to be a prefetch file");
    }
    let (data, compressed) = if &raw[0..3] == b"MAM" {
        (decompress_mam(raw)?, true)
    } else {
        (raw.to_vec(), false)
    };
    let mut pf = parse_scca(&data)?;
    pf.compressed = compressed;
    pf.compressed_size = raw.len();
    Ok(pf)
}

fn decompress_mam(raw: &[u8]) -> Result<Vec<u8>> {
    let flags = raw[3];
    let format = (flags & 0x0F) as u16;
    let has_crc = flags & 0x80 != 0;
    let uncompressed_size = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
    let data_start = if has_crc { 12 } else { 8 };
    if raw.len() < data_start {
        return err("truncated MAM header");
    }
    if uncompressed_size == 0 || uncompressed_size > 256 * 1024 * 1024 {
        return err(format!("implausible decompressed size: {uncompressed_size}"));
    }
    if format == XPRESS_HUFFMAN {
        // Pure Rust, so this works on every platform.
        return crate::xpress::decompress(&raw[data_start..], uncompressed_size)
            .map_err(|e| ParseError(e.to_string()));
    }
    native::decompress(format, &raw[data_start..], uncompressed_size)
}

/// COMPRESSION_FORMAT_XPRESS_HUFF, used by all Windows 10+ prefetch files.
const XPRESS_HUFFMAN: u16 = 4;

#[cfg(windows)]
mod native {
    use super::{ParseError, Result};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetCompressionWorkSpaceSize(
            format: u16,
            buffer_workspace_size: *mut u32,
            fragment_workspace_size: *mut u32,
        ) -> i32;
        fn RtlDecompressBufferEx(
            format: u16,
            uncompressed_buffer: *mut u8,
            uncompressed_buffer_size: u32,
            compressed_buffer: *const u8,
            compressed_buffer_size: u32,
            final_uncompressed_size: *mut u32,
            workspace: *mut u8,
        ) -> i32;
    }

    pub fn decompress(format: u16, input: &[u8], out_size: usize) -> Result<Vec<u8>> {
        let mut ws_size = 0u32;
        let mut frag_size = 0u32;
        let status =
            unsafe { RtlGetCompressionWorkSpaceSize(format, &mut ws_size, &mut frag_size) };
        if status < 0 {
            return Err(ParseError(format!(
                "unsupported compression format {format} (NTSTATUS 0x{:08X})",
                status as u32
            )));
        }
        let mut workspace = vec![0u8; ws_size as usize];
        let mut out = vec![0u8; out_size];
        let mut final_size = 0u32;
        let status = unsafe {
            RtlDecompressBufferEx(
                format,
                out.as_mut_ptr(),
                out_size as u32,
                input.as_ptr(),
                input.len() as u32,
                &mut final_size,
                workspace.as_mut_ptr(),
            )
        };
        if status < 0 {
            return Err(ParseError(format!(
                "decompression failed (NTSTATUS 0x{:08X})",
                status as u32
            )));
        }
        out.truncate(final_size as usize);
        Ok(out)
    }
}

#[cfg(not(windows))]
mod native {
    use super::Result;
    pub fn decompress(_format: u16, _input: &[u8], _out_size: usize) -> Result<Vec<u8>> {
        super::err(format!(
            "compression format {_format} is only supported on Windows"
        ))
    }
}

fn parse_scca(data: &[u8]) -> Result<Prefetch> {
    let r = Reader::new(data);
    let version = r.u32(0)?;
    let sig = r.slice(4, 4)?;
    if sig != b"SCCA" {
        return err(format!(
            "missing SCCA signature (found {:02X?}); not a prefetch file",
            sig
        ));
    }
    if !matches!(version, 17 | 23 | 26 | 30 | 31) {
        return err(format!("unsupported prefetch format version {version}"));
    }

    let file_size = r.u32(12)?;
    let executable = r.utf16(16, 30)?;
    let hash = r.u32(76)?;

    let metrics_offset = r.u32(84)?;
    let metrics_count = r.u32(88)?;
    let trace_chains_offset = r.u32(92)?;
    let trace_chains_count = r.u32(96)?;
    let filename_strings_offset = r.u32(100)?;
    let filename_strings_size = r.u32(104)?;
    let volumes_offset = r.u32(108)?;
    let volumes_count = r.u32(112)?;
    let volumes_size = r.u32(116)?;

    let (time_offset, time_count, run_count_offset) = match version {
        17 => (120, 1, 144),
        23 => (128, 1, 152),
        26 => (128, 8, 208),
        // Version 30 has two layouts; the shorter one (file metrics start at
        // 0x128 instead of 0x130) drops 8 bytes before the run count.
        _ if metrics_offset == 0x128 => (128, 8, 200),
        _ => (128, 8, 208),
    };
    let mut last_run_times = Vec::new();
    for i in 0..time_count {
        if let Some(t) = filetime_to_utc(r.u64(time_offset + i * 8)?) {
            last_run_times.push(t);
        }
    }
    let run_count = r.u32(run_count_offset)?;

    // File metrics + filename strings.
    let metric_size = if version == 17 { 20 } else { 32 };
    let mut files = Vec::with_capacity((metrics_count as usize).min(data.len() / metric_size));
    for i in 0..metrics_count as usize {
        let off = metrics_offset as usize + i * metric_size;
        let trace_chain_index = r.u32(off)?;
        let trace_chain_count = r.u32(off + 4)?;
        let (unknown_08, name_off, name_len, flags, file_reference) = if version == 17 {
            (None, r.u32(off + 8)?, r.u32(off + 12)?, r.u32(off + 16)?, None)
        } else {
            (
                Some(r.u32(off + 8)?),
                r.u32(off + 12)?,
                r.u32(off + 16)?,
                r.u32(off + 20)?,
                Some(FileRef { raw: r.u64(off + 24)? }),
            )
        };
        let filename = r
            .utf16(
                filename_strings_offset as usize + name_off as usize,
                name_len as usize,
            )
            .unwrap_or_else(|_| "<invalid filename offset>".into());
        files.push(FileMetric {
            index: i,
            trace_chain_index,
            trace_chain_count,
            unknown_08,
            filename,
            flags,
            file_reference,
        });
    }

    // Trace chains.
    let mut trace_chains = Vec::with_capacity((trace_chains_count as usize).min(data.len() / 8));
    for i in 0..trace_chains_count as usize {
        let tc = if version >= 30 {
            let off = trace_chains_offset as usize + i * 8;
            TraceChain {
                index: i,
                file_index: None,
                next_index: None,
                block_load_count: r.u32(off)?,
                flags: r.u8(off + 4)?,
                unknown: r.u8(off + 5)?,
                unknown2: r.u16(off + 6)?,
            }
        } else {
            let off = trace_chains_offset as usize + i * 12;
            TraceChain {
                index: i,
                file_index: None,
                next_index: Some(r.u32(off)?),
                block_load_count: r.u32(off + 4)?,
                flags: r.u8(off + 8)?,
                unknown: r.u8(off + 9)?,
                unknown2: r.u16(off + 10)?,
            }
        };
        trace_chains.push(tc);
    }
    assign_trace_chains(&files, &mut trace_chains);

    // Volumes.
    let volume_entry_size = match version {
        17 => 40,
        23 | 26 => 104,
        _ => 96,
    };
    let mut volumes = Vec::with_capacity((volumes_count as usize).min(data.len() / volume_entry_size));
    for i in 0..volumes_count as usize {
        let base = volumes_offset as usize;
        let off = base + i * volume_entry_size;
        let path_off = r.u32(off)? as usize;
        let path_len = r.u32(off + 4)? as usize;
        let creation_time = filetime_to_utc(r.u64(off + 8)?);
        let serial_number = r.u32(off + 16)?;
        let refs_off = r.u32(off + 20)? as usize;
        let refs_size = r.u32(off + 24)? as usize;
        let dirs_off = r.u32(off + 28)? as usize;
        let dirs_count = r.u32(off + 32)? as usize;

        let device_path = r.utf16(base + path_off, path_len)?;

        let mut file_references = Vec::new();
        if refs_off != 0 && refs_size >= 8 {
            let roff = base + refs_off;
            let count = r.u32(roff + 4)? as usize;
            // Version 17 has an 8-byte header; later versions add 8 more bytes.
            let header = if version == 17 { 8 } else { 16 };
            for j in 0..count {
                let p = roff + header + j * 8;
                if p + 8 > roff + refs_size {
                    break;
                }
                r.charge(8)?;
                file_references.push(FileRef { raw: r.u64(p)? });
            }
        }

        let mut directories = Vec::with_capacity(dirs_count.min(data.len() / 4));
        let mut p = base + dirs_off;
        for _ in 0..dirs_count {
            let chars = r.u16(p)? as usize;
            r.charge(2)?;
            directories.push(r.utf16(p + 2, chars)?);
            p += 2 + (chars + 1) * 2;
        }

        volumes.push(Volume {
            device_path,
            creation_time,
            serial_number,
            file_references,
            directories,
        });
    }

    Ok(Prefetch {
        compressed: false,
        compressed_size: data.len(),
        version,
        signature: String::from_utf8_lossy(sig).into_owned(),
        file_size,
        executable,
        hash,
        last_run_times,
        run_count,
        metrics_offset,
        metrics_count,
        trace_chains_offset,
        trace_chains_count,
        filename_strings_offset,
        filename_strings_size,
        volumes_offset,
        volumes_count,
        volumes_size,
        files,
        trace_chains,
        volumes,
    })
}

/// Marks each trace chain entry with the file metric whose range holds it;
/// later metrics win where (malformed) ranges overlap. Entries already
/// claimed are skipped through `next`, so overlapping ranges stay linear.
fn assign_trace_chains(files: &[FileMetric], chains: &mut [TraceChain]) {
    fn unclaimed(next: &mut [usize], mut i: usize) -> usize {
        while next[i] != i {
            next[i] = next[next[i]];
            i = next[i];
        }
        i
    }
    let n = chains.len();
    let mut next: Vec<usize> = (0..=n).collect();
    for f in files.iter().rev() {
        let start = (f.trace_chain_index as usize).min(n);
        let end = start.saturating_add(f.trace_chain_count as usize).min(n);
        let mut i = unclaimed(&mut next, start);
        while i < end {
            chains[i].file_index = Some(f.index);
            next[i] = i + 1;
            i = unclaimed(&mut next, i + 1);
        }
    }
}

pub fn windows_version_name(version: u32) -> &'static str {
    match version {
        17 => "Windows XP / Server 2003",
        23 => "Windows Vista / 7",
        26 => "Windows 8 / 8.1",
        30 => "Windows 10 / 11",
        31 => "Windows 11",
        _ => "Unknown",
    }
}

/// Removes the leading `\VOLUME{...}` device prefix from a path, if present.
pub fn strip_volume(path: &str) -> &str {
    if path.starts_with("\\VOLUME{") || path.starts_with("\\DEVICE\\") {
        let rest = &path[1..];
        if let Some(i) = rest.find('\\') {
            return &rest[i..];
        }
    }
    path
}

#[derive(Debug, Clone)]
pub struct Notable {
    pub file_index: usize,
    pub reason: String,
}

impl Prefetch {
    /// Full path of the executable this prefetch file belongs to, taken from
    /// the loaded-file list. The header name is truncated to 29 characters,
    /// so a prefix match is used as a fallback.
    pub fn executable_path(&self) -> Option<&str> {
        let exe = self.executable.to_uppercase();
        let base = |p: &str| p.rsplit('\\').next().unwrap_or(p).to_uppercase();
        self.files
            .iter()
            .find(|f| base(&f.filename) == exe)
            .or_else(|| {
                self.files
                    .iter()
                    .find(|f| !exe.is_empty() && base(&f.filename).starts_with(&exe))
            })
            .map(|f| f.filename.as_str())
    }

    fn all_paths(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| f.filename.as_str()).chain(
            self.volumes
                .iter()
                .flat_map(|v| v.directories.iter().map(String::as_str)),
        )
    }

    /// User profile names seen under `\USERS\<name>`.
    pub fn user_accounts(&self) -> Vec<String> {
        let mut users: Vec<String> = self
            .all_paths()
            .filter_map(|p| {
                let rest = strip_volume(p).to_uppercase();
                let rest = rest.strip_prefix("\\USERS\\")?.to_string();
                Some(rest.split('\\').next()?.to_string())
            })
            .filter(|u| !u.is_empty())
            .collect();
        users.sort();
        users.dedup();
        users
    }

    /// Active Directory domains inferred from ADSI schema cache files
    /// (`...\SCHCACHE\<domain>.SCH`).
    pub fn domains(&self) -> Vec<String> {
        let mut d: Vec<String> = self
            .files
            .iter()
            .filter_map(|f| schcache_domain(&f.filename))
            .collect();
        d.sort();
        d.dedup();
        d
    }

    /// Loaded files that are usually worth a closer look during an
    /// investigation, with the reason they were flagged.
    pub fn notable_files(&self) -> Vec<Notable> {
        let mut out = Vec::new();
        for f in &self.files {
            let p = strip_volume(&f.filename).to_uppercase();
            let mut reasons = Vec::new();
            if let Some(i) = p.rfind('\\') {
                let name = &p[i + 1..];
                if let Some((_, stream)) = name.split_once(':') {
                    if stream == "ZONE.IDENTIFIER" {
                        reasons.push("Zone.Identifier stream (Mark of the Web: file came from the internet)".to_string());
                    } else {
                        reasons.push(format!("Alternate data stream \"{stream}\""));
                    }
                }
            }
            if let Some(domain) = schcache_domain(&f.filename) {
                reasons.push(format!("ADSI schema cache: host talked to domain {domain}"));
            }
            if f.filename.eq_ignore_ascii_case(self.executable_path().unwrap_or("")) {
                reasons.push("The executable itself".to_string());
            }
            for (needle, why) in [
                ("\\DOWNLOADS\\", "In a Downloads folder"),
                ("\\DESKTOP\\", "On a user's desktop"),
                ("\\APPDATA\\LOCAL\\TEMP\\", "In a user temp folder"),
                ("\\WINDOWS\\TEMP\\", "In the Windows temp folder"),
                ("\\$RECYCLE.BIN\\", "In the Recycle Bin"),
                ("\\PROGRAMDATA\\", "In ProgramData"),
                ("\\USERS\\PUBLIC\\", "In the Public profile"),
            ] {
                if p.contains(needle) {
                    reasons.push(why.to_string());
                }
            }
            let system_location = p.starts_with("\\WINDOWS\\")
                || p.starts_with("\\PROGRAM FILES")
                || p.starts_with("\\$");
            if reasons.is_empty() && !system_location {
                reasons.push("Outside the Windows and Program Files folders".to_string());
            }
            if !reasons.is_empty() {
                out.push(Notable {
                    file_index: f.index,
                    reason: reasons.join("; "),
                });
            }
        }
        out
    }
}

const KNOWN_TOOLS: &[(&str, &str)] = &[
    ("RUBEUS.EXE", "Rubeus: Kerberos abuse toolkit (ticket requests, Kerberoasting, AS-REP roasting)"),
    ("MIMIKATZ.EXE", "Mimikatz: credential dumping"),
    ("SHARPHOUND.EXE", "SharpHound: BloodHound Active Directory collector"),
    ("SEATBELT.EXE", "Seatbelt: host reconnaissance"),
    ("CERTIFY.EXE", "Certify: AD Certificate Services abuse"),
    ("SHARPUP.EXE", "SharpUp: privilege escalation checks"),
    ("PSEXEC.EXE", "PsExec: remote command execution"),
    ("PSEXEC64.EXE", "PsExec: remote command execution"),
    ("PSEXESVC.EXE", "PsExec service: target side of a remote PsExec session"),
    ("PROCDUMP.EXE", "ProcDump: can be used to dump LSASS memory"),
    ("PROCDUMP64.EXE", "ProcDump: can be used to dump LSASS memory"),
    ("ADFIND.EXE", "AdFind: Active Directory enumeration"),
    ("LAZAGNE.EXE", "LaZagne: credential recovery"),
    ("WINPEAS.EXE", "winPEAS: privilege escalation enumeration"),
    ("WINPEASX64.EXE", "winPEAS: privilege escalation enumeration"),
    ("CHISEL.EXE", "Chisel: tunneling / port forwarding"),
    ("NC.EXE", "Netcat: network tool, often used for reverse shells"),
    ("NC64.EXE", "Netcat: network tool, often used for reverse shells"),
    ("PLINK.EXE", "Plink: SSH tunneling"),
    ("RCLONE.EXE", "Rclone: often used for data exfiltration"),
    ("NTDSUTIL.EXE", "ntdsutil: can be used to copy NTDS.dit"),
    ("VSSADMIN.EXE", "vssadmin: shadow copy management (deleted by ransomware)"),
];

/// (capability, library file names that indicate it)
const CAPABILITIES: &[(&str, &[&str])] = &[
    (".NET runtime", &["MSCOREE.DLL", "CLR.DLL", "CLRJIT.DLL", "CORECLR.DLL"]),
    ("Kerberos / authentication", &["KERBEROS.DLL", "CRYPTDLL.DLL", "SECUR32.DLL", "SAMLIB.DLL", "VAULTCLI.DLL"]),
    ("Active Directory / LDAP", &["WLDAP32.DLL", "NTDSAPI.DLL", "ACTIVEDS.DLL", "ADSLDPC.DLL", "SYSTEM.DIRECTORYSERVICES.DLL", "SYSTEM.DIRECTORYSERVICES.PROTOCOLS.DLL", "LOGONCLI.DLL"]),
    ("Networking", &["WS2_32.DLL", "MSWSOCK.DLL", "DNSAPI.DLL", "WINHTTP.DLL", "WININET.DLL", "URLMON.DLL", "WEBIO.DLL"]),
    ("Cryptography", &["BCRYPT.DLL", "RSAENH.DLL", "NCRYPT.DLL", "CRYPT32.DLL", "DPAPI.DLL"]),
    ("PowerShell", &["SYSTEM.MANAGEMENT.AUTOMATION.DLL", "SYSTEM.MANAGEMENT.AUTOMATION.NI.DLL"]),
    ("Script engine", &["JSCRIPT.DLL", "JSCRIPT9.DLL", "VBSCRIPT.DLL", "WSHOM.OCX", "SCRRUN.DLL"]),
    ("WMI", &["WBEMPROX.DLL", "WMIUTILS.DLL", "FASTPROX.DLL"]),
    ("Remote desktop / WinRM", &["MSTSCAX.DLL", "WSMSVC.DLL", "WSMAUTO.DLL"]),
];

impl Prefetch {
    /// Description of a well-known attacker or admin tool with this
    /// executable name, if any.
    pub fn known_tool(&self) -> Option<&'static str> {
        let exe = self.executable.to_uppercase();
        KNOWN_TOOLS.iter().find(|(n, _)| *n == exe).map(|(_, d)| *d)
    }

    /// Capability hints derived from the libraries the program loaded, with
    /// the matching library names.
    pub fn capabilities(&self) -> Vec<(&'static str, Vec<String>)> {
        let names: Vec<String> = self
            .files
            .iter()
            .map(|f| f.filename.rsplit('\\').next().unwrap_or("").to_uppercase())
            .collect();
        CAPABILITIES
            .iter()
            .filter_map(|(cap, dlls)| {
                let mut hits: Vec<String> = names
                    .iter()
                    .filter(|n| dlls.contains(&n.as_str()))
                    .cloned()
                    .collect();
                hits.dedup();
                (!hits.is_empty()).then_some((*cap, hits))
            })
            .collect()
    }

    /// Rewrites a `\VOLUME{...}` path to a drive letter when a volume with
    /// the same serial number is mounted on this machine.
    pub fn local_path(&self, path: &str) -> Option<String> {
        let rest = strip_volume(path);
        let prefix = &path[..path.len() - rest.len()];
        if prefix.is_empty() {
            return None;
        }
        let volume = self
            .volumes
            .iter()
            .find(|v| v.device_path.eq_ignore_ascii_case(prefix))?;
        Some(format!("{}{rest}", local_drive_for_serial(volume.serial_number)?))
    }
}

#[cfg(windows)]
fn local_drive_for_serial(serial: u32) -> Option<String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetVolumeInformationW(
            root: *const u16,
            name_buf: *mut u16,
            name_size: u32,
            serial: *mut u32,
            max_component: *mut u32,
            flags: *mut u32,
            fs_name_buf: *mut u16,
            fs_name_size: u32,
        ) -> i32;
    }
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8).filter(|i| mask & (1 << i) != 0).find_map(|i| {
        let letter = (b'A' + i) as char;
        let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain([0]).collect();
        let mut s = 0u32;
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        (ok != 0 && s == serial).then(|| format!("{letter}:"))
    })
}

#[cfg(not(windows))]
fn local_drive_for_serial(_serial: u32) -> Option<String> {
    None
}

fn schcache_domain(path: &str) -> Option<String> {
    // ASCII-only uppercasing keeps byte offsets valid for `path`.
    let up = path.to_ascii_uppercase();
    let i = up.find("\\SCHCACHE\\")?;
    let name = &path[i + "\\SCHCACHE\\".len()..];
    let stem = name.strip_suffix(".SCH").or_else(|| name.strip_suffix(".sch"))?;
    (!stem.is_empty() && !stem.contains('\\')).then(|| stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "samples/RUBEUS.EXE-5873E24B.pf";

    const SYN_EXE: &str = r"\VOLUME{01d9aaaa-12345678}\TOOLS\EVIL.EXE";
    const SYN_DEV: &str = r"\VOLUME{01d9aaaa-12345678}";
    const SYN_DIR: &str = r"\VOLUME{01d9aaaa-12345678}\TOOLS";
    const SYN_LAST_RUN: u64 = 133_600_000_000_000_000;

    fn synthetic_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/EVIL.EXE-DEADBEEF.pf")
    }

    /// A minimal, hand-built version 30 (Windows 10/11) prefetch file: EVIL.EXE,
    /// run 3 times, one loaded file, one volume with one directory.
    fn synthetic_scca() -> Vec<u8> {
        fn utf16z(s: &str) -> Vec<u8> {
            s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
        }
        fn put(b: &mut [u8], off: usize, bytes: &[u8]) {
            b[off..off + bytes.len()].copy_from_slice(bytes);
        }
        let chars = |s: &str| s.encode_utf16().count() as u32;

        let metrics_off = 0x130usize;
        let chains_off = metrics_off + 32;
        let names_off = chains_off + 8;
        let names = utf16z(SYN_EXE);
        let volumes_off = names_off + names.len();
        let dev = utf16z(SYN_DEV);
        let dev_off = 96usize; // after the single volume entry
        let dirs_off = dev_off + dev.len();
        let mut dirs = (chars(SYN_DIR) as u16).to_le_bytes().to_vec();
        dirs.extend(utf16z(SYN_DIR));
        let volumes_size = dirs_off + dirs.len();
        let total = volumes_off + volumes_size;

        let mut b = vec![0u8; total];
        put(&mut b, 0, &30u32.to_le_bytes());
        put(&mut b, 4, b"SCCA");
        put(&mut b, 12, &(total as u32).to_le_bytes());
        put(&mut b, 16, &utf16z("EVIL.EXE"));
        put(&mut b, 76, &0xDEAD_BEEFu32.to_le_bytes());
        for (off, v) in [
            (84, metrics_off),
            (88, 1),
            (92, chains_off),
            (96, 1),
            (100, names_off),
            (104, names.len()),
            (108, volumes_off),
            (112, 1),
            (116, volumes_size),
        ] {
            put(&mut b, off, &(v as u32).to_le_bytes());
        }
        put(&mut b, 128, &SYN_LAST_RUN.to_le_bytes());
        put(&mut b, 208, &3u32.to_le_bytes()); // run count
        // File metric: trace chain 0 (+1), name at 0, flags 0x200.
        for (i, v) in [0u32, 1, 1, 0, chars(SYN_EXE), 0x200].iter().enumerate() {
            put(&mut b, metrics_off + i * 4, &v.to_le_bytes());
        }
        put(&mut b, chains_off, &1u32.to_le_bytes()); // block load count
        put(&mut b, names_off, &names);
        // Volume entry: device path, creation time, serial, no refs, 1 dir.
        let v = volumes_off;
        put(&mut b, v, &(dev_off as u32).to_le_bytes());
        put(&mut b, v + 4, &chars(SYN_DEV).to_le_bytes());
        put(&mut b, v + 8, &SYN_LAST_RUN.to_le_bytes());
        put(&mut b, v + 16, &0x1234_5678u32.to_le_bytes());
        put(&mut b, v + 28, &(dirs_off as u32).to_le_bytes());
        put(&mut b, v + 32, &1u32.to_le_bytes());
        put(&mut b, v + dev_off, &dev);
        put(&mut b, v + dirs_off, &dirs);
        b
    }

    /// Writes the synthetic prefetch file, compressed by Windows' own
    /// encoder: `cargo test -- --ignored write_synthetic_fixture`.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn write_synthetic_fixture() {
        let scca = synthetic_scca();
        let mut out = b"MAM\x04".to_vec();
        out.extend((scca.len() as u32).to_le_bytes());
        out.extend(crate::xpress::tests::native::compress(&scca));
        std::fs::write(synthetic_fixture(), out).unwrap();
    }

    /// End-to-end on every platform: a Windows-compressed .pf decompresses
    /// and parses without any Windows APIs.
    #[test]
    fn parses_compressed_prefetch_everywhere() {
        let raw = std::fs::read(synthetic_fixture()).expect("fixture present");
        let size = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        assert!(crate::xpress::decompress(&raw[8..], size).unwrap() == synthetic_scca());
        let pf = parse(&raw).unwrap();
        assert!(pf.compressed);
        assert_eq!(pf.version, 30);
        assert_eq!(pf.executable, "EVIL.EXE");
        assert_eq!(pf.hash, 0xDEAD_BEEF);
        assert_eq!(pf.run_count, 3);
        assert_eq!(pf.last_run_times, [filetime_to_utc(SYN_LAST_RUN).unwrap()]);
        assert_eq!(pf.files.len(), 1);
        assert_eq!(pf.executable_path(), Some(SYN_EXE));
        assert_eq!(pf.volumes[0].serial_number, 0x1234_5678);
        assert_eq!(pf.volumes[0].directories, [SYN_DIR]);
        assert_eq!(pf.trace_chains[0].file_index, Some(0));
    }

    /// Characters whose uppercase form has a different UTF-8 length must not
    /// shift the slice into the middle of a character.
    #[test]
    fn schcache_domain_non_ascii() {
        let p = "\\\u{250}\\SCHCACHE\\\u{250}\u{250}.sch";
        assert_eq!(schcache_domain(p).as_deref(), Some("\u{250}\u{250}"));
        assert_eq!(schcache_domain(r"\X\schcache\corp.local.sch").as_deref(), Some("corp.local"));
    }

    /// The pure-Rust decoder must agree byte for byte with Windows' own.
    #[cfg(windows)]
    #[test]
    fn xpress_matches_ntdll_on_sample() {
        let Ok(raw) = std::fs::read(SAMPLE) else { return };
        let size = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        let ours = crate::xpress::decompress(&raw[8..], size).unwrap();
        let windows = native::decompress(XPRESS_HUFFMAN, &raw[8..], size).unwrap();
        assert!(ours == windows);
    }

    #[test]
    fn parses_sample_win10_prefetch() {
        let Ok(_) = std::fs::metadata(SAMPLE) else { return };
        let pf = parse_file(std::path::Path::new(SAMPLE)).unwrap();
        assert!(pf.compressed);
        assert_eq!(pf.version, 30);
        assert_eq!(pf.executable, "RUBEUS.EXE");
        assert_eq!(pf.hash, 0x5873E24B);
        assert_eq!(pf.run_count, 1);
        assert_eq!(pf.files.len(), 109);
        assert_eq!(pf.volumes.len(), 1);
        assert_eq!(pf.volumes[0].directories.len(), 56);

        // File metrics own consecutive, non-overlapping trace chain ranges.
        let mut next = 0;
        for f in &pf.files {
            assert_eq!(f.trace_chain_index, next);
            next += f.trace_chain_count;
        }
        assert_eq!(next as usize, pf.trace_chains.len());
        assert!(pf.trace_chains.iter().all(|t| t.file_index.is_some()));

        // The sample's user and domain names are left out of the source on purpose.
        let users = pf.user_accounts();
        assert_eq!(users.len(), 1);
        assert_eq!(
            pf.executable_path().map(strip_volume),
            Some(format!("\\USERS\\{}\\DOWNLOADS\\RUBEUS.EXE", users[0]).as_str())
        );
        let domains = pf.domains();
        assert!(domains.len() == 1 && domains[0].ends_with(".LOCAL"));
        assert!(pf.known_tool().is_some_and(|t| t.starts_with("Rubeus")));
        let caps: Vec<&str> = pf.capabilities().iter().map(|(c, _)| *c).collect();
        for expected in [".NET runtime", "Kerberos / authentication", "Active Directory / LDAP", "Networking"] {
            assert!(caps.contains(&expected), "missing capability {expected}: {caps:?}");
        }
        let notable = pf.notable_files();
        for n in &notable {
            println!("{} -> {}", strip_volume(&pf.files[n.file_index].filename), n.reason);
        }
        assert!(notable
            .iter()
            .any(|n| pf.files[n.file_index].filename.ends_with(":ZONE.IDENTIFIER")));
    }
}

#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    /// Decodes every prefetch file on this machine with both decoders.
    /// Needs read access to C:\Windows\Prefetch, so it is opt-in:
    /// `cargo test -- --ignored live_prefetch_dir`.
    #[test]
    #[ignore]
    fn live_prefetch_dir() {
        let Ok(dir) = std::fs::read_dir(r"C:\Windows\Prefetch") else {
            println!(r"C:\Windows\Prefetch is not readable; skipped");
            return;
        };
        let (mut checked, mut parsed) = (0, 0);
        for entry in dir.flatten() {
            let path = entry.path();
            let Ok(raw) = std::fs::read(&path) else { continue };
            if raw.len() < 8 || &raw[0..3] != b"MAM" {
                continue;
            }
            let size = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
            let ours = crate::xpress::decompress(&raw[8..], size);
            let windows = native::decompress(XPRESS_HUFFMAN, &raw[8..], size);
            assert_eq!(ours.ok(), windows.ok(), "{}", path.display());
            checked += 1;
            if parse(&raw).is_ok() {
                parsed += 1;
            }
        }
        println!("decoded {checked} prefetch files identically; {parsed} parsed");
    }
}
