//! Pulls resident `$DATA` streams out of an MFT record and packs them into a
//! ZIP encrypted with the password `infected`, the usual way of handing out
//! possibly malicious samples: antivirus leaves it alone and nobody runs the
//! content by double-clicking it. The encryption is traditional PKWARE
//! ("ZipCrypto"), which every unzip tool supports and which is weak on purpose
//! here: it is a safety wrapper, not confidentiality.
//!
//! A file is read from all of its records (see `MftFile::file_records`): when
//! its attributes don't fit in one record, `$DATA` and the long name often
//! live in an extension record. Only resident content can be recovered: a
//! non-resident stream lives in clusters on the volume, which the `$MFT` alone
//! does not contain.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::mft::{self, AttrBody, Record, ATTR_DATA, ATTR_FILE_NAME, ATTR_STANDARD_INFORMATION};
use crate::ntfs;

pub const PASSWORD: &str = "infected";

/// A `$DATA` stream of a record and whether its bytes are in the record.
pub struct Stream<'a> {
    /// Empty for the unnamed (main) stream, otherwise the ADS name.
    pub name: &'a str,
    /// `Some` when the content is resident.
    pub data: Option<&'a [u8]>,
}

/// The `$DATA` streams of a file, given its records (base record first).
pub fn streams(recs: &[Record]) -> Vec<Stream<'_>> {
    let mut out: Vec<Stream> = Vec::new();
    for rec in recs {
        for a in rec.attributes.iter().filter(|a| a.type_code == ATTR_DATA) {
            // A non-resident stream split over several records is listed once.
            if matches!(a.body, AttrBody::NonResident { start_vcn, .. } if start_vcn != 0)
                || out.iter().any(|s| s.name == a.name)
            {
                continue;
            }
            out.push(Stream {
                name: &a.name,
                data: a.resident_content(&rec.data),
            });
        }
    }
    out
}

/// The file's preferred name (Win32 over POSIX over DOS 8.3).
pub fn file_name(recs: &[Record]) -> Option<String> {
    recs.iter()
        .flat_map(|r| {
            r.attributes
                .iter()
                .filter(|a| a.type_code == ATTR_FILE_NAME)
                .filter_map(|a| a.file_name(&r.data))
        })
        .max_by_key(|f| mft::namespace_rank(f.namespace))
        .map(|f| f.name)
}

/// Builds the encrypted archive of every resident `$DATA` stream of the file
/// made of `recs`. Returns `None` when there is nothing resident to extract.
#[cfg(test)]
pub fn resident_zip(recs: &[Record], record_no: usize) -> Option<Vec<u8>> {
    let base = file_name(recs)
        .map(|n| sanitize(&n))
        .unwrap_or_else(|| format!("record_{record_no}"));
    let modified = recs
        .iter()
        .flat_map(|r| r.attributes.iter().map(move |a| (r, a)))
        .find_map(|(r, a)| (a.type_code == ATTR_STANDARD_INFORMATION).then(|| a.standard_info(&r.data))?)
        .map_or(0, |si| si.times.modified);
    let files: Vec<ZipFile> = streams(recs)
        .into_iter()
        .filter_map(|s| {
            let name = if s.name.is_empty() {
                base.clone()
            } else {
                format!("{base}_{}", sanitize(s.name))
            };
            Some(ZipFile { name, data: s.data?, modified })
        })
        .collect();
    (!files.is_empty()).then(|| encrypted_zip(&files, PASSWORD.as_bytes()))
}

/// What `extract_to` wrote.
pub struct Extracted {
    pub files: usize,
    pub bytes: u64,
    /// Streams left out, with the reason.
    pub skipped: Vec<String>,
}

/// Total size of what `extract_to` would write, for progress.
pub fn extract_size(recs: &[Record], vol: Option<&ntfs::Volume>) -> u64 {
    streams(recs)
        .iter()
        .filter(|s| s.data.is_some() || vol.is_some())
        .filter_map(|s| ntfs::content_size(recs, s.name))
        .sum()
}

/// Writes every `$DATA` stream of the file made of `recs` to an encrypted
/// ZIP at `dest`. Content in the record needs nothing else; content in
/// clusters is read from `vol`, the volume the `$MFT` came from. The archive
/// is written next to `dest` and only renamed into place once complete.
pub fn extract_to(
    dest: &std::path::Path,
    recs: &[Record],
    record_no: usize,
    vol: Option<&ntfs::Volume>,
    progress: &AtomicU64,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Extracted, String> {
    let base = file_name(recs)
        .map(|n| sanitize(&n))
        .unwrap_or_else(|| format!("record_{record_no}"));
    let modified = recs
        .iter()
        .flat_map(|r| r.attributes.iter().map(move |a| (r, a)))
        .find_map(|(r, a)| (a.type_code == ATTR_STANDARD_INFORMATION).then(|| a.standard_info(&r.data))?)
        .map_or(0, |si| si.times.modified);
    let wof = matches!(ntfs::kind(recs, ""), Some(ntfs::Kind::Wof));

    let tmp = dest.with_extension("zip.partial");
    let file = std::fs::File::create(&tmp).map_err(|e| format!("couldn't create {}: {e}", tmp.display()))?;
    let mut zip = ZipWriter::new(std::io::BufWriter::with_capacity(1 << 20, file), PASSWORD.as_bytes());
    let mut out = Extracted { files: 0, bytes: 0, skipped: Vec::new() };
    let result = (|| -> Result<(), String> {
        for s in streams(recs) {
            let label = if s.name.is_empty() { "main stream".to_string() } else { format!("stream {:?}", s.name) };
            // WOF content is read through the main stream, decompressed.
            if wof && s.name == "WofCompressedData" {
                continue;
            }
            let kind = ntfs::kind(recs, s.name);
            let mut name = if s.name.is_empty() { base.clone() } else { format!("{base}_{}", sanitize(s.name)) };
            if matches!(kind, Some(ntfs::Kind::Encrypted)) {
                name.push_str(".efs-encrypted");
            }
            let Some(size) = ntfs::content_size(recs, s.name) else {
                out.skipped.push(format!("{label}: no data"));
                continue;
            };
            match (s.data, vol) {
                (Some(d), _) if !(wof && s.name.is_empty()) => {
                    zip.add(&name, modified, d).map_err(|e| e.to_string())?;
                    progress.fetch_add(d.len() as u64, Ordering::Relaxed);
                }
                (_, Some(vol)) => {
                    let local = AtomicU64::new(0);
                    zip.add_stream(&name, modified, size, |e| {
                        ntfs::read_content(vol, recs, s.name, &mut |b| {
                            if cancel.load(Ordering::Relaxed) {
                                return Err("cancelled".into());
                            }
                            progress.fetch_add(b.len() as u64, Ordering::Relaxed);
                            e.write(b).map_err(|x| format!("couldn't write the archive: {x}"))
                        }, &local)
                        .map_err(|err| std::io::Error::other(format!("{label}: {err}")))
                    })
                    .map_err(|e| e.to_string())?;
                }
                (_, None) => {
                    out.skipped.push(format!(
                        "{label} ({size} bytes): its content is on the volume, not in the $MFT; open the disk image to extract it"
                    ));
                    continue;
                }
            }
            out.files += 1;
            out.bytes += size;
        }
        Ok(())
    })();
    let finished = result.and_then(|()| zip.finish().map_err(|e| e.to_string()));
    match finished {
        Ok(_) if out.files == 0 => {
            let _ = std::fs::remove_file(&tmp);
            Err(out.skipped.first().cloned().unwrap_or_else(|| "nothing to extract".into()))
        }
        Ok(_) => {
            let _ = std::fs::remove_file(dest);
            std::fs::rename(&tmp, dest).map_err(|e| format!("couldn't save {}: {e}", dest.display()))?;
            Ok(out)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// Default name offered for the archive.
pub fn zip_file_name(recs: &[Record], record_no: usize) -> String {
    match file_name(recs) {
        Some(n) => format!("record_{record_no}_{}.zip", sanitize(&n)),
        None => format!("record_{record_no}.zip"),
    }
}

/// Makes an NTFS name safe as a path component on any OS.
fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    match s.trim_matches(|c| c == '.' || c == ' ') {
        "" => "_".into(),
        t => t.into(),
    }
}

// ---------------------------------------------------------------- zip writer

#[cfg(test)]
pub struct ZipFile<'a> {
    pub name: String,
    pub data: &'a [u8],
    /// FILETIME; 0 for unknown.
    pub modified: u64,
}

/// Writes a ZIP of stored (uncompressed) entries, each encrypted with
/// traditional PKWARE encryption (APPNOTE 6.1).
#[cfg(test)]
pub fn encrypted_zip(files: &[ZipFile], password: &[u8]) -> Vec<u8> {
    let mut z = ZipWriter::new(Vec::new(), password);
    for f in files {
        z.add(&f.name, f.modified, f.data).expect("writing to memory");
    }
    z.finish().expect("writing to memory")
}

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_UTF8: u16 = 0x0800;
const U32_MAX: u64 = 0xFFFF_FFFF;

/// Streams encrypted, stored entries to `out`, so files larger than memory
/// can be archived. Entries whose content is known up front get their CRC in
/// the local header; streamed ones use a data descriptor. ZIP64 is used where
/// sizes or offsets don't fit in 32 bits.
pub struct ZipWriter<W: std::io::Write> {
    out: W,
    pos: u64,
    central: Vec<u8>,
    count: u64,
    password: Vec<u8>,
    rng: HeaderRng,
    /// Sizes and offsets from here on use ZIP64 fields (lowered by tests).
    limit: u64,
}

/// The open entry of a `ZipWriter::add_stream`.
pub struct EntryWriter<'a, W: std::io::Write> {
    zip: &'a mut ZipWriter<W>,
    keys: Keys,
    crc: u32,
    written: u64,
    buf: Vec<u8>,
}

impl<W: std::io::Write> EntryWriter<'_, W> {
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.crc = !data.iter().fold(!self.crc, |c, &b| crc_step(c, b));
        self.buf.clear();
        self.buf.extend(data.iter().map(|&b| self.keys.encrypt(b)));
        self.zip.out.write_all(&self.buf)?;
        self.zip.pos += data.len() as u64;
        self.written += data.len() as u64;
        Ok(())
    }
}

impl<W: std::io::Write> ZipWriter<W> {
    pub fn new(out: W, password: &[u8]) -> Self {
        ZipWriter { out, pos: 0, central: Vec::new(), count: 0, password: password.to_vec(), rng: HeaderRng::new(), limit: U32_MAX }
    }

    fn put(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.out.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// Adds an entry whose content is in memory.
    pub fn add(&mut self, name: &str, modified: u64, data: &[u8]) -> std::io::Result<()> {
        let crc = crc32(data);
        self.entry(name, modified, data.len() as u64, Some(crc), |e| e.write(data))
    }

    /// Adds an entry of `size` bytes produced by `fill`, which may hand over
    /// the content in pieces.
    pub fn add_stream(
        &mut self,
        name: &str,
        modified: u64,
        size: u64,
        fill: impl FnOnce(&mut EntryWriter<W>) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.entry(name, modified, size, None, fill)
    }

    fn entry(
        &mut self,
        name: &str,
        modified: u64,
        size: u64,
        crc: Option<u32>,
        fill: impl FnOnce(&mut EntryWriter<W>) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let (time, date) = dos_datetime(modified);
        let name_bytes = name.as_bytes();
        let offset = self.pos;
        let stored = size + 12;
        let zip64 = stored >= self.limit;
        let far = offset >= self.limit;
        let flags = FLAG_ENCRYPTED | FLAG_UTF8 | if crc.is_none() { FLAG_DESCRIPTOR } else { 0 };
        let version: u16 = if zip64 || far { 45 } else { 20 };

        let mut local = Vec::new();
        put32(&mut local, 0x0403_4B50);
        put16(&mut local, version);
        put16(&mut local, flags);
        put16(&mut local, 0); // stored
        put16(&mut local, time);
        put16(&mut local, date);
        put32(&mut local, crc.unwrap_or(0));
        if zip64 {
            put32(&mut local, U32_MAX as u32);
            put32(&mut local, U32_MAX as u32);
        } else {
            put32(&mut local, if crc.is_some() { stored as u32 } else { 0 });
            put32(&mut local, if crc.is_some() { size as u32 } else { 0 });
        }
        put16(&mut local, name_bytes.len() as u16);
        put16(&mut local, if zip64 { 20 } else { 0 });
        local.extend_from_slice(name_bytes);
        if zip64 {
            put16(&mut local, 0x0001);
            put16(&mut local, 16);
            let known = if crc.is_some() { (size, stored) } else { (0, 0) };
            local.extend_from_slice(&known.0.to_le_bytes());
            local.extend_from_slice(&known.1.to_le_bytes());
        }
        self.put(&local)?;

        // 12-byte encryption header; its last byte lets unzip tools check the
        // password: the CRC's high byte, or the time's when the CRC comes later.
        let mut keys = Keys::new(&self.password);
        let mut header = [0u8; 12];
        self.rng.fill(&mut header[..11]);
        header[11] = match crc {
            Some(c) => (c >> 24) as u8,
            None => (time >> 8) as u8,
        };
        let enc: Vec<u8> = header.iter().map(|&b| keys.encrypt(b)).collect();
        self.put(&enc)?;

        let mut e = EntryWriter { zip: self, keys, crc: 0, written: 0, buf: Vec::new() };
        fill(&mut e)?;
        let (actual_crc, written) = (e.crc, e.written);
        if written != size {
            return Err(std::io::Error::other(format!("{name}: expected {size} bytes, got {written}")));
        }
        if crc.is_none() {
            let mut d = Vec::new();
            put32(&mut d, 0x0807_4B50);
            put32(&mut d, actual_crc);
            if zip64 {
                d.extend_from_slice(&stored.to_le_bytes());
                d.extend_from_slice(&size.to_le_bytes());
            } else {
                put32(&mut d, stored as u32);
                put32(&mut d, size as u32);
            }
            self.put(&d)?;
        }

        let mut extra = Vec::new();
        if zip64 {
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&stored.to_le_bytes());
        }
        if far {
            extra.extend_from_slice(&offset.to_le_bytes());
        }
        let c = &mut self.central;
        put32(c, 0x0201_4B50);
        put16(c, version); // made by
        put16(c, version); // needed
        put16(c, flags);
        put16(c, 0);
        put16(c, time);
        put16(c, date);
        put32(c, actual_crc);
        put32(c, if zip64 { U32_MAX as u32 } else { stored as u32 });
        put32(c, if zip64 { U32_MAX as u32 } else { size as u32 });
        put16(c, name_bytes.len() as u16);
        put16(c, if extra.is_empty() { 0 } else { extra.len() as u16 + 4 });
        put16(c, 0); // comment
        put16(c, 0); // disk
        put16(c, 0); // internal attributes
        put32(c, 0); // external attributes
        put32(c, if far { U32_MAX as u32 } else { offset as u32 });
        c.extend_from_slice(name_bytes);
        if !extra.is_empty() {
            put16(c, 0x0001);
            put16(c, extra.len() as u16);
            c.extend_from_slice(&extra);
        }
        self.count += 1;
        Ok(())
    }

    /// Writes the central directory and returns the underlying writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        let cd_offset = self.pos;
        let central = std::mem::take(&mut self.central);
        self.put(&central)?;
        let cd_size = central.len() as u64;
        let zip64 = self.count >= 0xFFFF || cd_offset >= self.limit || cd_size >= self.limit;
        let mut end = Vec::new();
        if zip64 {
            let record_at = self.pos;
            put32(&mut end, 0x0606_4B50);
            end.extend_from_slice(&44u64.to_le_bytes());
            put16(&mut end, 45);
            put16(&mut end, 45);
            put32(&mut end, 0);
            put32(&mut end, 0);
            end.extend_from_slice(&self.count.to_le_bytes());
            end.extend_from_slice(&self.count.to_le_bytes());
            end.extend_from_slice(&cd_size.to_le_bytes());
            end.extend_from_slice(&cd_offset.to_le_bytes());
            put32(&mut end, 0x0706_4B50);
            put32(&mut end, 0);
            end.extend_from_slice(&record_at.to_le_bytes());
            put32(&mut end, 1);
        }
        put32(&mut end, 0x0605_4B50);
        put16(&mut end, 0);
        put16(&mut end, 0);
        let n = if zip64 { 0xFFFF } else { self.count as u16 };
        put16(&mut end, n);
        put16(&mut end, n);
        put32(&mut end, if zip64 { U32_MAX as u32 } else { cd_size as u32 });
        put32(&mut end, if zip64 { U32_MAX as u32 } else { cd_offset as u32 });
        put16(&mut end, 0);
        self.put(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TABLE: [u32; 256] = crc_table();

fn crc_step(crc: u32, b: u8) -> u32 {
    CRC_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8)
}

fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |c, &b| crc_step(c, b))
}

struct Keys([u32; 3]);

impl Keys {
    fn new(password: &[u8]) -> Keys {
        let mut k = Keys([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            k.update(b);
        }
        k
    }

    fn update(&mut self, plain: u8) {
        let k = &mut self.0;
        k[0] = crc_step(k[0], plain);
        k[1] = k[1].wrapping_add(k[0] & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        k[2] = crc_step(k[2], (k[1] >> 24) as u8);
    }

    fn stream_byte(&self) -> u8 {
        let t = (self.0[2] | 2) & 0xFFFF;
        (t.wrapping_mul(t ^ 1) >> 8) as u8
    }

    fn encrypt(&mut self, plain: u8) -> u8 {
        let c = plain ^ self.stream_byte();
        self.update(plain);
        c
    }

    #[cfg(test)]
    fn decrypt(&mut self, cipher: u8) -> u8 {
        let p = cipher ^ self.stream_byte();
        self.update(p);
        p
    }
}

/// Unpredictable bytes for the encryption headers, from std's per-process
/// random hash keys (no extra dependency needed).
struct HeaderRng(RandomState, u64);

impl HeaderRng {
    fn new() -> Self {
        HeaderRng(RandomState::new(), 0)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let mut h = self.0.build_hasher();
            h.write_u64(self.1);
            self.1 += 1;
            chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
        }
    }
}

/// FILETIME to MS-DOS (time, date); 1980-01-01 when unknown or out of range.
fn dos_datetime(ft: u64) -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    const DEFAULT: (u16, u16) = (0, (1 << 5) | 1);
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let Some(t) = chrono::DateTime::from_timestamp(secs, 0).filter(|_| ft != 0) else {
        return DEFAULT;
    };
    if !(1980..=2107).contains(&t.year()) {
        return DEFAULT;
    }
    let time = (t.hour() << 11 | t.minute() << 5 | (t.second() / 2)) as u16;
    let date = ((t.year() as u32 - 1980) << 9 | t.month() << 5 | t.day()) as u16;
    (time, date)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mft::{u32_at, MftFile};
    use std::sync::atomic::AtomicUsize;

    /// Builds a 1024-byte FILE record for `readme.txt` holding `content` as
    /// resident `$DATA` plus a `Zone.Identifier` ADS, with valid fixups.
    pub(crate) fn fake_record(content: &[u8]) -> Vec<u8> {
        let attrs = [
            resident(0x10, "", 0, &std_info()),
            resident(0x30, "", 1, &file_name_attr("readme.txt", 3, content.len())),
            resident(0x80, "", 2, content),
            resident(0x80, "Zone.Identifier", 3, b"[ZoneTransfer]\r\nZoneId=3\r\n"),
        ];
        build_record(1, 1, 0, &attrs.concat())
    }

    pub(crate) fn resident(type_code: u32, name: &str, id: u16, content: &[u8]) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let content_off = (24 + name16.len()).next_multiple_of(8);
        let len = (content_off + content.len()).next_multiple_of(8);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[9] = name.encode_utf16().count() as u8;
        a[10..12].copy_from_slice(&24u16.to_le_bytes());
        a[14..16].copy_from_slice(&id.to_le_bytes());
        a[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[20..22].copy_from_slice(&(content_off as u16).to_le_bytes());
        a[24..24 + name16.len()].copy_from_slice(&name16);
        a[content_off..content_off + content.len()].copy_from_slice(content);
        a
    }

    /// `$STANDARD_INFORMATION` content with every time 2025-09-01 21:08:54.
    pub(crate) fn std_info() -> Vec<u8> {
        let ft: u64 = 0x01DC_1B84_9F82_04B6;
        let mut si = vec![0u8; 72];
        for i in 0..4 {
            si[i * 8..i * 8 + 8].copy_from_slice(&ft.to_le_bytes());
        }
        si[32] = 0x20; // archive
        si
    }

    /// `$FILE_NAME` content for `name` in the root folder.
    pub(crate) fn file_name_attr(name: &str, namespace: u8, size: usize) -> Vec<u8> {
        let mut f = vec![0u8; 66];
        f[0..8].copy_from_slice(&5u64.to_le_bytes()); // parent: root
        f[48..56].copy_from_slice(&(size as u64).to_le_bytes());
        f[64] = name.encode_utf16().count() as u8;
        f[65] = namespace;
        f.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        f
    }

    /// A 1024-byte FILE record holding `attrs`, with valid fixups. `base` is
    /// the base record reference of an extension record, 0 otherwise.
    pub(crate) fn build_record(sequence: u16, flags: u16, base: u64, attrs: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&48u16.to_le_bytes()); // update sequence offset
        r[6..8].copy_from_slice(&3u16.to_le_bytes()); // 1 + one per sector
        r[16..18].copy_from_slice(&sequence.to_le_bytes());
        r[18..20].copy_from_slice(&1u16.to_le_bytes()); // link count
        r[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attribute
        r[22..24].copy_from_slice(&flags.to_le_bytes());
        r[24..28].copy_from_slice(&((56 + attrs.len() + 8) as u32).to_le_bytes());
        r[28..32].copy_from_slice(&1024u32.to_le_bytes());
        r[32..40].copy_from_slice(&base.to_le_bytes());
        r[40..42].copy_from_slice(&8u16.to_le_bytes()); // next attribute id
        r[56..56 + attrs.len()].copy_from_slice(attrs);
        r[56 + attrs.len()..60 + attrs.len()].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Fixups: save each sector's last two bytes, stamp the check value.
        let usn = [0x07, 0x00];
        r[48..50].copy_from_slice(&usn);
        for (i, end) in [512usize, 1024].into_iter().enumerate() {
            let saved = [r[end - 2], r[end - 1]];
            r[50 + i * 2..52 + i * 2].copy_from_slice(&saved);
            r[end - 2..end].copy_from_slice(&usn);
        }
        r
    }

    /// Minimal reader for the archives written above: (name, plaintext).
    fn read_zip(zip: &[u8], password: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while u32_at(zip, pos) == 0x0403_4B50 {
            let crc = u32_at(zip, pos + 14);
            let stored = u32_at(zip, pos + 18) as usize;
            let size = u32_at(zip, pos + 22) as usize;
            let name_len = crate::mft::u16_at(zip, pos + 26) as usize;
            let name = String::from_utf8(zip[pos + 30..pos + 30 + name_len].to_vec()).unwrap();
            let body = &zip[pos + 30 + name_len..pos + 30 + name_len + stored];
            let mut keys = Keys::new(password);
            let plain: Vec<u8> = body.iter().map(|&b| keys.decrypt(b)).collect();
            assert_eq!(plain[11], (crc >> 24) as u8, "password check byte");
            let data = plain[12..].to_vec();
            assert_eq!(data.len(), size);
            assert_eq!(crc32(&data), crc);
            out.push((name, data));
            pos += 30 + name_len + stored;
        }
        assert_eq!(u32_at(zip, pos), 0x0201_4B50, "central directory follows");
        out
    }

    #[test]
    fn crc_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn extracts_resident_data_from_fake_record() {
        let content = b"Hello from a fake MFT record. Nothing to see here.\r\n";
        let rec = [Record::parse(&fake_record(content))];
        assert!(rec[0].is_valid() && rec[0].fixup_ok);
        assert_eq!(file_name(&rec).as_deref(), Some("readme.txt"));
        let s = streams(&rec);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].data, Some(&content[..]));
        assert_eq!(s[1].name, "Zone.Identifier");

        let zip = resident_zip(&rec, 42).expect("resident content");
        assert_eq!(zip_file_name(&rec, 42), "record_42_readme.txt.zip");
        let files = read_zip(&zip, PASSWORD.as_bytes());
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "readme.txt");
        assert_eq!(files[0].1, content);
        assert_eq!(files[1].0, "readme.txt_Zone.Identifier");
        assert_eq!(files[1].1, b"[ZoneTransfer]\r\nZoneId=3\r\n");
        // Ciphertext must not leak the plaintext.
        assert!(!zip.windows(5).any(|w| w == b"Hello"));
        // Timestamp comes from $SI modified: 2025-09-01 21:08:54.
        assert_eq!(dos_datetime(0x01DC_1B84_9F82_04B6), (21 << 11 | 8 << 5 | 27, 45 << 9 | 9 << 5 | 1));
    }

    #[test]
    fn nothing_to_extract_without_data() {
        let mut raw = fake_record(b"x");
        // End the attribute list right after $FN.
        let data_off = Record::parse(&raw).attributes[2].offset;
        raw[data_off..data_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(resident_zip(&[Record::parse(&raw)], 1).is_none());
    }

    #[test]
    fn extracts_from_extension_records() {
        let file_ref = |n: u64, seq: u16| n | (seq as u64) << 48;
        let base = |seq, flags| {
            let attrs = [
                resident(0x10, "", 0, &std_info()),
                resident(0x30, "", 1, &file_name_attr("NEWSAP~1.PNG", 2, 0)),
            ];
            build_record(seq, flags, 0, &attrs.concat())
        };
        let ext = |base: u64, name: &str, body: &[u8]| {
            let attrs = [
                resident(0x30, "", 0, &file_name_attr(name, 1, body.len())),
                resident(0x80, "", 1, body),
            ];
            build_record(1, 1, base, &attrs.concat())
        };
        let data = b"PNG data that ended up in an extension record";
        let mft = [
            fake_record(b"x"),
            // #1 holds only the 8.3 name; #2 has the long name and the data.
            base(3, 1),
            ext(file_ref(1, 3), "newsapp.png", data),
            // Left over from an earlier file in #1.
            ext(file_ref(1, 2), "old.txt", b"STALE"),
            // A deleted file: NTFS bumped #4's sequence number when it freed it.
            base(5, 0),
            ext(file_ref(4, 4), "gone.txt", b"deleted but still here"),
        ]
        .concat();
        let f = MftFile::load(mft, &AtomicUsize::new(0));

        // The base record and its extension record give the same file.
        for i in [1, 2] {
            let recs = f.file_records(i);
            assert_eq!(recs.len(), 2);
            assert_eq!(file_name(&recs).as_deref(), Some("newsapp.png"));
            assert_eq!(zip_file_name(&recs, 1), "record_1_newsapp.png.zip");
            let files = read_zip(&resident_zip(&recs, 1).unwrap(), PASSWORD.as_bytes());
            assert_eq!(files, [("newsapp.png".to_string(), data.to_vec())]);
        }
        assert_eq!(f.file_records(3).len(), 1);

        let deleted = f.file_records(4);
        assert_eq!(deleted.len(), 2);
        let files = read_zip(&resident_zip(&deleted, 4).unwrap(), PASSWORD.as_bytes());
        assert_eq!(files, [("gone.txt".to_string(), b"deleted but still here".to_vec())]);
    }

    /// Writes archives in every layout for checking with an external tool:
    /// `cargo test -- --ignored dump_zip_layouts`, then unzip them with the password.
    #[test]
    #[ignore]
    fn dump_zip_layouts() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 253) as u8).collect();
        for (name, limit) in [("plain", U32_MAX), ("zip64", 0)] {
            let mut z = ZipWriter::new(Vec::new(), PASSWORD.as_bytes());
            z.limit = limit;
            z.add("known.bin", 0x01DC_1B84_9F82_04B6, &data[..1000]).unwrap();
            z.add_stream("streamed.bin", 0x01DC_1B84_9F82_04B6, data.len() as u64, |e| {
                for c in data.chunks(65536) {
                    e.write(c)?;
                }
                Ok(())
            })
            .unwrap();
            let path = std::env::temp_dir().join(format!("sediment-{name}.zip"));
            std::fs::write(&path, z.finish().unwrap()).unwrap();
            println!("{}", path.display());
        }
    }

    /// Writes the fake record's archive for checking with an external tool, and
    /// the record itself as a one-record `$MFT`:
    /// `cargo test -- --ignored dump_fake_record_zip`.
    #[test]
    #[ignore]
    fn dump_fake_record_zip() {
        let rec = [Record::parse(&fake_record(b"Hello from a fake MFT record.\r\n"))];
        let path = std::env::temp_dir().join(zip_file_name(&rec, 42));
        std::fs::write(&path, resident_zip(&rec, 42).unwrap()).unwrap();
        println!("{}", path.display());
        // The same record as a one-record $MFT, to try the Extract button.
        let mft = std::env::temp_dir().join("fake_MFT");
        std::fs::write(&mft, fake_record(b"Hello from a fake MFT record.\r\n")).unwrap();
        println!("{}", mft.display());
    }
}
