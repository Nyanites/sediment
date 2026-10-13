//! Pulls resident `$DATA` streams out of an MFT record and packs them into a
//! ZIP encrypted with the password `infected`, the usual way of handing out
//! possibly malicious samples: antivirus leaves it alone and nobody runs the
//! content by double-clicking it. The encryption is traditional PKWARE
//! ("ZipCrypto"), which every unzip tool supports and which is weak on purpose
//! here: it is a safety wrapper, not confidentiality.
//!
//! Only resident content can be recovered: a non-resident stream lives in
//! clusters on the volume, which the `$MFT` alone does not contain.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use crate::mft::{self, AttrBody, Record, ATTR_DATA, ATTR_FILE_NAME, ATTR_STANDARD_INFORMATION};

pub const PASSWORD: &str = "infected";

/// A `$DATA` stream of a record and whether its bytes are in the record.
pub struct Stream<'a> {
    /// Empty for the unnamed (main) stream, otherwise the ADS name.
    pub name: &'a str,
    /// `Some` when the content is resident.
    pub data: Option<&'a [u8]>,
}

pub fn streams(rec: &Record) -> Vec<Stream<'_>> {
    rec.attributes
        .iter()
        .filter(|a| a.type_code == ATTR_DATA)
        // A non-resident stream split over several records is listed once.
        .filter(|a| !matches!(a.body, AttrBody::NonResident { start_vcn, .. } if start_vcn != 0))
        .map(|a| Stream {
            name: &a.name,
            data: a.resident_content(&rec.data),
        })
        .collect()
}

/// The record's preferred file name (Win32 over POSIX over DOS 8.3).
pub fn file_name(rec: &Record) -> Option<String> {
    rec.attributes
        .iter()
        .filter(|a| a.type_code == ATTR_FILE_NAME)
        .filter_map(|a| a.file_name(&rec.data))
        .max_by_key(|f| mft::namespace_rank(f.namespace))
        .map(|f| f.name)
}

/// Builds the encrypted archive of every resident `$DATA` stream in `rec`.
/// Returns `None` when there is nothing resident to extract.
pub fn resident_zip(rec: &Record, record_no: usize) -> Option<Vec<u8>> {
    let base = file_name(rec)
        .map(|n| sanitize(&n))
        .unwrap_or_else(|| format!("record_{record_no}"));
    let modified = rec
        .attributes
        .iter()
        .find_map(|a| (a.type_code == ATTR_STANDARD_INFORMATION).then(|| a.standard_info(&rec.data))?)
        .map_or(0, |si| si.times.modified);
    let files: Vec<ZipFile> = streams(rec)
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

/// Default name offered for the archive.
pub fn zip_file_name(rec: &Record, record_no: usize) -> String {
    match file_name(rec) {
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

pub struct ZipFile<'a> {
    pub name: String,
    pub data: &'a [u8],
    /// FILETIME; 0 for unknown.
    pub modified: u64,
}

/// Writes a ZIP of stored (uncompressed) entries, each encrypted with
/// traditional PKWARE encryption (APPNOTE 6.1).
pub fn encrypted_zip(files: &[ZipFile], password: &[u8]) -> Vec<u8> {
    const FLAGS: u16 = 0x0001 | 0x0800; // encrypted, UTF-8 names
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut rng = HeaderRng::new();

    for f in files {
        let crc = crc32(f.data);
        let (time, date) = dos_datetime(f.modified);
        let name = f.name.as_bytes();
        let stored = f.data.len() as u32 + 12;
        let offset = out.len() as u32;

        let mut common = Vec::new();
        put16(&mut common, 20); // version needed
        put16(&mut common, FLAGS);
        put16(&mut common, 0); // stored
        put16(&mut common, time);
        put16(&mut common, date);
        put32(&mut common, crc);
        put32(&mut common, stored);
        put32(&mut common, f.data.len() as u32);
        put16(&mut common, name.len() as u16);
        put16(&mut common, 0); // extra length

        put32(&mut out, 0x0403_4B50);
        out.extend_from_slice(&common);
        out.extend_from_slice(name);

        // 12-byte encryption header: random, last byte checks the password.
        let mut keys = Keys::new(password);
        let mut header = [0u8; 12];
        rng.fill(&mut header[..11]);
        header[11] = (crc >> 24) as u8;
        out.extend(header.iter().map(|&b| keys.encrypt(b)));
        out.extend(f.data.iter().map(|&b| keys.encrypt(b)));

        put32(&mut central, 0x0201_4B50);
        put16(&mut central, 20); // version made by
        central.extend_from_slice(&common);
        put16(&mut central, 0); // comment length
        put16(&mut central, 0); // disk
        put16(&mut central, 0); // internal attributes
        put32(&mut central, 0); // external attributes
        put32(&mut central, offset);
        central.extend_from_slice(name);
    }

    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    put32(&mut out, 0x0605_4B50);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, files.len() as u16);
    put16(&mut out, files.len() as u16);
    put32(&mut out, central.len() as u32);
    put32(&mut out, cd_offset);
    put16(&mut out, 0);
    out
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
    use crate::mft::u32_at;

    /// Builds a 1024-byte FILE record for `readme.txt` holding `content` as
    /// resident `$DATA` plus a `Zone.Identifier` ADS, with valid fixups.
    pub(crate) fn fake_record(content: &[u8]) -> Vec<u8> {
        fn resident(type_code: u32, name: &str, id: u16, content: &[u8]) -> Vec<u8> {
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
        let ft: u64 = 0x01DC_1B84_9F82_04B6; // 2025-09-01 21:08:54
        let mut si = vec![0u8; 72];
        for i in 0..4 {
            si[i * 8..i * 8 + 8].copy_from_slice(&ft.to_le_bytes());
        }
        si[32] = 0x20; // archive
        let name: Vec<u8> = "readme.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut fname = vec![0u8; 66];
        fname[0..8].copy_from_slice(&5u64.to_le_bytes()); // parent: root
        fname[48..56].copy_from_slice(&(content.len() as u64).to_le_bytes());
        fname[64] = 10;
        fname[65] = 3; // Win32 & DOS
        fname.extend_from_slice(&name);

        let mut attrs = Vec::new();
        attrs.extend(resident(0x10, "", 0, &si));
        attrs.extend(resident(0x30, "", 1, &fname));
        attrs.extend(resident(0x80, "", 2, content));
        attrs.extend(resident(0x80, "Zone.Identifier", 3, b"[ZoneTransfer]\r\nZoneId=3\r\n"));
        attrs.extend(0xFFFF_FFFFu32.to_le_bytes());
        attrs.extend([0u8; 4]);

        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&48u16.to_le_bytes()); // update sequence offset
        r[6..8].copy_from_slice(&3u16.to_le_bytes()); // 1 + one per sector
        r[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence
        r[18..20].copy_from_slice(&1u16.to_le_bytes()); // link count
        r[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attribute
        r[22..24].copy_from_slice(&1u16.to_le_bytes()); // in use
        r[24..28].copy_from_slice(&((56 + attrs.len()) as u32).to_le_bytes());
        r[28..32].copy_from_slice(&1024u32.to_le_bytes());
        r[40..42].copy_from_slice(&4u16.to_le_bytes()); // next attribute id
        r[56..56 + attrs.len()].copy_from_slice(&attrs);
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
        let rec = Record::parse(&fake_record(content));
        assert!(rec.is_valid() && rec.fixup_ok);
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
        let rec = Record::parse(&raw);
        assert!(resident_zip(&rec, 1).is_none());
    }

    /// Writes the fake record's archive for checking with an external tool, and
    /// the record itself as a one-record `$MFT`:
    /// `cargo test -- --ignored dump_fake_record_zip`.
    #[test]
    #[ignore]
    fn dump_fake_record_zip() {
        let rec = Record::parse(&fake_record(b"Hello from a fake MFT record.\r\n"));
        let path = std::env::temp_dir().join(zip_file_name(&rec, 42));
        std::fs::write(&path, resident_zip(&rec, 42).unwrap()).unwrap();
        println!("{}", path.display());
        // The same record as a one-record $MFT, to try the Extract button.
        let mft = std::env::temp_dir().join("fake_MFT");
        std::fs::write(&mft, fake_record(b"Hello from a fake MFT record.
")).unwrap();
        println!("{}", mft.display());
    }
}
