//! Minimal NTFS `$MFT` parser: FILE record headers, update-sequence fixups,
//! and the attributes needed for a timeline/browse view.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const ROOT_RECORD: usize = 5;

pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_END: u32 = 0xFFFF_FFFF;

pub const RECORD_IN_USE: u16 = 0x0001;
pub const RECORD_IS_DIRECTORY: u16 = 0x0002;

// ---------------------------------------------------------------- helpers

/// `len` bytes at `off`, or `None` when out of range (including overflow).
fn bytes_at(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(len)?)
}

pub(crate) fn u16_at(b: &[u8], off: usize) -> u16 {
    bytes_at(b, off, 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

pub(crate) fn u32_at(b: &[u8], off: usize) -> u32 {
    bytes_at(b, off, 4).map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub(crate) fn u64_at(b: &[u8], off: usize) -> u64 {
    bytes_at(b, off, 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

pub(crate) fn utf16_at(b: &[u8], off: usize, chars: usize) -> String {
    let Some(bytes) = chars.checked_mul(2).and_then(|n| bytes_at(b, off, n)) else {
        return String::new();
    };
    let units: Vec<u16> = bytes
        .as_chunks::<2>().0.iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Splits a 64-bit NTFS file reference into (record number, sequence number).
pub fn split_ref(r: u64) -> (u64, u16) {
    (r & 0x0000_FFFF_FFFF_FFFF, (r >> 48) as u16)
}

/// Formats a Windows FILETIME (100ns ticks since 1601-01-01 UTC) as
/// `YYYY-MM-DD HH:MM:SS.fffffff`.
pub fn format_filetime(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    const TICKS_PER_SEC: u64 = 10_000_000;
    const SECS_1601_TO_1970: i64 = 11_644_473_600;
    let secs = (ft / TICKS_PER_SEC) as i64 - SECS_1601_TO_1970;
    let frac = ft % TICKS_PER_SEC;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{frac:07}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's days-since-epoch to civil date algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn attr_type_name(t: u32) -> &'static str {
    match t {
        0x10 => "$STANDARD_INFORMATION",
        0x20 => "$ATTRIBUTE_LIST",
        0x30 => "$FILE_NAME",
        0x40 => "$OBJECT_ID",
        0x50 => "$SECURITY_DESCRIPTOR",
        0x60 => "$VOLUME_NAME",
        0x70 => "$VOLUME_INFORMATION",
        0x80 => "$DATA",
        0x90 => "$INDEX_ROOT",
        0xA0 => "$INDEX_ALLOCATION",
        0xB0 => "$BITMAP",
        0xC0 => "$REPARSE_POINT",
        0xD0 => "$EA_INFORMATION",
        0xE0 => "$EA",
        0x100 => "$LOGGED_UTILITY_STREAM",
        _ => "(unknown)",
    }
}

const FILE_ATTR_FLAGS: &[(u32, char, &str)] = &[
    (0x0001, 'R', "ReadOnly"),
    (0x0002, 'H', "Hidden"),
    (0x0004, 'S', "System"),
    (0x0010, 'D', "Directory"),
    (0x0020, 'A', "Archive"),
    (0x0040, 'V', "Device"),
    (0x0080, 'N', "Normal"),
    (0x0100, 'T', "Temporary"),
    (0x0200, 'P', "SparseFile"),
    (0x0400, 'L', "ReparsePoint"),
    (0x0800, 'C', "Compressed"),
    (0x1000, 'O', "Offline"),
    (0x2000, 'I', "NotContentIndexed"),
    (0x4000, 'E', "Encrypted"),
    (0x1000_0000, 'D', "Directory(FN)"),
    (0x2000_0000, 'X', "IndexView"),
];

/// Compact letter form, e.g. `HSA`.
pub fn file_attr_short(a: u32) -> String {
    FILE_ATTR_FLAGS
        .iter()
        .filter(|(bit, _, _)| a & bit != 0 && *bit != 0x1000_0000)
        .map(|(_, c, _)| *c)
        .collect()
}

pub fn file_attr_long(a: u32) -> String {
    let names: Vec<&str> = FILE_ATTR_FLAGS
        .iter()
        .filter(|(bit, _, _)| a & bit != 0)
        .map(|(_, _, n)| *n)
        .collect();
    if names.is_empty() {
        format!("0x{a:08X}")
    } else {
        format!("0x{a:08X} ({})", names.join(" | "))
    }
}

pub fn namespace_name(ns: u8) -> &'static str {
    match ns {
        0 => "POSIX",
        1 => "Win32",
        2 => "DOS",
        3 => "Win32 & DOS",
        _ => "?",
    }
}

// ---------------------------------------------------------------- records

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
}

impl Timestamps {
    fn read(b: &[u8], off: usize) -> Self {
        Self {
            created: u64_at(b, off),
            modified: u64_at(b, off + 8),
            mft_modified: u64_at(b, off + 16),
            accessed: u64_at(b, off + 24),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StandardInfo {
    pub times: Timestamps,
    pub file_attributes: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub usn: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct FileName {
    pub parent_record: u64,
    pub parent_seq: u16,
    pub times: Timestamps,
    pub alloc_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub namespace: u8,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct DataRun {
    /// `None` for a sparse run.
    pub lcn: Option<i64>,
    pub length: u64,
}

#[derive(Clone, Debug)]
pub enum AttrBody {
    Resident {
        content_offset: usize,
        content_len: usize,
    },
    NonResident {
        start_vcn: u64,
        last_vcn: u64,
        alloc_size: u64,
        real_size: u64,
        init_size: u64,
        runs: Vec<DataRun>,
    },
}

#[derive(Clone, Debug)]
pub struct Attribute {
    pub type_code: u32,
    pub offset: usize,
    pub length: usize,
    pub name: String,
    pub flags: u16,
    pub id: u16,
    pub body: AttrBody,
}

impl Attribute {
    /// Logical size of the attribute's content.
    pub fn data_size(&self) -> u64 {
        match self.body {
            AttrBody::Resident { content_len, .. } => content_len as u64,
            AttrBody::NonResident { real_size, .. } => real_size,
        }
    }

    pub fn resident_content<'a>(&self, rec: &'a [u8]) -> Option<&'a [u8]> {
        match self.body {
            AttrBody::Resident {
                content_offset,
                content_len,
            } => bytes_at(rec, content_offset, content_len),
            AttrBody::NonResident { .. } => None,
        }
    }

    pub fn standard_info(&self, rec: &[u8]) -> Option<StandardInfo> {
        if self.type_code != ATTR_STANDARD_INFORMATION {
            return None;
        }
        let c = self.resident_content(rec)?;
        if c.len() < 36 {
            return None;
        }
        let ext = c.len() >= 72;
        Some(StandardInfo {
            times: Timestamps::read(c, 0),
            file_attributes: u32_at(c, 32),
            owner_id: ext.then(|| u32_at(c, 48)),
            security_id: ext.then(|| u32_at(c, 52)),
            usn: ext.then(|| u64_at(c, 64)),
        })
    }

    pub fn file_name(&self, rec: &[u8]) -> Option<FileName> {
        if self.type_code != ATTR_FILE_NAME {
            return None;
        }
        let c = self.resident_content(rec)?;
        if c.len() < 66 {
            return None;
        }
        let (parent_record, parent_seq) = split_ref(u64_at(c, 0));
        Some(FileName {
            parent_record,
            parent_seq,
            times: Timestamps::read(c, 8),
            alloc_size: u64_at(c, 40),
            real_size: u64_at(c, 48),
            flags: u32_at(c, 56),
            namespace: c[65],
            name: utf16_at(c, 66, c[64] as usize),
        })
    }
}

/// A single MFT record after fixups, with its attributes decoded.
#[derive(Clone)]
pub struct Record {
    pub data: Vec<u8>,
    pub signature: [u8; 4],
    pub fixup_ok: bool,
    pub lsn: u64,
    pub sequence: u16,
    pub link_count: u16,
    pub flags: u16,
    pub used_size: u32,
    pub alloc_size: u32,
    pub base_record: u64,
    pub base_seq: u16,
    pub next_attr_id: u16,
    pub record_number_field: u32,
    pub attributes: Vec<Attribute>,
}

impl Record {
    pub fn is_valid(&self) -> bool {
        &self.signature == b"FILE"
    }

    pub fn parse(raw: &[u8]) -> Record {
        let mut data = raw.to_vec();
        let signature = raw.first_chunk().copied().unwrap_or_default();
        let mut rec = Record {
            signature,
            fixup_ok: false,
            lsn: u64_at(&data, 8),
            sequence: u16_at(&data, 16),
            link_count: u16_at(&data, 18),
            flags: u16_at(&data, 22),
            used_size: u32_at(&data, 24),
            alloc_size: u32_at(&data, 28),
            base_record: 0,
            base_seq: 0,
            next_attr_id: u16_at(&data, 40),
            record_number_field: u32_at(&data, 44),
            attributes: Vec::new(),
            data: Vec::new(),
        };
        (rec.base_record, rec.base_seq) = split_ref(u64_at(&data, 32));

        if rec.is_valid() {
            rec.fixup_ok = apply_fixup(&mut data);
            rec.attributes = parse_attributes(&data);
        }
        rec.data = data;
        rec
    }

    pub fn in_use(&self) -> bool {
        self.flags & RECORD_IN_USE != 0
    }

    pub fn is_dir(&self) -> bool {
        self.flags & RECORD_IS_DIRECTORY != 0
    }
}

/// Replaces the last two bytes of every sector with the saved values from the
/// update sequence array. Returns false if any sector failed its check.
fn apply_fixup(buf: &mut [u8]) -> bool {
    let usa_off = u16_at(buf, 4) as usize;
    let usa_count = u16_at(buf, 6) as usize;
    if usa_count < 2 || usa_off + usa_count * 2 > buf.len() {
        return usa_count == 0;
    }
    let stride = buf.len() / (usa_count - 1);
    let usn = [buf[usa_off], buf[usa_off + 1]];
    let mut ok = true;
    for i in 1..usa_count {
        let pos = i * stride - 2;
        if pos + 2 > buf.len() {
            return false;
        }
        if buf[pos..pos + 2] != usn {
            ok = false;
        }
        buf[pos] = buf[usa_off + i * 2];
        buf[pos + 1] = buf[usa_off + i * 2 + 1];
    }
    ok
}

fn parse_attributes(buf: &[u8]) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut off = u16_at(buf, 20) as usize;
    let limit = (u32_at(buf, 24) as usize).min(buf.len());

    while off + 16 <= limit {
        let type_code = u32_at(buf, off);
        if type_code == ATTR_END {
            break;
        }
        let length = u32_at(buf, off + 4) as usize;
        if length < 16 || off + length > limit {
            break;
        }
        let a = &buf[off..off + length];
        let non_resident = a[8] != 0;
        let name_len = a[9] as usize;
        let name_off = u16_at(a, 10) as usize;
        let name = utf16_at(a, name_off, name_len);

        let body = if non_resident {
            let runs_off = u16_at(a, 32) as usize;
            AttrBody::NonResident {
                start_vcn: u64_at(a, 16),
                last_vcn: u64_at(a, 24),
                alloc_size: u64_at(a, 40),
                real_size: u64_at(a, 48),
                init_size: u64_at(a, 56),
                runs: if runs_off < a.len() {
                    decode_runs(&a[runs_off..])
                } else {
                    Vec::new()
                },
            }
        } else {
            let content_len = u32_at(a, 16) as usize;
            let content_off = u16_at(a, 20) as usize;
            let content_len = content_len.min(length.saturating_sub(content_off));
            AttrBody::Resident {
                content_offset: off + content_off,
                content_len,
            }
        };

        attrs.push(Attribute {
            type_code,
            offset: off,
            length,
            name,
            flags: u16_at(a, 12),
            id: u16_at(a, 14),
            body,
        });
        off += length;
    }
    attrs
}

fn decode_runs(b: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut lcn: i64 = 0;
    while pos < b.len() {
        let header = b[pos];
        if header == 0 {
            break;
        }
        let len_sz = (header & 0x0F) as usize;
        let off_sz = (header >> 4) as usize;
        pos += 1;
        if len_sz == 0 || len_sz > 8 || off_sz > 8 || pos + len_sz + off_sz > b.len() {
            break;
        }
        let mut length: u64 = 0;
        for i in 0..len_sz {
            length |= (b[pos + i] as u64) << (8 * i);
        }
        pos += len_sz;
        let run_lcn = if off_sz == 0 {
            None
        } else {
            let mut delta: i64 = 0;
            for i in 0..off_sz {
                delta |= (b[pos + i] as i64) << (8 * i);
            }
            // sign-extend
            let shift = 64 - 8 * off_sz as u32;
            delta = (delta << shift) >> shift;
            lcn = lcn.wrapping_add(delta);
            Some(lcn)
        };
        pos += off_sz;
        runs.push(DataRun {
            lcn: run_lcn,
            length,
        });
    }
    runs
}

// ---------------------------------------------------------------- table rows

/// One row of the browse table; a flattened summary of a record.
#[derive(Clone, Default)]
pub struct Entry {
    pub record: u64,
    pub sequence: u16,
    pub valid: bool,
    pub in_use: bool,
    pub is_dir: bool,
    pub base_record: u64,
    pub base_seq: u16,
    pub name: String,
    pub parent_record: u64,
    pub parent_seq: u16,
    /// Parent record after sequence validation; `None` for root, nameless
    /// records and orphans.
    pub parent_idx: Option<u32>,
    pub path: String,
    pub size: u64,
    pub file_attributes: u32,
    pub si: Timestamps,
    pub fn_times: Timestamps,
    pub has_fn: bool,
    pub ads: Vec<String>,
    /// Number of USN journal entries for this record number (set by the app
    /// when a journal is loaded alongside).
    pub journal_count: u32,
    /// Additional hard links (non-DOS `$FILE_NAME`s other than the primary).
    pub links: Vec<HardLink>,
    pub name_lc: String,
    pub path_lc: String,
}

#[derive(Clone, Default)]
pub struct HardLink {
    pub name: String,
    pub parent_record: u64,
    pub parent_seq: u16,
    pub parent_idx: Option<u32>,
    pub path: String,
}

impl Entry {
    /// Validated parents of every name this record has.
    pub fn parent_indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.parent_idx
            .into_iter()
            .chain(self.links.iter().filter_map(|l| l.parent_idx))
    }

    /// $SI creation earlier than $FN creation is a common timestomping tell.
    pub fn timestomp_suspect(&self) -> bool {
        self.has_fn && self.si.created != 0 && self.si.created < self.fn_times.created
    }
}

pub(crate) fn namespace_rank(ns: u8) -> u8 {
    match ns {
        1 | 3 => 3, // Win32
        0 => 2,     // POSIX
        _ => 1,     // DOS 8.3
    }
}

fn summarize(index: u64, rec: &Record) -> Entry {
    let mut e = Entry {
        record: index,
        sequence: rec.sequence,
        valid: rec.is_valid(),
        in_use: rec.in_use(),
        is_dir: rec.is_dir(),
        base_record: rec.base_record,
        base_seq: rec.base_seq,
        ..Default::default()
    };
    let mut best_ns = 0u8;
    for a in &rec.attributes {
        match a.type_code {
            ATTR_STANDARD_INFORMATION => {
                if let Some(si) = a.standard_info(&rec.data) {
                    e.si = si.times;
                    e.file_attributes = si.file_attributes;
                }
            }
            ATTR_FILE_NAME => {
                if let Some(f) = a.file_name(&rec.data) {
                    let rank = namespace_rank(f.namespace);
                    if f.namespace != 2 {
                        e.links.push(HardLink {
                            name: f.name.clone(),
                            parent_record: f.parent_record,
                            parent_seq: f.parent_seq,
                            ..Default::default()
                        });
                    }
                    if rank > best_ns {
                        best_ns = rank;
                        e.has_fn = true;
                        e.name = f.name;
                        e.parent_record = f.parent_record;
                        e.parent_seq = f.parent_seq;
                        e.fn_times = f.times;
                    }
                }
            }
            ATTR_DATA => {
                if a.name.is_empty() {
                    if let AttrBody::NonResident { start_vcn: 0, .. } | AttrBody::Resident { .. } =
                        a.body
                    {
                        e.size = a.data_size();
                    }
                } else if !e.ads.contains(&a.name) {
                    e.ads.push(a.name.clone());
                }
            }
            _ => {}
        }
    }
    e.drop_primary_link();
    e
}

impl Entry {
    fn drop_primary_link(&mut self) {
        let (p, n) = (self.parent_record, std::mem::take(&mut self.name));
        self.links.retain(|l| !(l.parent_record == p && l.name == n));
        self.name = n;
    }
}

pub struct MftFile {
    pub raw: Vec<u8>,
    pub record_size: usize,
    pub entries: Vec<Entry>,
    /// Child record numbers per record, directories first, then by name.
    pub children: Vec<Vec<u32>>,
    /// Number of child directories per record (drives tree expanders).
    pub subdir_count: Vec<u32>,
    /// Named base records whose parent could not be resolved.
    pub orphans: Vec<u32>,
    /// Extension records per base record, for files whose attributes did
    /// not fit in one record.
    pub extensions: HashMap<u32, Vec<u32>>,
}

impl MftFile {
    pub fn record_count(raw_len: usize, record_size: usize) -> usize {
        raw_len / record_size
    }

    /// Picks the record size from the first FILE header, defaulting to 1024.
    pub fn detect_record_size(raw: &[u8]) -> usize {
        if raw.len() >= 32 && &raw[0..4] == b"FILE" {
            let s = u32_at(raw, 28) as usize;
            if s.is_power_of_two() && (256..=65536).contains(&s) {
                return s;
            }
        }
        1024
    }

    /// Empty when `index` is past the end of the file.
    pub fn record_bytes(&self, index: usize) -> &[u8] {
        index
            .checked_mul(self.record_size)
            .and_then(|start| bytes_at(&self.raw, start, self.record_size))
            .unwrap_or_default()
    }

    pub fn parse_record(&self, index: usize) -> Record {
        Record::parse(self.record_bytes(index))
    }

    /// The record numbers that make up the file at `index`: its base record
    /// first, then the extension records that belong to it. An extension
    /// record's index gives the same set.
    pub fn file_record_numbers(&self, index: usize) -> Vec<usize> {
        let Some(e) = self.entries.get(index) else {
            return Vec::new();
        };
        let base = match self.entries.get(e.base_record as usize) {
            _ if e.base_record == 0 => index,
            Some(b) if extends(b, e) => e.base_record as usize,
            // An orphaned extension record stands on its own.
            _ => return vec![index],
        };
        let b = &self.entries[base];
        let mut nums = vec![base];
        nums.extend(
            self.extensions
                .get(&(base as u32))
                .into_iter()
                .flatten()
                .map(|&x| x as usize)
                .filter(|&x| extends(b, &self.entries[x])),
        );
        nums
    }

    /// The parsed records of `file_record_numbers(index)`.
    pub fn file_records(&self, index: usize) -> Vec<Record> {
        self.file_record_numbers(index).into_iter().map(|i| self.parse_record(i)).collect()
    }

    pub fn load(raw: Vec<u8>, progress: &AtomicUsize) -> MftFile {
        let record_size = Self::detect_record_size(&raw);
        let count = Self::record_count(raw.len(), record_size);
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let rec = Record::parse(&raw[i * record_size..(i + 1) * record_size]);
            entries.push(summarize(i as u64, &rec));
            if i % 4096 == 0 {
                progress.store(i, Ordering::Relaxed);
            }
        }
        merge_extension_records(&mut entries);
        let mut extensions: HashMap<u32, Vec<u32>> = HashMap::new();
        for e in &entries {
            if e.valid && e.base_record != 0 && (e.base_record as usize) < entries.len() {
                extensions.entry(e.base_record as u32).or_default().push(e.record as u32);
            }
        }
        resolve_parents(&mut entries);
        build_paths(&mut entries);
        for e in &mut entries {
            e.name_lc = e.name.to_lowercase();
            e.path_lc = e.path.to_lowercase();
        }
        let (children, subdir_count, orphans) = build_tree(&entries);
        progress.store(count, Ordering::Relaxed);
        MftFile {
            raw,
            record_size,
            entries,
            children,
            subdir_count,
            orphans,
            extensions,
        }
    }
}

/// Whether `ext` is an extension record of `base`. NTFS bumps a record's
/// sequence number when it frees it, so a deleted file's extension records
/// refer to the number before that.
fn extends(base: &Entry, ext: &Entry) -> bool {
    ext.valid
        && ext.base_record == base.record
        && (ext.base_seq == base.sequence
            || (!base.in_use && ext.base_seq == base.sequence.wrapping_sub(1)))
}

/// Large files spill attributes into extension records; fold the useful
/// pieces back into the base record's row.
fn merge_extension_records(entries: &mut [Entry]) {
    for i in 0..entries.len() {
        let base = entries[i].base_record as usize;
        if base == 0 || base >= entries.len() || !entries[i].valid {
            continue;
        }
        let ext = entries[i].clone();
        let b = &mut entries[base];
        if ext.has_fn && !b.has_fn {
            b.has_fn = true;
            b.name = ext.name;
            b.parent_record = ext.parent_record;
            b.parent_seq = ext.parent_seq;
            b.fn_times = ext.fn_times;
        } else if ext.has_fn {
            b.links.push(HardLink {
                name: ext.name,
                parent_record: ext.parent_record,
                parent_seq: ext.parent_seq,
                ..Default::default()
            });
        }
        if b.size == 0 && ext.size != 0 {
            b.size = ext.size;
        }
        for s in ext.ads {
            if !b.ads.contains(&s) {
                b.ads.push(s);
            }
        }
        for l in ext.links {
            if !b.links.iter().any(|x| x.parent_record == l.parent_record && x.name == l.name) {
                b.links.push(l);
            }
        }
        b.drop_primary_link();
    }
}

/// Validates a `$FILE_NAME` parent reference against the parent's record.
fn resolve_parent(entries: &[Entry], child: usize, record: u64, seq: u16) -> Option<u32> {
    let p = record as usize;
    if p >= entries.len() || p == child {
        return None;
    }
    let parent = &entries[p];
    // A deleted parent has its sequence bumped by one.
    let seq_ok = parent.sequence == seq
        || (!parent.in_use && parent.sequence == seq.wrapping_add(1));
    (seq_ok && parent.has_fn && parent.is_dir).then_some(p as u32)
}

fn resolve_parents(entries: &mut [Entry]) {
    for i in 0..entries.len() {
        let e = &entries[i];
        if !is_tree_node(e) || i == ROOT_RECORD {
            continue;
        }
        let primary = resolve_parent(entries, i, e.parent_record, e.parent_seq);
        let links: Vec<Option<u32>> = e
            .links
            .iter()
            .map(|l| resolve_parent(entries, i, l.parent_record, l.parent_seq))
            .collect();
        let e = &mut entries[i];
        e.parent_idx = primary;
        for (l, p) in e.links.iter_mut().zip(links) {
            l.parent_idx = p;
        }
    }
}

fn is_tree_node(e: &Entry) -> bool {
    e.valid && e.has_fn && e.base_record == 0
}

fn build_tree(entries: &[Entry]) -> (Vec<Vec<u32>>, Vec<u32>, Vec<u32>) {
    let n = entries.len();
    let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut subdirs = vec![0u32; n];
    let mut orphans = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if !is_tree_node(e) || i == ROOT_RECORD {
            continue;
        }
        if e.parent_idx.is_none() {
            orphans.push(i as u32);
        }
        let mut seen: Vec<u32> = Vec::new();
        for p in e.parent_indices() {
            if seen.contains(&p) {
                continue;
            }
            seen.push(p);
            children[p as usize].push(i as u32);
            if e.is_dir {
                subdirs[p as usize] += 1;
            }
        }
    }
    let order = |a: &u32, b: &u32| {
        let (ea, eb) = (&entries[*a as usize], &entries[*b as usize]);
        eb.is_dir
            .cmp(&ea.is_dir)
            .then_with(|| ea.name_lc.cmp(&eb.name_lc))
            .then(a.cmp(b))
    };
    for c in &mut children {
        c.sort_by(order);
    }
    orphans.sort_by(order);
    (children, subdirs, orphans)
}

/// Longest directory path kept, in bytes; anything below it restarts from
/// `\[Too long]`, so a crafted directory chain cannot make every row hold
/// megabytes.
const MAX_PATH_BYTES: usize = 8 * 1024;

/// Appends `name` to the directory path `base`. A `\` inside a name (never
/// valid on NTFS) becomes U+FF3C (fullwidth reverse solidus) so it cannot
/// fake extra path components.
pub(crate) fn join_path(base: &str, name: &str) -> String {
    let base = if base.len() > MAX_PATH_BYTES { "\\[Too long]" } else { base };
    let mut s = String::with_capacity(base.len() + name.len() + 1);
    s.push_str(base);
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s.extend(name.chars().map(|c| if c == '\\' { '\u{FF3C}' } else { c }));
    s
}

fn build_paths(entries: &mut [Entry]) {
    let n = entries.len();
    let mut paths: Vec<Option<String>> = vec![None; n];
    if n > ROOT_RECORD {
        paths[ROOT_RECORD] = Some("\\".to_string());
    }

    let mut chain = Vec::new();
    for i in 0..n {
        if paths[i].is_some() {
            continue;
        }
        if !entries[i].has_fn || entries[i].base_record != 0 {
            paths[i] = Some(String::new());
            continue;
        }
        chain.clear();
        let mut cur = i;
        let base = loop {
            if let Some(p) = &paths[cur] {
                break p.clone();
            }
            chain.push(cur);
            let Some(p) = entries[cur].parent_idx.map(|p| p as usize) else {
                break "\\[Orphan]".to_string();
            };
            if chain.contains(&p) || chain.len() > 2048 {
                break "\\[Loop]".to_string();
            }
            cur = p;
        };
        let mut s = base;
        for &idx in chain.iter().rev() {
            s = join_path(&s, &entries[idx].name);
            paths[idx] = Some(s.clone());
        }
    }
    for e in entries.iter_mut() {
        for l in &mut e.links {
            let base = l
                .parent_idx
                .and_then(|p| paths[p as usize].as_deref())
                .unwrap_or("\\[Orphan]");
            l.path = join_path(base, &l.name);
        }
    }
    for (e, p) in entries.iter_mut().zip(paths) {
        e.path = p.unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_mft() {
        let Ok(raw) = std::fs::read("samples/$MFT") else { return };
        let f = MftFile::load(raw, &AtomicUsize::new(0));
        let valid = f.entries.iter().filter(|e| e.valid).count();
        let bad_fixup = (0..f.entries.len())
            .filter(|&i| f.entries[i].valid && !f.parse_record(i).fixup_ok)
            .count();
        let orphans = f.entries.iter().filter(|e| e.path.starts_with(r"\[")).count();
        println!("records={} valid={valid} bad_fixup={bad_fixup} orphans={orphans}", f.entries.len());
        for i in [0usize, 5, 6, 11, 40, 1000, 50000, 100000] {
            let e = &f.entries[i.min(f.entries.len() - 1)];
            println!(
                "#{} {:?} dir={} size={} si_c={} path={}",
                e.record, e.name, e.is_dir, e.size, format_filetime(e.si.created), e.path
            );
        }
        let links = f.entries.iter().filter(|e| !e.links.is_empty()).count();
        println!("records with extra hard links={links} top-level orphans={}", f.orphans.len());
        for p in [r"\windows", r"\windows\system32"] {
            if let Some(e) = f.entries.iter().find(|e| e.path_lc == p && e.is_dir) {
                println!(
                    "{p}: {} children ({} subdirs)",
                    f.children[e.record as usize].len(),
                    f.subdir_count[e.record as usize]
                );
            }
        }
        assert_eq!(f.entries[0].name, "$MFT");
        assert_eq!(f.entries[5].path, "\\");
    }

    #[test]
    fn filetime_format() {
        assert_eq!(format_filetime(116444736000000000), "1970-01-01 00:00:00.0000000");
        assert_eq!(format_filetime(0x01dc1b849f8204b6), "2025-09-01 21:08:54.0003510");
    }
}
