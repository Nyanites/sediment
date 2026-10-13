//! NTFS change journal: `$Extend\$UsnJrnl:$J` records and the `$Max` header.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::mft::{split_ref, u16_at, u32_at, u64_at, utf16_at};

const PAGE: usize = 4096;

const REASONS: &[(u32, &str)] = &[
    (0x0000_0001, "DataOverwrite"),
    (0x0000_0002, "DataExtend"),
    (0x0000_0004, "DataTruncation"),
    (0x0000_0010, "NamedDataOverwrite"),
    (0x0000_0020, "NamedDataExtend"),
    (0x0000_0040, "NamedDataTruncation"),
    (0x0000_0100, "FileCreate"),
    (0x0000_0200, "FileDelete"),
    (0x0000_0400, "EaChange"),
    (0x0000_0800, "SecurityChange"),
    (0x0000_1000, "RenameOldName"),
    (0x0000_2000, "RenameNewName"),
    (0x0000_4000, "IndexableChange"),
    (0x0000_8000, "BasicInfoChange"),
    (0x0001_0000, "HardLinkChange"),
    (0x0002_0000, "CompressionChange"),
    (0x0004_0000, "EncryptionChange"),
    (0x0008_0000, "ObjectIdChange"),
    (0x0010_0000, "ReparsePointChange"),
    (0x0020_0000, "StreamChange"),
    (0x0040_0000, "TransactedChange"),
    (0x0080_0000, "IntegrityChange"),
    (0x8000_0000, "Close"),
];

pub const REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
pub const REASON_RENAME: u32 = 0x0000_1000 | 0x0000_2000;
pub const REASON_DATA: u32 = 0x77; // (named) overwrite / extend / truncation
pub const REASON_BASIC_INFO: u32 = 0x0000_8000;
pub const REASON_STREAM_CHANGE: u32 = 0x0020_0000;

pub fn reason_text(r: u32) -> String {
    let names: Vec<&str> = REASONS
        .iter()
        .filter(|(bit, _)| r & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(" | ")
}

pub fn source_info_text(s: u32) -> String {
    let mut parts = Vec::new();
    if s & 0x1 != 0 {
        parts.push("DataManagement");
    }
    if s & 0x2 != 0 {
        parts.push("AuxiliaryData");
    }
    if s & 0x4 != 0 {
        parts.push("ReplicationManagement");
    }
    if s & 0x8 != 0 {
        parts.push("ClientReplicationManagement");
    }
    if parts.is_empty() {
        format!("0x{s:X}")
    } else {
        format!("0x{s:X} ({})", parts.join(" | "))
    }
}

#[derive(Clone, Default)]
pub struct UsnRecord {
    /// Byte offset of the record within the `$J` file.
    pub offset: u64,
    pub length: u32,
    pub major: u16,
    pub minor: u16,
    pub file_record: u64,
    pub file_seq: u16,
    pub parent_record: u64,
    pub parent_seq: u16,
    pub usn: i64,
    pub timestamp: u64,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub name: String,
    /// Full path resolved through a loaded `$MFT` (empty until resolved).
    pub path: String,
    pub name_lc: String,
    pub path_lc: String,
}

/// Validates and decodes one V2 or V3 record at `pos`.
fn parse_record(d: &[u8], pos: usize) -> Option<UsnRecord> {
    let len = u32_at(d, pos) as usize;
    let major = u16_at(d, pos + 4);
    if !len.is_multiple_of(8) || len > 0x1_0000 || pos + len > d.len() {
        return None;
    }
    let r = &d[pos..pos + len];
    // V2 uses 64-bit file references, V3 uses 128-bit ones.
    let (file_ref, parent_ref, rest) = match major {
        2 if len >= 0x40 => (u64_at(r, 8), u64_at(r, 16), 24),
        3 if len >= 0x50 => (u64_at(r, 8), u64_at(r, 24), 40),
        _ => return None,
    };
    let name_len = u16_at(r, rest + 32) as usize;
    let name_off = u16_at(r, rest + 34) as usize;
    if !name_len.is_multiple_of(2) || name_off < rest + 36 || name_off + name_len > len {
        return None;
    }
    let (file_record, file_seq) = split_ref(file_ref);
    let (parent_record, parent_seq) = split_ref(parent_ref);
    let name = utf16_at(r, name_off, name_len / 2);
    Some(UsnRecord {
        offset: pos as u64,
        length: len as u32,
        major,
        minor: u16_at(r, 6),
        file_record,
        file_seq,
        parent_record,
        parent_seq,
        usn: u64_at(r, rest) as i64,
        timestamp: u64_at(r, rest + 8),
        reason: u32_at(r, rest + 16),
        source_info: u32_at(r, rest + 20),
        security_id: u32_at(r, rest + 24),
        file_attributes: u32_at(r, rest + 28),
        name_lc: name.to_lowercase(),
        name,
        ..Default::default()
    })
}

pub struct UsnJournal {
    pub raw: Vec<u8>,
    pub records: Vec<UsnRecord>,
    /// Bytes skipped because they did not decode as a record.
    pub skipped_bytes: usize,
}

impl UsnJournal {
    /// True if the file plausibly holds USN records: the first non-zero
    /// 8-byte-aligned position decodes as one.
    pub fn sniff(d: &[u8]) -> bool {
        // Exported journals often start with a long zeroed (sparse) region.
        let mut pos = 0;
        while pos + 8 <= d.len() && u32_at(d, pos) == 0 {
            pos += 8;
        }
        pos + 8 <= d.len() && parse_record(d, pos).is_some()
    }

    pub fn load(raw: Vec<u8>, progress: &AtomicUsize) -> UsnJournal {
        let mut records = Vec::new();
        let mut skipped = 0;
        let mut pos = 0;
        let mut last_report = 0;
        while pos + 8 <= raw.len() {
            if pos - last_report > 1 << 20 {
                progress.store(pos, Ordering::Relaxed);
                last_report = pos;
            }
            if u32_at(&raw, pos) == 0 {
                // Records never straddle a page; zeros mean padding to the
                // end of the page (or a sparse region).
                pos = (pos / PAGE + 1) * PAGE;
                continue;
            }
            match parse_record(&raw, pos) {
                Some(r) => {
                    pos += r.length as usize;
                    records.push(r);
                }
                None => {
                    skipped += 8;
                    pos += 8;
                }
            }
        }
        progress.store(raw.len(), Ordering::Relaxed);
        UsnJournal {
            raw,
            records,
            skipped_bytes: skipped,
        }
    }

    pub fn record_bytes(&self, r: &UsnRecord) -> &[u8] {
        &self.raw[r.offset as usize..(r.offset + r.length as u64) as usize]
    }
}

/// The `$Extend\$UsnJrnl:$Max` stream.
#[derive(Clone, Debug)]
pub struct UsnMax {
    pub maximum_size: u64,
    pub allocation_delta: u64,
    /// Journal ID; it is the FILETIME at which the journal was created.
    pub journal_id: u64,
    pub lowest_valid_usn: i64,
}

impl UsnMax {
    pub fn parse(d: &[u8]) -> Option<UsnMax> {
        if d.len() != 32 {
            return None;
        }
        let m = UsnMax {
            maximum_size: u64_at(d, 0),
            allocation_delta: u64_at(d, 8),
            journal_id: u64_at(d, 16),
            lowest_valid_usn: u64_at(d, 24) as i64,
        };
        (m.maximum_size != 0 && m.lowest_valid_usn >= 0).then_some(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_journal() {
        let Ok(raw) = std::fs::read("samples/$J") else { return };
        assert!(UsnJournal::sniff(&raw));
        let j = UsnJournal::load(raw, &AtomicUsize::new(0));
        println!("usn records={} skipped={}", j.records.len(), j.skipped_bytes);
        for r in j.records.iter().take(3) {
            println!(
                "usn={} {} {:?} #{}-{} parent #{}-{} [{}]",
                r.usn,
                crate::mft::format_filetime(r.timestamp),
                r.name,
                r.file_record,
                r.file_seq,
                r.parent_record,
                r.parent_seq,
                reason_text(r.reason)
            );
        }
        assert!(!j.records.is_empty());
        assert!(j.records.windows(2).all(|w| w[0].usn < w[1].usn));
    }

    #[test]
    fn sample_max() {
        let Ok(raw) = std::fs::read("samples/$Max") else { return };
        let m = UsnMax::parse(&raw).expect("valid $Max");
        println!("{m:?} id={}", crate::mft::format_filetime(m.journal_id));
        assert_eq!(m.maximum_size, 32 * 1024 * 1024);
    }
}
