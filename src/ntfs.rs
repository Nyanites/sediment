//! NTFS volumes inside disk images: finding them, matching one to a loaded
//! `$MFT`, and reading a file's content from its clusters, which is what the
//! `$MFT` alone doesn't hold for anything bigger than about 700 bytes.
//!
//! Handles fragmented files (any number of runs, split over extension
//! records), sparse runs, the initialized size, NTFS (LZNT1) compression and
//! Windows Overlay Filter (WOF / `compact.exe`) compression with Xpress.
//! EFS-encrypted content is read as the raw ciphertext.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::image::Source;
use crate::mft::{self, AttrBody, MftFile, Record, ATTR_DATA};
use crate::{lznt1, xpress};

const ATTR_REPARSE_POINT: u32 = 0xC0;
const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;
const FLAG_COMPRESSED: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 0x4000;
/// Content is handed to the caller in pieces of this size.
const PIECE: usize = 1 << 20;

pub type Sink<'a> = dyn FnMut(&[u8]) -> Result<(), String> + 'a;

/// An NTFS file system found in an image.
pub struct Volume {
    pub src: Arc<dyn Source>,
    /// Byte offset of the volume in the image.
    pub offset: u64,
    pub size: u64,
    pub cluster_size: u64,
    pub record_size: usize,
    pub mft_lcn: u64,
    pub serial: u64,
}

impl Volume {
    /// Parses the NTFS boot sector at `offset`.
    fn at(src: &Arc<dyn Source>, offset: u64) -> Option<Volume> {
        let mut b = [0u8; 512];
        src.read_at(offset, &mut b).ok()?;
        if &b[3..11] != b"NTFS    " || b[510..512] != [0x55, 0xAA] {
            return None;
        }
        let bps = mft::u16_at(&b, 0x0B) as u64;
        let spc = match b[0x0D] {
            0 => return None,
            n if n > 0x80 => 1u64.checked_shl(256 - n as u32)?,
            n => n as u64,
        };
        if !bps.is_power_of_two() || !(256..=4096).contains(&bps) {
            return None;
        }
        let cluster_size = bps.checked_mul(spc).filter(|&c| c <= 2 << 20)?;
        let record_size = match b[0x40] as i8 {
            n if n < 0 => 1usize.checked_shl((-(n as i32)) as u32)?,
            n => (n as u64).checked_mul(cluster_size)? as usize,
        };
        if !record_size.is_power_of_two() || !(256..=65536).contains(&record_size) {
            return None;
        }
        let size = mft::u64_at(&b, 0x28).checked_add(1)?.checked_mul(bps)?;
        let mft_lcn = mft::u64_at(&b, 0x30);
        if mft_lcn.checked_mul(cluster_size)? >= size {
            return None;
        }
        Some(Volume { src: src.clone(), offset, size, cluster_size, record_size, mft_lcn, serial: mft::u64_at(&b, 0x48) })
    }

    /// Short description for the UI.
    pub fn describe(&self) -> String {
        format!(
            "NTFS volume at offset {} ({} MB, serial {:016X})",
            self.offset,
            self.size / 1_000_000,
            self.serial
        )
    }

    fn read(&self, at: u64, buf: &mut [u8]) -> Result<(), String> {
        let end = at.checked_add(buf.len() as u64).ok_or("read past the end of the volume")?;
        if end > self.size {
            return Err("the file's clusters point past the end of the volume".into());
        }
        self.src
            .read_at(self.offset + at, buf)
            .map_err(|e| format!("couldn't read the image at offset {}: {e}", self.offset + at))
    }

    /// Whether `file` is this volume's `$MFT`: same record size, and record
    /// 0's data starts at the cluster the boot sector names.
    pub fn matches(&self, file: &MftFile) -> bool {
        self.matches_record0(file.record_size, &file.parse_record(0))
    }

    /// `matches` for a `$MFT` known only by its record size and first record.
    pub fn matches_record0(&self, record_size: usize, rec0: &Record) -> bool {
        record_size == self.record_size
            && rec0.attributes.iter().any(|a| {
                a.type_code == ATTR_DATA
                    && matches!(&a.body, AttrBody::NonResident { start_vcn: 0, runs, .. }
                        if runs.first().and_then(|r| r.lcn) == Some(self.mft_lcn as i64))
            })
    }

    /// Reads this volume's own `$MFT`.
    pub fn read_mft(&self, progress: &AtomicU64) -> Result<Vec<u8>, String> {
        let mut first = vec![0u8; self.record_size];
        self.read(self.mft_lcn * self.cluster_size, &mut first)?;
        let rec0 = Record::parse(&first);
        if !rec0.is_valid() {
            return Err("the $MFT's first record is damaged".into());
        }
        let mut recs = vec![rec0];
        let mut map = stream_map(&recs, "").ok_or("the $MFT has no data runs")?;
        let mut data = self.read_all(&map, progress)?;
        // A very large or fragmented $MFT keeps more runs in extension records,
        // which live in the part read so far.
        if !map.covers_all(self.cluster_size) {
            let seq = recs[0].sequence;
            for chunk in data.chunks_exact(self.record_size).skip(1) {
                let r = Record::parse(chunk);
                if r.is_valid() && r.base_record == 0 && r.base_seq == seq && r.base_seq != 0 {
                    recs.push(r);
                }
            }
            map = stream_map(&recs, "").ok_or("the $MFT has no data runs")?;
            data = self.read_all(&map, progress)?;
        }
        Ok(data)
    }

    fn read_all(&self, map: &StreamMap, progress: &AtomicU64) -> Result<Vec<u8>, String> {
        if map.size > self.size {
            return Err("the stream is larger than the volume".into());
        }
        let mut out = Vec::with_capacity(map.size as usize);
        self.read_stream(map, &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        }, progress)?;
        Ok(out)
    }

    /// Hands the content of `map` to `sink` in order, in pieces.
    pub fn read_stream(&self, map: &StreamMap, sink: &mut Sink, progress: &AtomicU64) -> Result<(), String> {
        // Sparse files may be larger than the volume, but not by this much:
        // a damaged record would otherwise produce endless zeros.
        if map.size > self.size.saturating_mul(4).max(4 << 30) {
            return Err(format!(
                "the record claims a size of {} bytes, far more than this volume could hold; it is probably damaged",
                map.size
            ));
        }
        match map.compression_unit {
            Some(unit) => self.read_compressed(map, unit, sink, progress),
            None => {
                let mut buf = vec![0u8; PIECE];
                let mut off = 0u64;
                while off < map.size {
                    let n = (map.size - off).min(PIECE as u64) as usize;
                    self.read_range(map, off, &mut buf[..n])?;
                    sink(&buf[..n])?;
                    off += n as u64;
                    progress.store(off, Ordering::Relaxed);
                }
                Ok(())
            }
        }
    }

    /// Reads bytes `off..off + buf.len()` of an uncompressed stream: sparse
    /// runs, gaps and anything past the initialized size read as zeros.
    fn read_range(&self, map: &StreamMap, off: u64, buf: &mut [u8]) -> Result<(), String> {
        buf.fill(0);
        let cs = self.cluster_size;
        let end = off + buf.len() as u64;
        let start_ext = map.extents.partition_point(|e| (e.vcn + e.len) * cs <= off);
        for e in &map.extents[start_ext..] {
            let (e_start, e_end) = (e.vcn * cs, (e.vcn + e.len) * cs);
            if e_start >= end {
                break;
            }
            let Some(lcn) = e.lcn else { continue };
            let (from, to) = (e_start.max(off), e_end.min(end));
            let disk = lcn
                .checked_mul(cs)
                .and_then(|b| b.checked_add(from - e_start))
                .ok_or("bad cluster number")?;
            self.read(disk, &mut buf[(from - off) as usize..(to - off) as usize])?;
        }
        if end > map.init_size {
            let z = (map.init_size.saturating_sub(off) as usize).min(buf.len());
            buf[z..].fill(0);
        }
        Ok(())
    }

    /// NTFS compression: every unit of 2^n clusters is either all sparse
    /// (zeros), fully allocated (stored as is) or partly allocated (LZNT1
    /// data in the allocated clusters).
    fn read_compressed(&self, map: &StreamMap, unit: u64, sink: &mut Sink, progress: &AtomicU64) -> Result<(), String> {
        let cs = self.cluster_size;
        let unit_bytes = (unit * cs) as usize;
        if unit_bytes > 16 << 20 {
            return Err("compression unit too large".into());
        }
        let mut raw = Vec::with_capacity(unit_bytes);
        let mut off = 0u64;
        let mut u = 0u64;
        while off < map.size {
            raw.clear();
            let mut allocated = 0;
            for c in 0..unit {
                if let Some(lcn) = map.lcn_of(u * unit + c) {
                    let mut cl = vec![0u8; cs as usize];
                    self.read(lcn.checked_mul(cs).ok_or("bad cluster number")?, &mut cl)?;
                    raw.extend_from_slice(&cl);
                    allocated += 1;
                }
            }
            let plain = if allocated == 0 {
                vec![0u8; unit_bytes]
            } else if allocated == unit {
                std::mem::take(&mut raw)
            } else {
                lznt1::decompress(&raw, unit_bytes).map_err(|e| format!("NTFS compression: {e}"))?
            };
            let n = (map.size - off).min(unit_bytes as u64) as usize;
            sink(&plain[..n.min(plain.len())])?;
            off += n as u64;
            u += 1;
            progress.store(off, Ordering::Relaxed);
        }
        Ok(())
    }
}

/// Finds every NTFS volume in an image: a volume image itself, or the
/// partitions of a disk image (MBR, extended partitions and GPT).
pub fn find_volumes(src: Arc<dyn Source>) -> Vec<Volume> {
    let mut offsets = vec![0u64];
    let mut sector0 = [0u8; 512];
    if src.read_at(0, &mut sector0).is_ok() && sector0[510..512] == [0x55, 0xAA] {
        for i in 0..4 {
            let e = &sector0[0x1BE + i * 16..0x1BE + (i + 1) * 16];
            let start = mft::u32_at(e, 8) as u64 * 512;
            match e[4] {
                0 => {}
                0x05 | 0x0F | 0x85 => walk_ebr(&*src, start, &mut offsets),
                0xEE => {}
                _ => offsets.push(start),
            }
        }
    }
    for sector in [512u64, 4096] {
        gpt(&*src, sector, &mut offsets);
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets.into_iter().filter_map(|o| Volume::at(&src, o)).collect()
}

fn walk_ebr(src: &dyn Source, ext_start: u64, offsets: &mut Vec<u64>) {
    let mut ebr = ext_start;
    for _ in 0..128 {
        let mut s = [0u8; 512];
        if src.read_at(ebr, &mut s).is_err() || s[510..512] != [0x55, 0xAA] {
            return;
        }
        let (a, b) = (&s[0x1BE..0x1CE], &s[0x1CE..0x1DE]);
        if a[4] != 0 {
            offsets.push(ebr + mft::u32_at(a, 8) as u64 * 512);
        }
        if b[4] == 0 {
            return;
        }
        let next = ext_start + mft::u32_at(b, 8) as u64 * 512;
        if next <= ebr {
            return;
        }
        ebr = next;
    }
}

fn gpt(src: &dyn Source, sector: u64, offsets: &mut Vec<u64>) {
    let mut h = [0u8; 92];
    if src.read_at(sector, &mut h).is_err() || &h[..8] != b"EFI PART" {
        return;
    }
    let entries_lba = mft::u64_at(&h, 72);
    let count = (mft::u32_at(&h, 80) as u64).min(512);
    let size = mft::u32_at(&h, 84) as u64;
    if !(128..=1024).contains(&size) {
        return;
    }
    let mut table = vec![0u8; (count * size) as usize];
    if entries_lba.checked_mul(sector).is_none_or(|at| src.read_at(at, &mut table).is_err()) {
        return;
    }
    for e in table.chunks_exact(size as usize) {
        if e[..16].iter().any(|&b| b != 0)
            && let Some(o) = mft::u64_at(e, 32).checked_mul(sector)
        {
            offsets.push(o);
        }
    }
}

#[derive(Debug)]
struct Extent {
    vcn: u64,
    len: u64,
    lcn: Option<u64>,
}

/// Where a non-resident stream's content lives on the volume.
#[derive(Debug)]
pub struct StreamMap {
    pub size: u64,
    init_size: u64,
    alloc_size: u64,
    extents: Vec<Extent>,
    /// Clusters per compression unit, for NTFS-compressed streams.
    compression_unit: Option<u64>,
    pub encrypted: bool,
}

impl StreamMap {
    fn lcn_of(&self, vcn: u64) -> Option<u64> {
        let i = self.extents.partition_point(|e| e.vcn + e.len <= vcn);
        let e = self.extents.get(i).filter(|e| e.vcn <= vcn)?;
        e.lcn.map(|l| l + (vcn - e.vcn))
    }

    fn covers_all(&self, cluster_size: u64) -> bool {
        let mapped: u64 = self.extents.iter().map(|e| e.len).sum();
        mapped * cluster_size >= self.alloc_size.min(self.size.next_multiple_of(cluster_size))
    }
}

/// The map of the `$DATA` stream called `name` (empty for the main stream)
/// of a file made of `recs`, if it is non-resident. Pieces of the run list
/// spread over extension records are put together in VCN order.
pub fn stream_map(recs: &[Record], name: &str) -> Option<StreamMap> {
    let mut pieces: Vec<(&Record, &mft::Attribute)> = recs
        .iter()
        .flat_map(|r| r.attributes.iter().map(move |a| (r, a)))
        .filter(|(_, a)| a.type_code == ATTR_DATA && a.name == name && matches!(a.body, AttrBody::NonResident { .. }))
        .collect();
    pieces.sort_by_key(|(_, a)| match a.body {
        AttrBody::NonResident { start_vcn, .. } => start_vcn,
        AttrBody::Resident { .. } => 0,
    });
    let (first_rec, first) = *pieces.first()?;
    let AttrBody::NonResident { start_vcn: 0, real_size, init_size, alloc_size, .. } = first.body else {
        return None;
    };
    let mut extents = Vec::new();
    for (_, a) in &pieces {
        let AttrBody::NonResident { start_vcn, runs, .. } = &a.body else { continue };
        let mut vcn = *start_vcn;
        for r in runs {
            let lcn = match r.lcn {
                Some(l) if l >= 0 => Some(l as u64),
                Some(_) => return None,
                None => None,
            };
            extents.push(Extent { vcn, len: r.length, lcn });
            vcn = vcn.checked_add(r.length)?;
        }
    }
    extents.sort_by_key(|e| e.vcn);
    // Overlapping pieces mean a damaged run list; keep the first claim.
    let mut next = 0;
    extents.retain(|e| {
        let ok = e.vcn >= next;
        if ok {
            next = e.vcn + e.len;
        }
        ok
    });
    let compressed = first.flags & FLAG_COMPRESSED != 0;
    let unit = mft::u16_at(&first_rec.data, first.offset + 34) as u32;
    let compression_unit = (compressed && unit > 0 && unit <= 8).then(|| 1u64 << unit);
    Some(StreamMap {
        size: real_size,
        init_size: init_size.min(real_size),
        alloc_size,
        extents,
        compression_unit,
        encrypted: first.flags & FLAG_ENCRYPTED != 0,
    })
}

/// The algorithm of a WOF-compressed file (0 XPRESS4K, 1 LZX, 2 XPRESS8K,
/// 3 XPRESS16K), from its reparse point.
fn wof_algorithm(recs: &[Record]) -> Option<u32> {
    recs.iter().find_map(|r| {
        let a = r.attributes.iter().find(|a| a.type_code == ATTR_REPARSE_POINT)?;
        let c = a.resident_content(&r.data)?;
        // Reparse header (8), WOF_EXTERNAL_INFO (version, provider), then
        // FILE_PROVIDER_EXTERNAL_INFO_V1 (version, algorithm, flags).
        (mft::u32_at(c, 0) == IO_REPARSE_TAG_WOF && mft::u32_at(c, 12) == 2).then(|| mft::u32_at(c, 20))
    })
}

/// How a stream will be read, for the UI.
pub enum Kind {
    Resident,
    Clusters,
    NtfsCompressed,
    Wof,
    Encrypted,
}

pub fn kind(recs: &[Record], name: &str) -> Option<Kind> {
    if name.is_empty() && wof_algorithm(recs).is_some() && stream_present(recs, "WofCompressedData") {
        return Some(Kind::Wof);
    }
    let resident = recs.iter().any(|r| {
        r.attributes.iter().any(|a| a.type_code == ATTR_DATA && a.name == name && matches!(a.body, AttrBody::Resident { .. }))
    });
    if resident {
        return Some(Kind::Resident);
    }
    let m = stream_map(recs, name)?;
    Some(if m.encrypted {
        Kind::Encrypted
    } else if m.compression_unit.is_some() {
        Kind::NtfsCompressed
    } else {
        Kind::Clusters
    })
}

fn stream_present(recs: &[Record], name: &str) -> bool {
    recs.iter().any(|r| r.attributes.iter().any(|a| a.type_code == ATTR_DATA && a.name == name))
}

fn resident<'a>(recs: &'a [Record], name: &str) -> Option<&'a [u8]> {
    recs.iter().find_map(|r| {
        r.attributes
            .iter()
            .find(|a| a.type_code == ATTR_DATA && a.name == name)
            .and_then(|a| a.resident_content(&r.data))
    })
}

/// The size of a stream's content as it will be extracted.
pub fn content_size(recs: &[Record], name: &str) -> Option<u64> {
    if let Some(d) = resident(recs, name) {
        return Some(d.len() as u64);
    }
    stream_map(recs, name).map(|m| m.size)
}

/// Reads the content of stream `name` of the file made of `recs`, wherever
/// it lives: in the record, in clusters, NTFS- or WOF-compressed.
pub fn read_content(vol: &Volume, recs: &[Record], name: &str, sink: &mut Sink, progress: &AtomicU64) -> Result<(), String> {
    if name.is_empty()
        && let Some(alg) = wof_algorithm(recs)
        && stream_present(recs, "WofCompressedData")
    {
        return read_wof(vol, recs, alg, sink, progress);
    }
    if let Some(d) = resident(recs, name) {
        progress.store(d.len() as u64, Ordering::Relaxed);
        return sink(d);
    }
    let map = stream_map(recs, name).ok_or("no data stream by that name")?;
    vol.read_stream(&map, sink, progress)
}

/// WOF keeps a file's content compressed in its `WofCompressedData` stream:
/// a table of chunk offsets, then chunks that each decompress to the chunk
/// size (stored as is when compression didn't help).
fn read_wof(vol: &Volume, recs: &[Record], alg: u32, sink: &mut Sink, progress: &AtomicU64) -> Result<(), String> {
    let chunk = match alg {
        0 => 4096u64,
        2 => 8192,
        3 => 16384,
        1 => return Err("this file is WOF-compressed with LZX, which Sediment can't decompress yet".into()),
        _ => return Err(format!("unknown WOF compression algorithm {alg}")),
    };
    let size = stream_map(recs, "").map(|m| m.size).or_else(|| resident(recs, "").map(|d| d.len() as u64)).unwrap_or(0);
    // The compressed stream is small next to the file; read it whole, capped.
    let compressed = match resident(recs, "WofCompressedData") {
        Some(d) => d.to_vec(),
        None => {
            let m = stream_map(recs, "WofCompressedData").ok_or("WofCompressedData is missing")?;
            if m.size > 4 << 30 {
                return Err("WofCompressedData is implausibly large".into());
            }
            vol.read_all(&m, &AtomicU64::new(0))?
        }
    };
    let n = size.div_ceil(chunk);
    let entry = if size > u32::MAX as u64 { 8 } else { 4 };
    let table_len = n.saturating_sub(1).checked_mul(entry).ok_or("bad WOF table")? as usize;
    if table_len > compressed.len() {
        return Err("WofCompressedData is shorter than its chunk table".into());
    }
    let offset = |i: u64| -> u64 {
        if i == 0 {
            return 0;
        }
        let at = ((i - 1) * entry) as usize;
        if entry == 8 { mft::u64_at(&compressed, at) } else { mft::u32_at(&compressed, at) as u64 }
    };
    let data = &compressed[table_len..];
    let mut done = 0u64;
    for i in 0..n {
        let (from, to) = (offset(i), if i + 1 == n { data.len() as u64 } else { offset(i + 1) });
        let piece = data.get(from as usize..to as usize).ok_or("WOF chunk outside its stream")?;
        let want = (size - i * chunk).min(chunk) as usize;
        if piece.len() == want {
            sink(piece)?;
        } else {
            let out = xpress::decompress(piece, want).map_err(|e| format!("WOF chunk {i}: {e}"))?;
            sink(&out)?;
        }
        done += want as u64;
        progress.store(done, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};
    use std::sync::atomic::AtomicUsize;

    struct NoImage;

    impl Source for NoImage {
        fn len(&self) -> u64 {
            0
        }
        fn read_at(&self, _: u64, _: &mut [u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("no image"))
        }
        fn describe(&self) -> String {
            String::new()
        }
    }

    fn no_volume() -> Volume {
        Volume { src: Arc::new(NoImage), offset: 0, size: 0, cluster_size: 4096, record_size: 1024, mft_lcn: 0, serial: 0 }
    }

    /// An image held in memory.
    struct MemImage(Vec<u8>);

    impl Source for MemImage {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            let src = self.0.get(off as usize..off as usize + buf.len()).ok_or(std::io::Error::other("past end"))?;
            buf.copy_from_slice(src);
            Ok(())
        }
        fn describe(&self) -> String {
            String::new()
        }
    }

    /// A non-resident `$DATA` called `name` of `size` bytes: one run starting
    /// at cluster `lcn`, or sparse (the way WOF leaves a file's main stream).
    fn nonresident(name: &str, size: u64, lcn: Option<u8>) -> Vec<u8> {
        let clusters = size.div_ceil(4096);
        let name16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let runs_off = (0x40 + name16.len()).next_multiple_of(8);
        let len = (runs_off + 8) as u32;
        let mut a = vec![0u8; len as usize];
        a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        a[4..8].copy_from_slice(&len.to_le_bytes());
        a[8] = 1;
        a[9] = name.encode_utf16().count() as u8;
        a[10..12].copy_from_slice(&0x40u16.to_le_bytes());
        if lcn.is_none() {
            a[12..14].copy_from_slice(&0x8000u16.to_le_bytes());
        }
        a[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
        a[32..34].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[40..48].copy_from_slice(&(clusters * 4096).to_le_bytes());
        a[48..56].copy_from_slice(&size.to_le_bytes());
        a[56..64].copy_from_slice(&size.to_le_bytes());
        a[0x40..0x40 + name16.len()].copy_from_slice(&name16);
        match lcn {
            Some(l) => a[runs_off..runs_off + 3].copy_from_slice(&[0x11, clusters as u8, l]),
            None => a[runs_off..runs_off + 2].copy_from_slice(&[0x01, clusters as u8]),
        }
        a
    }

    /// A WOF XPRESS4K file built with Windows' own Xpress Huffman encoder:
    /// two compressed chunks, one stored as is, and a short last chunk.
    #[cfg(windows)]
    #[test]
    fn wof_xpress4k() {
        use crate::extract::tests::{build_record, resident};
        use crate::xpress::tests::native::compress;
        let mut plain: Vec<u8> = (0..4096 * 3 + 1000).map(|i| (i / 7 % 251) as u8).collect();
        let mut x = 0x2545_F491u32;
        for b in &mut plain[4096 * 2..4096 * 3] {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8; // incompressible: stored as is
        }
        let chunks: Vec<Vec<u8>> = plain
            .chunks(4096)
            .map(|c| {
                let z = compress(c);
                if z.len() >= c.len() { c.to_vec() } else { z }
            })
            .collect();
        assert_eq!(chunks[2].len(), 4096, "the random chunk is stored raw");
        let mut wof = Vec::new();
        let mut end = 0u32;
        for c in &chunks[..chunks.len() - 1] {
            end += c.len() as u32;
            wof.extend(end.to_le_bytes());
        }
        for c in &chunks {
            wof.extend_from_slice(c);
        }
        let mut reparse = Vec::new();
        for v in [IO_REPARSE_TAG_WOF, 16, 1, 2, 1, 0, 0] {
            reparse.extend(v.to_le_bytes());
        }
        // The compressed stream lives in clusters 2.. of an in-memory volume.
        let mut disk = vec![0u8; 4096 * 2];
        disk.extend_from_slice(&wof);
        disk.resize(disk.len().next_multiple_of(4096), 0);
        let vol = Volume { src: Arc::new(MemImage(disk.clone())), size: disk.len() as u64, ..no_volume() };
        let attrs = [
            resident(0xC0, "", 1, &reparse),
            nonresident("", plain.len() as u64, None),
            nonresident("WofCompressedData", wof.len() as u64, Some(2)),
        ]
        .concat();
        let recs = [Record::parse(&build_record(1, 1, 0, &attrs))];
        assert!(matches!(kind(&recs, ""), Some(Kind::Wof)));
        let mut out = Vec::new();
        read_content(&vol, &recs, "", &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        }, &AtomicU64::new(0))
        .unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn sparse_file_reads_as_zeros() {
        let attrs = nonresident("", 10_000, None);
        let recs = [Record::parse(&crate::extract::tests::build_record(1, 1, 0, &attrs))];
        let map = stream_map(&recs, "").unwrap();
        let mut out = Vec::new();
        no_volume().read_stream(&map, &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        }, &AtomicU64::new(0))
        .unwrap();
        assert_eq!(out, vec![0u8; 10_000]);
    }

    /// A 256 KiB NTFS volume: boot sector, a 16-record `$MFT` at cluster 4,
    /// and record 1 a file whose 6000 bytes live in clusters 10-11.
    fn tiny_volume() -> Vec<u8> {
        use crate::extract::tests::{build_record, resident};
        let mut img = vec![0u8; 64 * 4096];
        let b = &mut img[..512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        b[0x0D] = 8;
        b[0x28..0x30].copy_from_slice(&(64u64 * 8 - 1).to_le_bytes());
        b[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        b[0x40] = 0xF6; // 2^10-byte records
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mft = 4 * 4096;
        let rec0 = build_record(1, 1, 0, &[resident(0x10, "", 0, &[0u8; 72]), nonresident("", 16384, Some(4))].concat());
        img[mft..mft + 1024].copy_from_slice(&rec0);
        let rec1 = build_record(1, 1, 0, &nonresident("", 6000, Some(10)));
        img[mft + 1024..mft + 2048].copy_from_slice(&rec1);
        for (i, b) in img[10 * 4096..10 * 4096 + 6000].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        img
    }

    #[test]
    fn tiny_volume_reads() {
        let src: Arc<dyn Source> = Arc::new(MemImage(tiny_volume()));
        let vols = find_volumes(src);
        assert_eq!(vols.len(), 1);
        let mft = MftFile::load(vols[0].read_mft(&AtomicU64::new(0)).unwrap(), &AtomicUsize::new(0));
        assert!(vols[0].matches(&mft));
        let mut out = Vec::new();
        read_content(&vols[0], &mft.file_records(1), "", &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        }, &AtomicU64::new(0))
        .unwrap();
        assert_eq!(out, (0..6000).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    }

    /// Corrupts the boot sector, partition table and `$MFT` of `tiny_volume`
    /// at random and reads everything: errors are fine, panics and runaway
    /// output are not.
    #[test]
    fn fuzz_volume() {
        let base = tiny_volume();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let iters = if cfg!(debug_assertions) { 200 } else { 3000 };
        for _ in 0..iters {
            let mut img = base.clone();
            for _ in 0..1 + rnd() % 12 {
                let at = match rnd() % 3 {
                    0 => (rnd() % 512) as usize,
                    _ => 4 * 4096 + (rnd() % 2048) as usize,
                };
                img[at] = match rnd() % 4 {
                    0 => 0xFF,
                    1 => 0,
                    _ => rnd() as u8,
                };
            }
            if rnd() % 8 == 0 {
                img[0x1BE + 4] = [0x07, 0x05, 0xEE][(rnd() % 3) as usize];
                img[0x1BE + 8..0x1BE + 12].copy_from_slice(&(rnd() as u32).to_le_bytes());
            }
            for v in find_volumes(Arc::new(MemImage(img))) {
                let Ok(raw) = v.read_mft(&AtomicU64::new(0)) else { continue };
                let mft = MftFile::load(raw, &AtomicUsize::new(0));
                let _ = v.matches(&mft);
                for i in 0..mft.entries.len() {
                    let recs = mft.file_records(i);
                    for s in crate::extract::streams(&recs) {
                        let _ = kind(&recs, s.name);
                        let mut n = 0u64;
                        let _ = read_content(&v, &recs, s.name, &mut |b| {
                            n += b.len() as u64;
                            if n > 64 << 20 { Err("runaway".into()) } else { Ok(()) }
                        }, &AtomicU64::new(0));
                    }
                }
            }
        }
    }

    /// Reads every file of the public `nps-2009-ntfs1` image from its E01 and
    /// checks it against the MD5s in its DFXML file (made with The Sleuth Kit):
    /// a fragmented 21 MB file, NTFS-compressed copies and EFS-encrypted ones.
    /// Get both from digitalcorpora.org and point SEDIMENT_NTFS1 at the folder:
    /// `cargo test -- --ignored live_ntfs1_ground_truth`.
    #[test]
    #[ignore]
    fn live_ntfs1_ground_truth() {
        let Some(dir) = std::env::var_os("SEDIMENT_NTFS1").map(std::path::PathBuf::from) else {
            println!("SEDIMENT_NTFS1 not set; skipped");
            return;
        };
        let src: Arc<dyn Source> = Arc::from(crate::image::open(&dir.join("ntfs1-gen2.E01")).unwrap());
        let vols = find_volumes(src);
        assert_eq!(vols.len(), 1);
        let vol = &vols[0];
        let mft = MftFile::load(vol.read_mft(&AtomicU64::new(0)).unwrap(), &AtomicUsize::new(0));
        assert!(vol.matches(&mft));

        let xml = std::fs::read_to_string(dir.join("ntfs1-gen2.xml")).unwrap();
        let tag = |s: &str, t: &str| -> Option<String> {
            let a = s.find(&format!("<{t}>"))? + t.len() + 2;
            Some(s[a..a + s[a..].find("</")?].to_string())
        };
        let mut checked = 0;
        for fo in xml.split("<fileobject>").skip(1) {
            let (Some(name), Some(inode), Some(md5)) = (tag(fo, "filename"), tag(fo, "inode"), tag(fo, "md5")) else { continue };
            let recs = mft.file_records(inode.parse().unwrap());
            let mut h = Md5::new();
            let mut len = 0u64;
            let t = std::time::Instant::now();
            read_content(vol, &recs, "", &mut |b| {
                h.update(b);
                len += b.len() as u64;
                Ok(())
            }, &AtomicU64::new(0))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            let got = format!("{:x}", h.finalize());
            let kind = match kind(&recs, "") {
                Some(Kind::Resident) => "resident",
                Some(Kind::Clusters) => "clusters",
                Some(Kind::NtfsCompressed) => "NTFS-compressed",
                Some(Kind::Wof) => "WOF",
                Some(Kind::Encrypted) => "EFS-encrypted",
                None => "?",
            };
            println!("{} {name:<45} {len:>9} B  {kind:<16} {:?}", if got == md5 { "OK  " } else { "FAIL" }, t.elapsed());
            assert_eq!(got, md5, "{name}");
            checked += 1;
        }
        assert_eq!(checked, 19);

        // The Extract path end to end: archives to check with an unzip tool.
        let out = std::env::temp_dir().join("sediment-ntfs1-extract");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        for inode in [47usize, 37, 32, 46] {
            let recs = mft.file_records(inode);
            let dest = out.join(crate::extract::zip_file_name(&recs, inode));
            let no = std::sync::atomic::AtomicBool::new(false);
            let x = crate::extract::extract_to(&dest, &recs, inode, Some(vol), &AtomicU64::new(0), &no).unwrap();
            println!("extracted #{inode}: {} stream(s), {} bytes -> {}", x.files, x.bytes, dest.display());
        }
    }
}
