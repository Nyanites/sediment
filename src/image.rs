//! Disk and volume images behind one positional-read trait: EnCase E01 (EWF v1,
//! multi-segment), raw/dd (including .001 split sets) and live volumes.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A readable disk or volume image, addressed by byte offset.
pub trait Source: Send + Sync {
    /// Size in bytes of the media.
    fn len(&self) -> u64;
    /// Fills `buf` from `offset`; an error if any byte is unavailable (past the end, read error, corrupt chunk).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()>;
    /// Short human description, e.g. "E01 image, 3 segments, 512 MB" or "raw image" or "live volume \\\\.\\C:".
    fn describe(&self) -> String;
    /// The MD5 of the media recorded when the image was made, if the format keeps one.
    fn stored_md5(&self) -> Option<[u8; 16]> {
        None
    }
}

/// Opens `path` as an image, detecting the format from content (not extension).
pub fn open(path: &Path) -> Result<Box<dyn Source>, String> {
    if is_device_path(path) {
        return Ok(Box::new(Live::open(path)?));
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let ft = meta.file_type();
        if ft.is_block_device() || ft.is_char_device() {
            return Ok(Box::new(Live::open(path)?));
        }
    }
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut magic = [0u8; 8];
    if meta.len() >= 8 {
        read_full(&file, 0, &mut magic).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if magic == EVF_SIGNATURE {
        return Ok(Box::new(Ewf::open(path)?));
    }
    if magic.starts_with(b"EVF2") {
        return Err("EWF2 (.Ex01) images are not supported; convert to E01 or raw (ewfexport, FTK Imager)".into());
    }
    if magic.starts_with(b"LVF\x09") || magic.starts_with(b"LEF2") {
        return Err("logical evidence files (.L01/.Lx01) hold files, not a disk image".into());
    }
    Ok(Box::new(Raw::open(path, file, meta.len())?))
}

const EVF_SIGNATURE: [u8; 8] = *b"EVF\x09\x0d\x0a\xff\x00";
const MAX_CHUNK: u64 = 64 << 20;
const MAX_TABLE_ENTRIES: u64 = 1 << 24;
const MAX_SECTIONS: usize = 1 << 20;
const CACHE_CHUNKS: usize = 64;
const DESCRIPTOR: u64 = 76;

fn read_full(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match pread(file, &mut buf[done..], offset + done as u64) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected end of file")),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

#[cfg(unix)]
fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

fn check_range(len: u64, offset: u64, n: usize) -> io::Result<()> {
    match offset.checked_add(n as u64) {
        Some(end) if end <= len => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("read of {n} bytes at {offset} is past the end of the media ({len} bytes)"),
        )),
    }
}

fn corrupt(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} bytes") } else if v >= 100.0 { format!("{v:.0} {}", UNITS[u]) } else { format!("{v:.1} {}", UNITS[u]) }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(5552) {
        for &x in block {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

/// Raw/dd image, optionally a split set (name.001, name.002, ...).
struct Raw {
    parts: Vec<(File, u64, u64)>,
    len: u64,
}

impl Raw {
    fn open(path: &Path, first: File, first_len: u64) -> Result<Raw, String> {
        let mut parts = vec![(first, 0, first_len)];
        let mut len = first_len;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if let Some(stem) = name.strip_suffix(".001") {
            for n in 2..=999u32 {
                let p = path.with_file_name(format!("{stem}.{n:03}"));
                let Ok(meta) = std::fs::metadata(&p) else { break };
                if !meta.is_file() {
                    break;
                }
                let f = File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                parts.push((f, len, meta.len()));
                len = len.checked_add(meta.len()).ok_or("split image too large")?;
            }
        }
        Ok(Raw { parts, len })
    }
}

impl Source for Raw {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        let mut done = 0;
        let mut i = self.parts.partition_point(|p| p.1 <= offset).saturating_sub(1);
        while done < buf.len() {
            let (file, start, len) = self.parts.get(i).ok_or_else(|| corrupt("split image part missing".into()))?;
            let pos = offset + done as u64;
            let within = pos - start;
            if within >= *len {
                i += 1;
                continue;
            }
            let n = ((len - within) as usize).min(buf.len() - done);
            read_full(file, within, &mut buf[done..done + n])?;
            done += n;
            i += 1;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        if self.parts.len() > 1 {
            format!("split raw image, {} parts, {}", self.parts.len(), human_size(self.len))
        } else {
            format!("raw image, {}", human_size(self.len))
        }
    }
}

enum SegData {
    File(File),
    #[cfg(test)]
    Mem(Vec<u8>),
}

struct Segment {
    data: SegData,
    len: u64,
}

impl Segment {
    fn read(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        match &self.data {
            SegData::File(f) => read_full(f, offset, buf),
            #[cfg(test)]
            SegData::Mem(m) => {
                buf.copy_from_slice(&m[offset as usize..offset as usize + buf.len()]);
                Ok(())
            }
        }
    }
}

struct Section {
    kind: String,
    start: u64,
    end: u64,
}

impl Section {
    fn data_start(&self) -> u64 {
        self.start + DESCRIPTOR
    }

    fn data_len(&self) -> u64 {
        self.end.saturating_sub(self.data_start())
    }
}

struct Chunk {
    seg: u32,
    offset: u64,
    stored: u64,
    compressed: bool,
}

#[derive(Default)]
struct Cache {
    slots: Vec<(u64, Arc<Vec<u8>>, u64)>,
    tick: u64,
}

/// EnCase EWF v1 (E01) image, possibly split across segment files.
struct Ewf {
    segs: Vec<Segment>,
    chunks: Vec<Chunk>,
    chunk_size: u64,
    len: u64,
    complete: bool,
    md5: Option<[u8; 16]>,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct EwfBuilder {
    segs: Vec<Segment>,
    chunks: Vec<Chunk>,
    geometry: Option<(u64, u64)>,
    md5: Option<[u8; 16]>,
    done: bool,
}

/// Extension of segment `n` (1-based): E01..E99, then EAA..EZZ, FAA.. up to ZZZ.
fn segment_extension(first: char, n: u32) -> Option<String> {
    let lower = first.is_ascii_lowercase();
    let base = first.to_ascii_uppercase();
    if !base.is_ascii_uppercase() || n == 0 {
        return None;
    }
    let ext = if n <= 99 {
        format!("{base}{n:02}")
    } else {
        let k = n - 100;
        let lead = base as u32 + k / 676;
        if lead > 'Z' as u32 {
            return None;
        }
        let letter = |v: u32| char::from(b'A' + v as u8);
        format!("{}{}{}", char::from_u32(lead)?, letter((k / 26) % 26), letter(k % 26))
    };
    Some(if lower { ext.to_ascii_lowercase() } else { ext })
}

fn segment_path(path: &Path, n: u32) -> Option<PathBuf> {
    let ext = path.extension()?.to_str()?;
    let first = ext.chars().next()?;
    let tail = &ext[first.len_utf8()..];
    let numbered = ext.len() == 3
        && first.is_ascii_alphabetic()
        && (tail.bytes().all(|b| b.is_ascii_digit()) || tail.bytes().all(|b| b.is_ascii_alphabetic()));
    if !numbered {
        return None;
    }
    Some(path.with_extension(segment_extension(first, n)?))
}

impl Ewf {
    fn open(path: &Path) -> Result<Ewf, String> {
        if path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("s01")) {
            return Err("SMART (.s01) images are not supported; convert to E01 or raw (ewfexport)".into());
        }
        let open_seg = |p: &Path| -> Result<Segment, String> {
            let f = File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let len = f.metadata().map_err(|e| format!("{}: {e}", p.display()))?.len();
            Ok(Segment { data: SegData::File(f), len })
        };
        let given = open_seg(path)?;
        let mut header = [0u8; 13];
        given.read(0, &mut header).map_err(|e| format!("{}: {e}", path.display()))?;
        let given_no = u16::from_le_bytes([header[9], header[10]]) as u32;

        let mut b = EwfBuilder::default();
        if segment_path(path, 1).is_none() {
            b.add(given, 1).map_err(|e| format!("{}: {e}", path.display()))?;
            return b.finish();
        }
        let mut given = Some(given);
        for n in 1.. {
            let Some(p) = segment_path(path, n) else { break };
            let seg = if n == given_no {
                match given.take() {
                    Some(s) => s,
                    None => break,
                }
            } else if p.is_file() {
                open_seg(&p)?
            } else if n == 1 {
                return Err(format!("first segment {} not found", p.display()));
            } else {
                break;
            };
            b.add(seg, n).map_err(|e| format!("{}: {e}", p.display()))?;
            if b.done {
                break;
            }
        }
        b.finish()
    }

    fn describe_len(&self) -> String {
        human_size(self.len)
    }

    fn chunk(&self, idx: u64) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.tick += 1;
            let tick = cache.tick;
            if let Some(slot) = cache.slots.iter_mut().find(|s| s.0 == idx) {
                slot.2 = tick;
                return Ok(slot.1.clone());
            }
        }
        let data = Arc::new(self.load(idx)?);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let tick = cache.tick;
        if cache.slots.len() < CACHE_CHUNKS {
            cache.slots.push((idx, data.clone(), tick));
        } else if let Some(slot) = cache.slots.iter_mut().min_by_key(|s| s.2) {
            *slot = (idx, data.clone(), tick);
        }
        Ok(data)
    }

    fn load(&self, idx: u64) -> io::Result<Vec<u8>> {
        let c = usize::try_from(idx)
            .ok()
            .and_then(|i| self.chunks.get(i))
            .ok_or_else(|| corrupt(format!("chunk {idx} is missing from the image (incomplete segment set?)")))?;
        let seg = self
            .segs
            .get(c.seg as usize)
            .ok_or_else(|| corrupt(format!("chunk {idx} refers to a missing segment")))?;
        let want = self.chunk_size.min(self.len - idx * self.chunk_size) as usize;
        let cs = self.chunk_size as usize;
        if c.compressed {
            let n = c.stored.min(self.chunk_size + self.chunk_size / 8 + 1024) as usize;
            let mut input = vec![0u8; n];
            seg.read(c.offset, &mut input)?;
            let mut out = vec![0u8; cs];
            let mut z = flate2::Decompress::new(true);
            z.decompress(&input, &mut out, flate2::FlushDecompress::Finish)
                .map_err(|e| corrupt(format!("chunk {idx}: corrupt compressed data ({e})")))?;
            if (z.total_out() as usize) < want {
                return Err(corrupt(format!("chunk {idx}: decompressed to {} of {want} bytes", z.total_out())));
            }
            out.truncate(want);
            Ok(out)
        } else {
            let n = c.stored.min(self.chunk_size + 4) as usize;
            if n < want + 4 {
                return Err(corrupt(format!("chunk {idx}: stored size {} too small", c.stored)));
            }
            let mut buf = vec![0u8; n];
            seg.read(c.offset, &mut buf)?;
            let ok = |len: usize| n >= len + 4 && adler32(&buf[..len]) == le32(&buf, len);
            if !ok(want) && !ok(cs) {
                return Err(corrupt(format!("chunk {idx}: checksum mismatch")));
            }
            buf.truncate(want);
            Ok(buf)
        }
    }
}

impl EwfBuilder {
    fn needed(&self) -> u64 {
        self.geometry.map_or(0, |(cs, len)| len.div_ceil(cs))
    }

    fn sections(seg: &Segment) -> Result<Vec<Section>, String> {
        let mut out = Vec::new();
        let mut off = 13u64;
        loop {
            if out.len() >= MAX_SECTIONS {
                return Err("too many sections".into());
            }
            let mut d = [0u8; DESCRIPTOR as usize];
            seg.read(off, &mut d)
                .map_err(|_| format!("truncated: section descriptor at {off} is past the end of the segment"))?;
            if adler32(&d[..72]) != le32(&d, 72) {
                return Err(format!("corrupt section descriptor at {off} (checksum mismatch)"));
            }
            let kind: String = d[..16].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
            let next = le64(&d, 16);
            if kind == "done" || kind == "next" {
                out.push(Section { kind, start: off, end: off + DESCRIPTOR });
                return Ok(out);
            }
            if next < off + DESCRIPTOR || next > seg.len {
                return Err(format!("section \"{kind}\" at {off} has an invalid next offset {next}"));
            }
            out.push(Section { kind, start: off, end: next });
            off = next;
        }
    }

    fn add(&mut self, seg: Segment, number: u32) -> Result<(), String> {
        let mut header = [0u8; 13];
        seg.read(0, &mut header).map_err(|_| "file too short for an EWF header".to_string())?;
        if header[..8] != EVF_SIGNATURE {
            return Err("not an EWF (E01) segment".into());
        }
        let got = u16::from_le_bytes([header[9], header[10]]) as u32;
        if got != number {
            return Err(format!("expected segment number {number}, file says {got}"));
        }
        let sections = Self::sections(&seg)?;
        let seg_idx = self.segs.len() as u32;
        for s in &sections {
            match s.kind.as_str() {
                "volume" | "disk" | "data" if self.geometry.is_none() => self.volume(&seg, s)?,
                "hash" | "digest" if self.md5.is_none() && s.data_len() >= 16 => {
                    let mut h = [0u8; 16];
                    seg.read(s.data_start(), &mut h).map_err(|e| e.to_string())?;
                    if h != [0; 16] {
                        self.md5 = Some(h);
                    }
                }
                "table" => self.table(&seg, seg_idx, s, &sections)?,
                "done" => self.done = true,
                _ => {}
            }
        }
        self.segs.push(seg);
        Ok(())
    }

    fn volume(&mut self, seg: &Segment, s: &Section) -> Result<(), String> {
        if s.data_len() < 1052 {
            if s.data_len() >= 94 {
                return Err("SMART-format volume section; SMART (.s01) images are not supported".into());
            }
            return Err("volume section too short".into());
        }
        let mut v = [0u8; 24];
        seg.read(s.data_start(), &mut v).map_err(|e| e.to_string())?;
        let spc = le32(&v, 8) as u64;
        let bps = le32(&v, 12) as u64;
        let sectors = le64(&v, 16);
        let chunk_size = spc * bps;
        if chunk_size == 0 || chunk_size > MAX_CHUNK {
            return Err(format!("unsupported chunk size {spc} sectors x {bps} bytes"));
        }
        let len = sectors
            .checked_mul(bps)
            .filter(|&l| l > 0)
            .ok_or_else(|| format!("invalid media size {sectors} sectors x {bps} bytes"))?;
        self.geometry = Some((chunk_size, len));
        Ok(())
    }

    fn table(&mut self, seg: &Segment, seg_idx: u32, s: &Section, sections: &[Section]) -> Result<(), String> {
        if self.geometry.is_none() {
            return Err("table section before the volume section".into());
        }
        let data_len = s.data_len();
        if data_len < 24 {
            return Err(format!("table section at {} too short", s.start));
        }
        let mut h = [0u8; 24];
        seg.read(s.data_start(), &mut h).map_err(|e| e.to_string())?;
        let count = le32(&h, 0) as u64;
        let base = le64(&h, 8);
        if count > (data_len - 24) / 4 || count > MAX_TABLE_ENTRIES {
            return Err(format!("table section at {} claims {count} entries, more than it holds", s.start));
        }
        let mut raw = vec![0u8; count as usize * 4];
        seg.read(s.data_start() + 24, &mut raw).map_err(|e| e.to_string())?;
        let entries: Vec<u32> = raw.as_chunks::<4>().0.iter().map(|b| u32::from_le_bytes(*b)).collect();
        let offset_of = |e: u32| base.checked_add((e & 0x7fff_ffff) as u64);
        let needed = self.needed();
        for (i, &e) in entries.iter().enumerate() {
            if self.chunks.len() as u64 >= needed {
                break;
            }
            let Some(offset) = offset_of(e) else {
                return Err(format!("table section at {}: chunk offset overflows", s.start));
            };
            let section_end = sections
                .iter()
                .find(|x| x.start <= offset && offset < x.end)
                .map_or(0, |x| x.end - offset);
            let stored = match entries.get(i + 1).and_then(|&n| offset_of(n)) {
                Some(next) if next > offset => (next - offset).min(section_end),
                _ => section_end,
            };
            self.chunks.push(Chunk { seg: seg_idx, offset, stored, compressed: e & 0x8000_0000 != 0 });
        }
        Ok(())
    }

    fn finish(self) -> Result<Ewf, String> {
        let needed = self.needed();
        let Some((chunk_size, len)) = self.geometry else {
            return Err("E01 image has no volume section".into());
        };
        if self.chunks.is_empty() {
            return Err("E01 image has no chunk table".into());
        }
        Ok(Ewf {
            complete: self.done && self.chunks.len() as u64 >= needed,
            segs: self.segs,
            chunks: self.chunks,
            chunk_size,
            len,
            md5: self.md5,
            cache: Mutex::new(Cache::default()),
        })
    }
}

impl Source for Ewf {
    fn len(&self) -> u64 {
        self.len
    }

    fn stored_md5(&self) -> Option<[u8; 16]> {
        self.md5
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let chunk = self.chunk(pos / self.chunk_size)?;
            let within = (pos % self.chunk_size) as usize;
            let avail = chunk.get(within..).ok_or_else(|| corrupt("chunk shorter than expected".into()))?;
            let n = avail.len().min(buf.len() - done);
            if n == 0 {
                return Err(corrupt("chunk shorter than expected".into()));
            }
            buf[done..done + n].copy_from_slice(&avail[..n]);
            done += n;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        let segs = if self.segs.len() == 1 { "1 segment".to_string() } else { format!("{} segments", self.segs.len()) };
        let tail = if self.complete { "" } else { " (incomplete)" };
        format!("E01 image, {segs}, {}{tail}", self.describe_len())
    }
}

fn is_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if cfg!(windows) {
        s.starts_with(r"\\.\") || s.starts_with(r"\\?\GLOBALROOT\") || s.starts_with("//./")
    } else {
        s.starts_with("/dev/")
    }
}

const LIVE_ALIGN: u64 = 4096;
const LIVE_BLOCK: u64 = 1 << 20;

/// A live volume or physical disk; reads are widened to sector-aligned ranges.
struct Live {
    file: File,
    len: u64,
    name: String,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn DeviceIoControl(
        device: *mut std::ffi::c_void,
        code: u32,
        in_buf: *const std::ffi::c_void,
        in_size: u32,
        out_buf: *mut std::ffi::c_void,
        out_size: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;
}

impl Live {
    fn open(path: &Path) -> Result<Live, String> {
        let name = path.to_string_lossy().into_owned();
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, 0x1 | 0x2);
        let file = opts.open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                let who = if cfg!(windows) { "administrator" } else { "root" };
                format!("{name}: access denied; reading a live volume requires running Sediment as {who}")
            } else {
                format!("{name}: {e}")
            }
        })?;
        let len = Self::size(&file).map_err(|e| format!("{name}: cannot determine size: {e}"))?;
        if len == 0 {
            return Err(format!("{name}: cannot determine size"));
        }
        Ok(Live { file, len, name })
    }

    #[cfg(windows)]
    fn size(file: &File) -> io::Result<u64> {
        use std::os::windows::io::AsRawHandle;
        const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
        let mut len: i64 = 0;
        let mut returned = 0u32;
        // SAFETY: valid handle owned by `file`; output buffer is a live i64 of the stated size.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                (&mut len as *mut i64).cast(),
                8,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned != 8 {
            return Err(io::Error::last_os_error());
        }
        u64::try_from(len).map_err(|_| io::Error::other("negative length"))
    }

    #[cfg(unix)]
    fn size(file: &File) -> io::Result<u64> {
        use std::io::Seek;
        let mut f = file;
        f.seek(io::SeekFrom::End(0))
    }
}

impl Source for Live {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        let mut done = 0;
        let mut tmp = Vec::new();
        while done < buf.len() {
            let pos = offset + done as u64;
            let start = pos - pos % LIVE_ALIGN;
            let end = (start + LIVE_BLOCK).min(self.len);
            tmp.resize((end - start) as usize, 0);
            read_full(&self.file, start, &mut tmp)?;
            let within = (pos - start) as usize;
            let n = (tmp.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&tmp[within..within + n]);
            done += n;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("live volume {}, {}", self.name, human_size(self.len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sediment-image-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8).collect()
    }

    fn descriptor(kind: &str, next: u64, size: u64) -> Vec<u8> {
        let mut d = vec![0u8; 76];
        d[..kind.len()].copy_from_slice(kind.as_bytes());
        d[16..24].copy_from_slice(&next.to_le_bytes());
        d[24..32].copy_from_slice(&size.to_le_bytes());
        let c = adler32(&d[..72]);
        d[72..].copy_from_slice(&c.to_le_bytes());
        d
    }

    struct Geometry {
        spc: u32,
        bps: u32,
        sectors: u64,
    }

    /// One EWF v1 segment: optional volume, sectors with the given chunks (data, compress), table, done/next.
    fn build_segment(number: u16, volume: Option<&Geometry>, chunks: &[(Vec<u8>, bool)], last: bool) -> Vec<u8> {
        let mut f = EVF_SIGNATURE.to_vec();
        f.push(1);
        f.extend_from_slice(&number.to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        if let Some(g) = volume {
            let mut v = vec![0u8; 1052];
            v[0] = 1;
            v[8..12].copy_from_slice(&g.spc.to_le_bytes());
            v[12..16].copy_from_slice(&g.bps.to_le_bytes());
            v[16..24].copy_from_slice(&g.sectors.to_le_bytes());
            let start = f.len() as u64;
            f.extend(descriptor("volume", start + 76 + 1052, 76 + 1052));
            f.extend(v);
        }
        let sectors_start = f.len() as u64;
        let mut body = Vec::new();
        let mut entries = Vec::new();
        for (data, compress) in chunks {
            let rel = 76 + body.len() as u32;
            if *compress {
                let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
                z.write_all(data).unwrap();
                body.extend(z.finish().unwrap());
                entries.push(rel | 0x8000_0000);
            } else {
                body.extend_from_slice(data);
                body.extend(adler32(data).to_le_bytes());
                entries.push(rel);
            }
        }
        let size = 76 + body.len() as u64;
        f.extend(descriptor("sectors", sectors_start + size, size));
        f.extend(body);
        let table_start = f.len() as u64;
        let mut t = Vec::new();
        t.extend((entries.len() as u32).to_le_bytes());
        t.extend([0u8; 4]);
        t.extend(sectors_start.to_le_bytes());
        t.extend([0u8; 4]);
        t.extend(adler32(&t.clone()).to_le_bytes());
        let mut raw = Vec::new();
        for e in &entries {
            raw.extend(e.to_le_bytes());
        }
        t.extend(&raw);
        t.extend(adler32(&raw).to_le_bytes());
        let size = 76 + t.len() as u64;
        f.extend(descriptor("table", table_start + size, size));
        f.extend(t);
        let end = f.len() as u64;
        f.extend(descriptor(if last { "done" } else { "next" }, end, 76));
        f
    }

    fn mem_ewf(segments: Vec<Vec<u8>>) -> Result<Ewf, String> {
        let mut b = EwfBuilder::default();
        for (i, s) in segments.into_iter().enumerate() {
            let len = s.len() as u64;
            b.add(Segment { data: SegData::Mem(s), len }, i as u32 + 1)?;
        }
        b.finish()
    }

    fn sample() -> (Vec<u8>, Vec<u8>) {
        let media = pattern(1536, 7);
        let g = Geometry { spc: 2, bps: 512, sectors: 3 };
        let seg = build_segment(1, Some(&g), &[(media[..1024].to_vec(), true), (media[1024..].to_vec(), false)], true);
        (seg, media)
    }

    #[test]
    fn raw_split_reads_across_boundary() {
        let dir = temp_dir("split");
        let media = pattern(1500, 3);
        std::fs::write(dir.join("disk.001"), &media[..1000]).unwrap();
        std::fs::write(dir.join("disk.002"), &media[1000..]).unwrap();
        let src = open(&dir.join("disk.001")).unwrap();
        assert_eq!(src.len(), 1500);
        assert!(src.describe().contains("2 parts"));
        let mut buf = vec![0u8; 200];
        src.read_at(900, &mut buf).unwrap();
        assert_eq!(buf, &media[900..1100]);
        let mut all = vec![0u8; 1500];
        src.read_at(0, &mut all).unwrap();
        assert_eq!(all, media);
        assert!(src.read_at(1400, &mut buf).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn synthetic_e01_reads_back() {
        let dir = temp_dir("e01");
        let (seg, media) = sample();
        std::fs::write(dir.join("img.E01"), &seg).unwrap();
        let src = open(&dir.join("img.E01")).unwrap();
        assert_eq!(src.len(), 1536);
        assert!(src.describe().starts_with("E01 image, 1 segment"), "{}", src.describe());
        let mut all = vec![0u8; 1536];
        src.read_at(0, &mut all).unwrap();
        assert_eq!(all, media);
        let mut buf = vec![0u8; 100];
        src.read_at(1000, &mut buf).unwrap();
        assert_eq!(buf, &media[1000..1100]);
        assert!(src.read_at(1500, &mut buf).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn synthetic_e01_multi_segment() {
        let dir = temp_dir("e01multi");
        let media = pattern(4096, 11);
        let g = Geometry { spc: 2, bps: 512, sectors: 8 };
        let s1 = build_segment(1, Some(&g), &[(media[..1024].to_vec(), true), (media[1024..2048].to_vec(), false)], false);
        let s2 = build_segment(2, None, &[(media[2048..3072].to_vec(), false), (media[3072..].to_vec(), true)], true);
        std::fs::write(dir.join("img.e01"), &s1).unwrap();
        std::fs::write(dir.join("img.e02"), &s2).unwrap();
        for name in ["img.e01", "img.e02"] {
            let src = open(&dir.join(name)).unwrap();
            assert!(src.describe().contains("2 segments"), "{}", src.describe());
            let mut all = vec![0u8; 4096];
            src.read_at(0, &mut all).unwrap();
            assert_eq!(all, media);
            let mut buf = vec![0u8; 300];
            src.read_at(1900, &mut buf).unwrap();
            assert_eq!(buf, &media[1900..2200]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn segment_names() {
        assert_eq!(segment_extension('E', 1).unwrap(), "E01");
        assert_eq!(segment_extension('E', 99).unwrap(), "E99");
        assert_eq!(segment_extension('E', 100).unwrap(), "EAA");
        assert_eq!(segment_extension('E', 101).unwrap(), "EAB");
        assert_eq!(segment_extension('e', 126).unwrap(), "eba");
        assert_eq!(segment_extension('E', 776).unwrap(), "FAA");
        assert!(segment_extension('Z', 776).is_none());
    }

    #[test]
    fn rejects_other_formats() {
        let dir = temp_dir("formats");
        let mut ewf2 = b"EVF2\r\n\x81\x00".to_vec();
        ewf2.extend([0u8; 64]);
        std::fs::write(dir.join("a.Ex01"), &ewf2).unwrap();
        assert!(open(&dir.join("a.Ex01")).err().unwrap().contains("EWF2"));
        let (seg, _) = sample();
        std::fs::write(dir.join("a.s01"), &seg).unwrap();
        assert!(open(&dir.join("a.s01")).err().unwrap().contains("SMART"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_e01_is_an_error() {
        let mut junk = EVF_SIGNATURE.to_vec();
        junk.extend(pattern(5000, 99));
        assert!(mem_ewf(vec![junk]).is_err());
        assert!(mem_ewf(vec![EVF_SIGNATURE.to_vec()]).is_err());

        let (seg, media) = sample();
        for cut in 0..seg.len() {
            if let Ok(e) = mem_ewf(vec![seg[..cut].to_vec()]) {
                let mut buf = vec![0u8; 1536];
                if e.read_at(0, &mut buf).is_ok() {
                    assert_eq!(buf, media);
                }
            }
        }
        for i in 0..seg.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut bad = seg.clone();
                bad[i] ^= flip;
                if let Ok(e) = mem_ewf(vec![bad]) {
                    let mut buf = vec![0u8; e.len().min(1 << 20) as usize];
                    let _ = e.read_at(0, &mut buf);
                    let _ = e.describe();
                }
            }
        }
    }

    #[test]
    fn huge_claims_are_rejected() {
        let g = Geometry { spc: 1 << 20, bps: 4096, sectors: 3 };
        let seg = build_segment(1, Some(&g), &[(vec![0; 16], true)], true);
        assert!(mem_ewf(vec![seg]).err().unwrap().contains("chunk size"));
        let g = Geometry { spc: 2, bps: 512, sectors: u64::MAX };
        let seg = build_segment(1, Some(&g), &[(vec![0; 1024], true)], true);
        assert!(mem_ewf(vec![seg]).is_err());
    }

    /// The public nps-2009-ntfs1 images (digitalcorpora.org), from the
    /// folder in SEDIMENT_NTFS1.
    fn scratch_e01s() -> Vec<PathBuf> {
        let Some(dir) = std::env::var_os("SEDIMENT_NTFS1").map(PathBuf::from) else {
            return Vec::new();
        };
        ["ntfs1-gen2.E01", "ntfs1-gen1.E01"].iter().map(|n| dir.join(n)).collect()
    }

    #[test]
    #[ignore]
    fn live_e01_md5() {
        use md5::{Digest, Md5};
        for path in scratch_e01s() {
            if !path.exists() {
                eprintln!("skip {}", path.display());
                continue;
            }
            let ewf = Ewf::open(&path).unwrap();
            let stored = ewf.md5.expect("image carries an MD5");
            let src: &dyn Source = &ewf;
            let mut head = [0u8; 11];
            src.read_at(0, &mut head).unwrap();
            assert_eq!(&head[3..11], b"NTFS    ");
            let started = std::time::Instant::now();
            let mut h = Md5::new();
            let mut buf = vec![0u8; 1 << 20];
            let mut pos = 0u64;
            while pos < src.len() {
                let n = (src.len() - pos).min(buf.len() as u64) as usize;
                src.read_at(pos, &mut buf[..n]).unwrap();
                h.update(&buf[..n]);
                pos += n as u64;
            }
            let got: [u8; 16] = h.finalize().into();
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            eprintln!(
                "{}: {} | md5 {} (stored {}) in {:?}",
                path.display(),
                src.describe(),
                hex(&got),
                hex(&stored),
                started.elapsed()
            );
            assert_eq!(got, stored);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn live_volume_c() {
        match open(Path::new(r"\\.\C:")) {
            Ok(src) => {
                let mut b = [0u8; 8];
                src.read_at(3, &mut b).unwrap();
                eprintln!("{} oem {:?}", src.describe(), String::from_utf8_lossy(&b));
            }
            Err(e) => {
                eprintln!("{e}");
                assert!(e.contains("administrator"), "{e}");
            }
        }
    }
}
