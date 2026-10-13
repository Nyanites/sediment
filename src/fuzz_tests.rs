//! Deterministic fuzzing: random bytes and mutated valid inputs go through
//! every parser entry point. Any panic fails the test, and with it the build
//! that would otherwise crash on a hostile evidence file.

use std::sync::atomic::AtomicUsize;

use crate::extract::{self, tests::fake_record};
use crate::mft::{self, MftFile, Record};
use crate::usn::{UsnJournal, UsnMax};
use crate::{prefetch, xpress};

/// Iterations per target; debug builds are much slower.
pub(crate) const ITERS: usize = if cfg!(debug_assertions) { 300 } else { 20_000 };

/// xorshift64*: tiny and deterministic, plenty for driving mutations.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Up to `max - 1` random bytes.
    pub(crate) fn junk(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.bytes(n)
    }

    /// Values that tend to break length and offset arithmetic.
    pub(crate) fn interesting(&mut self, len: usize) -> u64 {
        const V: [u64; 13] =
            [0, 1, 2, 3, 7, 8, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0xFFFF_FFFF];
        match self.below(4) {
            0 | 1 => V[self.below(V.len())],
            2 => (len as u64).wrapping_add(self.below(17) as u64).wrapping_sub(8),
            _ => self.next(),
        }
    }
}

/// Writes `v` little-endian as a `width`-byte field at `off`, clipped to `b`.
pub(crate) fn poke(b: &mut [u8], off: usize, width: usize, v: u64) {
    for (i, &byte) in v.to_le_bytes()[..width].iter().enumerate() {
        if let Some(x) = b.get_mut(off + i) {
            *x = byte;
        }
    }
}

/// A few random edits: bit flips, byte and field overwrites, truncation,
/// extension and chunk copies.
pub(crate) fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(6) {
        let len = b.len();
        match rng.below(7) {
            0 if len > 0 => {
                let i = rng.below(len);
                b[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                b[i] = rng.next() as u8;
            }
            2 | 3 => {
                let width = [1, 2, 4, 8][rng.below(4)];
                let (off, v) = (rng.below(len.max(1)), rng.interesting(len));
                poke(&mut b, off, width, v);
            }
            4 => b.truncate(rng.below(len + 1)),
            5 => {
                let extra = rng.junk(64);
                b.extend(extra);
            }
            _ if len > 1 => {
                let n = rng.below(len.min(64));
                let (src, dst) = (rng.below(len - n), rng.below(len - n));
                b.copy_within(src..src + n, dst);
            }
            _ => {}
        }
    }
    b
}

/// Pokes interesting values into some of the given `(offset, width)` fields.
fn poke_fields(rng: &mut Rng, b: &mut [u8], fields: &[(usize, usize)]) {
    for _ in 0..1 + rng.below(4) {
        let (off, width) = fields[rng.below(fields.len())];
        let v = rng.interesting(b.len());
        poke(b, off, width, v);
    }
}

// ---------------------------------------------------------------- $MFT

/// `fake_record` with its unnamed `$DATA` turned non-resident, with a few
/// data runs (normal, negative delta, sparse).
fn nonresident_record() -> Vec<u8> {
    let mut r = fake_record(&[0u8; 64]);
    let o = Record::parse(&r).attributes[2].offset;
    r[o + 8] = 1;
    poke(&mut r, o + 16, 8, 0); // start VCN
    poke(&mut r, o + 24, 8, 0x1F); // last VCN
    poke(&mut r, o + 32, 2, 64); // runs offset
    for f in [40, 48, 56] {
        poke(&mut r, o + f, 8, 0x2_0000);
    }
    let runs = [0x21, 0x10, 0x00, 0x01, 0x31, 0x05, 0x34, 0x12, 0x00, 0x11, 0x02, 0xFE, 0x01, 0x03, 0x00];
    r[o + 64..o + 64 + runs.len()].copy_from_slice(&runs);
    r
}

/// Header and per-attribute fields of a FILE record worth targeting.
fn record_fields(rec: &[u8]) -> Vec<(usize, usize)> {
    let mut f = vec![(4, 2), (6, 2), (16, 2), (20, 2), (22, 2), (24, 4), (28, 4), (32, 8)];
    for a in Record::parse(rec).attributes {
        let o = a.offset;
        f.extend([(o, 4), (o + 4, 4), (o + 8, 1), (o + 9, 1), (o + 10, 2), (o + 16, 4)]);
        f.extend([(o + 20, 2), (o + 16, 8), (o + 32, 2), (o + 64, 1), (o + 65, 1), (o + 68, 1)]);
        if let mft::AttrBody::Resident { content_offset: c, .. } = a.body {
            f.extend([(c, 8), (c + 64, 1)]); // $FILE_NAME parent and name length
        }
    }
    f
}

/// Offset of the first `$FILE_NAME` content in `rec`.
fn fn_content(rec: &[u8]) -> usize {
    Record::parse(rec)
        .attributes
        .iter()
        .find_map(|a| match a.body {
            mft::AttrBody::Resident { content_offset, .. } if a.type_code == mft::ATTR_FILE_NAME => {
                Some(content_offset)
            }
            _ => None,
        })
        .unwrap()
}

/// A small `$MFT`: in-use directories pointing at random parents, so the
/// path and tree builders see orphans, loops and self references.
pub(crate) fn mft_seed(rng: &mut Rng, count: usize) -> Vec<u8> {
    let (plain, nonres) = (fake_record(b"x"), nonresident_record());
    let mut out = Vec::new();
    for i in 0..count {
        let mut r = if i % 2 == 0 { plain.clone() } else { nonres.clone() };
        poke(&mut r, 22, 2, 3); // in use, directory
        let parent = if i == mft::ROOT_RECORD { i } else { rng.below(count) };
        let c = fn_content(&r);
        poke(&mut r, c, 8, parent as u64 | 1 << 48);
        if rng.below(8) == 0 {
            poke(&mut r, 32, 8, rng.below(count + 2) as u64); // extension record
        }
        out.extend(r);
    }
    out
}

/// Calls everything the UI calls on a parsed record.
fn exercise_record(rec: &Record, no: usize) {
    let _ = (rec.is_valid(), rec.in_use(), rec.is_dir());
    for a in &rec.attributes {
        let _ = (a.data_size(), a.resident_content(&rec.data));
        let _ = (a.standard_info(&rec.data), a.file_name(&rec.data));
    }
    let _ = (extract::streams(rec).len(), extract::file_name(rec));
    let _ = (extract::resident_zip(rec, no), extract::zip_file_name(rec, no));
}

fn exercise_mft(raw: Vec<u8>) {
    let f = MftFile::load(raw, &AtomicUsize::new(0));
    for i in 0..f.entries.len() + 2 {
        exercise_record(&f.parse_record(i), i);
    }
    for e in &f.entries {
        assert!(e.path.len() <= 9 * 1024, "path of {} bytes", e.path.len());
        let _ = (e.timestomp_suspect(), e.parent_indices().count());
    }
}

#[test]
fn fuzz_record_parse() {
    let mut rng = Rng::new(0x5EED_0001);
    let seeds = [fake_record(b"Hello, fuzzer"), nonresident_record()];
    let fields: Vec<_> = seeds.iter().map(|s| record_fields(s)).collect();
    for len in 0..=64 {
        exercise_record(&Record::parse(&rng.bytes(len)), len);
    }
    for i in 0..ITERS * 4 {
        let k = rng.below(seeds.len());
        let mut b = seeds[k].clone();
        poke_fields(&mut rng, &mut b, &fields[k]);
        if rng.below(2) == 0 {
            b = mutate(&mut rng, &b);
        }
        exercise_record(&Record::parse(&b), i);
        // Random bytes behind a valid signature reach the attribute parser.
        let mut junk = rng.junk(1100);
        if junk.len() >= 4 {
            junk[..4].copy_from_slice(b"FILE");
        }
        exercise_record(&Record::parse(&junk), i);
    }
}

#[test]
fn fuzz_mft_load() {
    let mut rng = Rng::new(0x5EED_0002);
    for len in [0, 1, 3, 4, 31, 32, 255, 256, 1023, 1025] {
        let mut b = rng.bytes(len);
        if len >= 4 {
            b[..4].copy_from_slice(b"FILE");
        }
        exercise_mft(b);
    }
    let fields = record_fields(&nonresident_record());
    for _ in 0..ITERS / 10 {
        let count = 4 + rng.below(16);
        let mut b = mft_seed(&mut rng, count);
        for _ in 0..rng.below(8) {
            let base = rng.below(count) * 1024;
            let (off, width) = fields[rng.below(fields.len())];
            let v = rng.interesting(1024);
            poke(&mut b, base + off, width, v);
        }
        match rng.below(4) {
            0 => poke(&mut b, 28, 4, [3, 255, 256, 512, 2048, 4096, 65536, 1 << 20][rng.below(8)]),
            1 => b = mutate(&mut rng, &b),
            _ => {}
        }
        exercise_mft(b);
    }
}

/// Paths stay bounded even for a directory chain thousands deep, and a `\`
/// inside a name cannot fake extra path components.
#[test]
fn mft_paths_are_bounded() {
    let count = 3000;
    let mut raw = Vec::new();
    for i in 0..count {
        let mut r = fake_record(b"x");
        poke(&mut r, 22, 2, 3);
        let parent = if i <= mft::ROOT_RECORD { mft::ROOT_RECORD } else { i - 1 };
        let c = fn_content(&r);
        poke(&mut r, c, 8, parent as u64 | 1 << 48);
        poke(&mut r, c + 66 + 6, 2, u64::from(b'\\')); // "rea\me.txt"
        raw.extend(r);
    }
    let f = MftFile::load(raw, &AtomicUsize::new(0));
    assert!(f.entries[6].path == "\\rea\u{FF3C}me.txt", "{}", f.entries[6].path);
    assert!(f.entries.iter().all(|e| e.path.len() <= 9 * 1024));
    assert!(f.entries[count - 1].path.starts_with("\\[Too long]\\"));
    assert!(f.record_bytes(count).is_empty() && f.record_bytes(usize::MAX).is_empty());
}

// ---------------------------------------------------------------- USN

fn usn_record(major: u16, name: &str, usn: u64) -> Vec<u8> {
    let name16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let rest = if major == 2 { 24 } else { 40 };
    let len = (rest + 36 + name16.len()).next_multiple_of(8);
    let mut r = vec![0u8; len];
    poke(&mut r, 0, 4, len as u64);
    poke(&mut r, 4, 2, u64::from(major));
    poke(&mut r, 8, 8, 100 | 1 << 48);
    poke(&mut r, if major == 2 { 16 } else { 24 }, 8, 5 | 5 << 48);
    poke(&mut r, rest, 8, usn);
    poke(&mut r, rest + 8, 8, 0x01DC_1B84_9F82_04B6);
    poke(&mut r, rest + 16, 4, 0x100);
    poke(&mut r, rest + 32, 2, name16.len() as u64);
    poke(&mut r, rest + 34, 2, (rest + 36) as u64);
    r[rest + 36..rest + 36 + name16.len()].copy_from_slice(&name16);
    r
}

/// A sparse first page, V2 and V3 records, page padding, then more records.
pub(crate) fn usn_seed() -> Vec<u8> {
    let mut j = vec![0u8; 4096];
    for i in 0..6 {
        j.extend(usn_record(2 + (i % 2) as u16, &format!("file{i}.txt"), 0x1000 + i * 0x60));
    }
    j.resize(8192, 0);
    j.extend(usn_record(3, "after-page.txt", 0x2000));
    j.extend(usn_record(2, "", 0x2100));
    j
}

fn exercise_journal(raw: Vec<u8>) {
    let _ = UsnJournal::sniff(&raw);
    let j = UsnJournal::load(raw, &AtomicUsize::new(0));
    for r in &j.records {
        assert_eq!(j.record_bytes(r).len(), r.length as usize);
    }
}

#[test]
fn fuzz_usn() {
    let mut rng = Rng::new(0x5EED_0003);
    let seed = usn_seed();
    let starts: Vec<usize> = {
        let j = UsnJournal::load(seed.clone(), &AtomicUsize::new(0));
        assert_eq!(j.records.len(), 8);
        j.records.iter().map(|r| r.offset as usize).collect()
    };
    for len in 0..64 {
        exercise_journal(rng.bytes(len));
    }
    for _ in 0..ITERS {
        let mut b = seed.clone();
        for _ in 0..1 + rng.below(4) {
            let s = starts[rng.below(starts.len())];
            let (off, width) = [(0, 4), (4, 2), (56, 2), (58, 2), (72, 2), (74, 2)][rng.below(6)];
            let v = rng.interesting(0x50);
            poke(&mut b, s + off, width, v);
        }
        if rng.below(2) == 0 {
            b = mutate(&mut rng, &b);
        }
        exercise_journal(b);
        exercise_journal(rng.junk(5000));
    }

    let max = [32u64 << 20, 8 << 20, 0x01DC_1B84_9F82_04B6, 0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<u8>>();
    assert!(UsnMax::parse(&max).is_some());
    for _ in 0..ITERS {
        let _ = UsnMax::parse(&mutate(&mut rng, &max));
        let _ = UsnMax::parse(&rng.bytes(32));
    }
}

// ---------------------------------------------------------------- Prefetch

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The prefetch fixture: (MAM-compressed file, its SCCA contents).
pub(crate) fn prefetch_seeds() -> (Vec<u8>, Vec<u8>) {
    let mam = fixture("EVIL.EXE-DEADBEEF.pf");
    let size = u32::from_le_bytes(mam[4..8].try_into().unwrap()) as usize;
    let scca = xpress::decompress(&mam[8..], size).unwrap();
    (mam, scca)
}

/// Calls everything the UI calls on a parsed prefetch file.
fn exercise_prefetch(raw: &[u8]) {
    let Ok(pf) = prefetch::parse(raw) else { return };
    let _ = (pf.executable_path(), pf.user_accounts(), pf.domains(), pf.known_tool());
    let _ = pf.capabilities();
    for n in pf.notable_files() {
        let _ = &pf.files[n.file_index];
    }
    for f in &pf.files {
        let _ = (pf.local_path(&f.filename), prefetch::strip_volume(&f.filename));
    }
    for t in &pf.trace_chains {
        assert!(t.file_index.is_none_or(|i| i < pf.files.len()));
    }
}

/// Table offsets and counts in the SCCA header, and the fields of the first
/// file metric and volume entry they point at.
fn scca_fields(scca: &[u8]) -> Vec<(usize, usize)> {
    let at = |o: usize| u32::from_le_bytes(scca[o..o + 4].try_into().unwrap()) as usize;
    let mut f: Vec<_> = (84..=116).step_by(4).map(|o| (o, 4)).collect();
    f.extend([(0, 4), (12, 4), (16, 2)]);
    f.extend((0..32).step_by(4).map(|o| (at(84) + o, 4)));
    f.extend((0..36).step_by(4).map(|o| (at(108) + o, 4)));
    f
}

#[test]
fn fuzz_prefetch() {
    let mut rng = Rng::new(0x5EED_0004);
    let (mam, scca) = prefetch_seeds();
    exercise_prefetch(&mam);
    let fields = scca_fields(&scca);
    for _ in 0..ITERS {
        // Raw SCCA, as every version the parser knows.
        let mut b = scca.clone();
        poke(&mut b, 0, 4, [17, 23, 26, 30, 31][rng.below(5)]);
        poke_fields(&mut rng, &mut b, &fields);
        if rng.below(2) == 0 {
            b = mutate(&mut rng, &b);
        }
        exercise_prefetch(&b);

        // MAM: damaged compressed stream and size field. Kept on Xpress
        // Huffman so the fuzzer never feeds ntdll.
        let mut m = mutate(&mut rng, &mam);
        if m.len() >= 8 {
            m[..3].copy_from_slice(b"MAM");
            m[3] = (m[3] & 0xF0) | 4;
            if rng.below(3) == 0 {
                let v = rng.interesting(scca.len());
                poke(&mut m, 4, 4, v);
            }
        }
        exercise_prefetch(&m);

        let mut junk = rng.junk(600);
        if junk.len() >= 8 {
            junk[4..8].copy_from_slice(b"SCCA");
        }
        exercise_prefetch(&junk);
    }
}

/// Header counts claiming billions of entries fail cleanly instead of
/// reserving hundreds of gigabytes.
#[test]
fn prefetch_huge_counts() {
    let (_, scca) = prefetch_seeds();
    for (off, v) in [(88, u32::MAX), (96, u32::MAX), (112, u32::MAX)] {
        let mut b = scca.clone();
        poke(&mut b, off, 4, v.into());
        assert!(prefetch::parse(&b).is_err(), "count at {off}");
    }
    // Directory count of the first volume.
    let mut b = scca.clone();
    let vol = u32::from_le_bytes(b[108..112].try_into().unwrap()) as usize;
    poke(&mut b, vol + 32, 4, u32::MAX.into());
    assert!(prefetch::parse(&b).is_err());
}

/// Thousands of file metrics sharing one huge name and one huge trace chain
/// range: decoding stays linear in the file size.
#[test]
fn prefetch_overlapping_tables() {
    let (metrics, chains) = (20_000usize, 100_000usize);
    let (m_off, c_off) = (0x130, 0x130 + metrics * 32);
    let n_off = c_off + chains * 8;
    let name_chars = 200_000;
    let mut b = vec![0u8; n_off + name_chars * 2];
    poke(&mut b, 0, 4, 30);
    b[4..8].copy_from_slice(b"SCCA");
    for (off, v) in [(84, m_off), (88, metrics), (92, c_off), (96, chains), (100, n_off)] {
        poke(&mut b, off, 4, v as u64);
    }
    for i in 0..metrics {
        let m = m_off + i * 32;
        poke(&mut b, m + 4, 4, chains as u64); // every metric claims every chain
        poke(&mut b, m + 16, 4, name_chars as u64); // and the whole name table
    }
    for i in (n_off..b.len()).step_by(2) {
        b[i] = b'A';
    }
    let t = std::time::Instant::now();
    let pf = prefetch::parse(&b).unwrap();
    assert!(t.elapsed().as_secs() < 5, "took {:?}", t.elapsed());
    let decoded: usize = pf.files.iter().map(|f| f.filename.len()).sum();
    assert!(decoded <= 2 * b.len(), "{decoded} bytes of names from {} bytes", b.len());
    assert!(pf.trace_chains.iter().all(|t| t.file_index == Some(metrics - 1)));
}

// ---------------------------------------------------------------- Xpress

#[test]
fn fuzz_xpress() {
    let mut rng = Rng::new(0x5EED_0005);
    let fixtures: Vec<(usize, Vec<u8>)> = [17, 4096, 65537, 200_000]
        .into_iter()
        .map(|n| (n, fixture(&format!("xpress_{n}.bin"))))
        .collect();
    for i in 0..ITERS / 2 {
        // Mostly the small fixtures: the big ones cost a full decode each.
        let (size, packed) = &fixtures[if i % 16 == 0 { 2 + i / 16 % 2 } else { i % 2 }];
        let m = mutate(&mut rng, packed);
        let _ = xpress::decompress(&m, *size);
        let n = rng.interesting(*size) as usize;
        if let Ok(out) = xpress::decompress(&m, n) {
            assert_eq!(out.len(), n);
        }
        let junk = rng.junk(2000);
        let _ = xpress::decompress(&junk, rng.below(1 << 20));
    }
}

/// A size field claiming gigabytes is rejected before anything is allocated.
#[test]
fn xpress_rejects_impossible_sizes() {
    let packed = fixture("xpress_4096.bin");
    for size in [65_537 * 2, u32::MAX as usize, usize::MAX] {
        assert!(xpress::decompress(&packed, size).is_err());
    }
    let mut mam = b"MAM\x04".to_vec();
    mam.extend((200u32 << 20).to_le_bytes());
    mam.extend(&packed);
    assert!(prefetch::parse(&mam).is_err());
}
