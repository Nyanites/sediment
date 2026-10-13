//! Pure-Rust LZ77 + Huffman ("Xpress Huffman") decompression, as specified in
//! [MS-XCA] §2.2. Windows 10+ prefetch files are compressed with it; doing it
//! here instead of through ntdll keeps Sediment working on macOS and Linux.

const BLOCK_OUTPUT: usize = 65536;
const TABLE_BYTES: usize = 256;
const SYMBOLS: usize = 512;
const MAX_BITS: u32 = 15;

#[derive(Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Xpress Huffman: {}", self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Input<'_> {
    fn u8(&mut self) -> Result<u8, Error> {
        let b = *self.data.get(self.pos).ok_or(Error("unexpected end of input".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }

    /// Like `u16`, but reads past the end as zeros: the bit reader always
    /// keeps up to 32 bits buffered, which can run a little past the data.
    fn u16_or_zero(&mut self) -> u16 {
        let lo = self.data.get(self.pos).copied().unwrap_or(0);
        let hi = self.data.get(self.pos + 1).copied().unwrap_or(0);
        self.pos += 2;
        u16::from_le_bytes([lo, hi])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
}

/// Canonical Huffman decoding table indexed by the next 15 input bits.
struct Table {
    symbols: Vec<u16>,
    lengths: [u8; SYMBOLS],
}

impl Table {
    fn read(input: &mut Input) -> Result<Self, Error> {
        let raw = input
            .data
            .get(input.pos..input.pos + TABLE_BYTES)
            .ok_or(Error("truncated Huffman table".into()))?;
        input.pos += TABLE_BYTES;
        let mut lengths = [0u8; SYMBOLS];
        for (i, b) in raw.iter().enumerate() {
            lengths[2 * i] = b & 0x0F;
            lengths[2 * i + 1] = b >> 4;
        }

        let mut symbols = vec![0u16; 1 << MAX_BITS];
        let mut next = 0usize;
        // Codes are assigned in order of (length, symbol).
        for len in 1..=MAX_BITS as u8 {
            for (sym, &l) in lengths.iter().enumerate() {
                if l != len {
                    continue;
                }
                let span = 1usize << (MAX_BITS as u8 - len);
                if next + span > symbols.len() {
                    return err("over-subscribed Huffman table");
                }
                symbols[next..next + span].fill(sym as u16);
                next += span;
            }
        }
        if next == 0 {
            return err("empty Huffman table");
        }
        Ok(Self { symbols, lengths })
    }
}

/// Decompresses `data`, which must expand to exactly `output_size` bytes.
pub fn decompress(data: &[u8], output_size: usize) -> Result<Vec<u8>, Error> {
    // Every 64 KiB block starts with its own 256-byte table, so the input
    // bounds the output; reject impossible sizes before allocating them.
    if output_size.div_ceil(BLOCK_OUTPUT) > data.len() / TABLE_BYTES {
        return err(format!(
            "{} bytes of input cannot expand to {output_size} bytes",
            data.len()
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(output_size);
    let mut input = Input { data, pos: 0 };

    while out.len() < output_size {
        let table = Table::read(&mut input)?;

        let mut bits: u32 = (u32::from(input.u16_or_zero()) << 16) | u32::from(input.u16_or_zero());
        let mut extra: i32 = 16;
        let block_end = (out.len() + BLOCK_OUTPUT).min(output_size);

        macro_rules! consume {
            ($n:expr) => {{
                let n: u32 = $n;
                bits = if n == 32 { 0 } else { bits << n };
                extra -= n as i32;
                if extra < 0 {
                    bits |= u32::from(input.u16_or_zero()) << (-extra) as u32;
                    extra += 16;
                }
            }};
        }

        while out.len() < block_end {
            let symbol = table.symbols[(bits >> (32 - MAX_BITS)) as usize] as usize;
            let len = table.lengths[symbol];
            if len == 0 {
                return err("invalid Huffman code");
            }
            consume!(u32::from(len));

            if symbol < 256 {
                out.push(symbol as u8);
                continue;
            }

            let symbol = symbol - 256;
            let offset_bits = (symbol >> 4) as u32;
            let mut length = symbol & 0x0F;
            if length == 15 {
                length = input.u8()? as usize;
                if length == 255 {
                    length = input.u16()? as usize;
                    if length == 0 {
                        length = input.u32()? as usize;
                    }
                    if length < 15 {
                        return err("invalid match length");
                    }
                    length -= 15;
                }
                length = length.saturating_add(15);
            }
            length = length.saturating_add(3);

            let offset = if offset_bits == 0 {
                1
            } else {
                ((bits >> (32 - offset_bits)) as usize) | (1 << offset_bits)
            };
            consume!(offset_bits);

            if offset > out.len() {
                return err(format!(
                    "match offset {offset} points before the start of the output ({} bytes)",
                    out.len()
                ));
            }
            // Matches may overlap their own output, so copy byte by byte.
            let start = out.len() - offset;
            for i in 0..length {
                if out.len() >= output_size {
                    break;
                }
                let b = out[start + i];
                out.push(b);
            }
        }

        // Any bits still buffered are padding; the next block's table starts
        // where the byte reader left off.
    }
    out.truncate(output_size);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(windows)]
    pub(crate) mod native {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn RtlGetCompressionWorkSpaceSize(f: u16, ws: *mut u32, frag: *mut u32) -> i32;
            fn RtlCompressBuffer(
                f: u16,
                src: *const u8,
                src_len: u32,
                dst: *mut u8,
                dst_len: u32,
                chunk: u32,
                final_len: *mut u32,
                ws: *mut u8,
            ) -> i32;
        }

        /// Compresses with Windows' own Xpress Huffman encoder (format 4).
        pub fn compress(data: &[u8]) -> Vec<u8> {
            let (mut ws, mut frag) = (0u32, 0u32);
            assert!(unsafe { RtlGetCompressionWorkSpaceSize(4, &mut ws, &mut frag) } >= 0);
            let mut workspace = vec![0u8; ws as usize];
            let mut out = vec![0u8; data.len() + 4096];
            let mut n = 0u32;
            let status = unsafe {
                RtlCompressBuffer(
                    4,
                    data.as_ptr(),
                    data.len() as u32,
                    out.as_mut_ptr(),
                    out.len() as u32,
                    4096,
                    &mut n,
                    workspace.as_mut_ptr(),
                )
            };
            assert!(status >= 0, "RtlCompressBuffer failed: {status:#X}");
            out.truncate(n as usize);
            out
        }
    }

    /// Deterministic test input: text, very long runs and high-entropy bytes.
    fn sample_text() -> Vec<u8> {
        let mut text = Vec::new();
        let mut seed = 0x1234_5678u32;
        for i in 0..40_000u32 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            text.extend_from_slice(format!("line {i} value {} ", seed % 977).as_bytes());
            if i % 1000 == 0 {
                text.extend(std::iter::repeat_n(b'A', 5000)); // very long match
            }
            if i % 7 == 0 {
                text.push((seed >> 24) as u8); // some high-entropy bytes
            }
        }
        text
    }

    /// Sizes frozen in `tests/fixtures`: tiny, one block, just over one
    /// block, and several blocks.
    const FIXTURE_SIZES: [usize; 4] = [17, 4096, 65537, 200_000];

    fn fixture_path(size: usize) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("xpress_{size}.bin"))
    }

    /// Decodes output of Windows' own encoder, frozen in `tests/fixtures`, so
    /// macOS and Linux are checked against real Windows-compressed data.
    #[test]
    fn decodes_windows_fixtures() {
        let text = sample_text();
        for size in FIXTURE_SIZES {
            let packed = std::fs::read(fixture_path(size)).expect("fixture present");
            let unpacked = decompress(&packed, size).unwrap_or_else(|e| panic!("size {size}: {e}"));
            assert!(unpacked == text[..size], "size {size}: output differs");
        }
    }

    /// Regenerates the fixtures with Windows' encoder:
    /// `cargo test -- --ignored write_windows_fixtures`.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn write_windows_fixtures() {
        let text = sample_text();
        std::fs::create_dir_all(fixture_path(0).parent().unwrap()).unwrap();
        for size in FIXTURE_SIZES {
            std::fs::write(fixture_path(size), native::compress(&text[..size])).unwrap();
        }
    }

    /// Round-trips data through Windows' encoder and our decoder, including
    /// inputs spanning several 64 KiB blocks and long matches.
    #[cfg(windows)]
    #[test]
    fn matches_windows_encoder() {
        let text = sample_text();
        for size in [1usize, 17, 4096, 65535, 65536, 65537, 200_000, text.len()] {
            let data = &text[..size.min(text.len())];
            let packed = native::compress(data);
            let unpacked = decompress(&packed, data.len())
                .unwrap_or_else(|e| panic!("size {size}: {e}"));
            assert!(unpacked == data, "size {size}: output differs");
        }
    }
}
