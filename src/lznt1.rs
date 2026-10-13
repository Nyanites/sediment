//! Pure-Rust LZNT1 decompression, as specified in [MS-XCA] §2.5. NTFS stores
//! compressed files as compression units of LZNT1 chunks, each of which
//! expands to at most 4 KiB.

const CHUNK_OUTPUT: usize = 4096;
const SIZE_MASK: u16 = 0x0FFF;
const COMPRESSED: u16 = 0x8000;

fn err<T>(msg: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("LZNT1: {msg}"))
}

/// Length bits of a back-reference token made `pos` bytes into a chunk's
/// output: 12 up to position 16, one fewer each time `pos` doubles, 4 from
/// position 2049. The remaining high bits hold the offset.
fn length_bits(pos: usize) -> u32 {
    let mut bits = 12;
    let mut i = pos.saturating_sub(1);
    while i >= 16 {
        bits -= 1;
        i >>= 1;
    }
    bits
}

/// Expands one compressed chunk's data into `out` (the chunk's output window,
/// at most 4 KiB) and returns the number of bytes written.
fn decompress_chunk(data: &[u8], out: &mut [u8]) -> Result<usize, String> {
    let mut src = 0;
    let mut pos = 0;
    while src < data.len() {
        let flags = data[src];
        src += 1;
        for bit in 0..8 {
            if src >= data.len() {
                break;
            }
            if flags & (1 << bit) == 0 {
                *out.get_mut(pos).ok_or("LZNT1: chunk output overflow")? = data[src];
                src += 1;
                pos += 1;
                continue;
            }
            let Some(&[lo, hi]) = data.get(src..src + 2) else {
                return err("truncated back-reference");
            };
            src += 2;
            let token = u16::from_le_bytes([lo, hi]) as usize;
            let bits = length_bits(pos);
            let len = (token & ((1 << bits) - 1)) + 3;
            let offset = (token >> bits) + 1;
            if offset > pos {
                return err(format!(
                    "back-reference {offset} before chunk start at {pos}"
                ));
            }
            if pos + len > out.len() {
                return err("chunk output overflow");
            }
            // Byte by byte: source and destination may overlap.
            for i in pos..pos + len {
                out[i] = out[i - offset];
            }
            pos += len;
        }
    }
    Ok(pos)
}

/// Decompresses one NTFS compression unit. Output is `out_size` bytes: the
/// unit's data followed by zeros when the compressed stream ends early (a
/// zero chunk header), as NTFS does.
pub fn decompress(input: &[u8], out_size: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; out_size];
    let mut src = 0;
    let mut chunk_start = 0;
    // A lone trailing byte cannot hold a header; treat it like the end.
    while let Some(&[lo, hi]) = input.get(src..src + 2) {
        let header = u16::from_le_bytes([lo, hi]);
        if header == 0 {
            break;
        }
        if chunk_start >= out_size {
            return err("chunk past the end of the output");
        }
        // The signature (bits 12-14, normally 3) is not checked, like Windows.
        let size = (header & SIZE_MASK) as usize + 1;
        let Some(data) = input.get(src + 2..src + 2 + size) else {
            return err(format!("chunk at {src} claims {size} bytes past the input"));
        };
        src += 2 + size;
        let window_end = out_size.min(chunk_start + CHUNK_OUTPUT);
        let window = &mut out[chunk_start..window_end];
        if header & COMPRESSED != 0 {
            decompress_chunk(data, window)?;
        } else {
            let Some(dest) = window.get_mut(..size) else {
                return err("stored chunk overflows the output");
            };
            dest.copy_from_slice(data);
        }
        // Chunks shorter than 4 KiB are zero-padded, so every chunk starts
        // on a 4 KiB boundary of the output.
        chunk_start += CHUNK_OUTPUT;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Greedy test-only compressor following the same token layout.
    fn compress_chunk(chunk: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut pos = 0;
        while pos < chunk.len() {
            let flag_at = body.len();
            body.push(0u8);
            for bit in 0..8 {
                if pos >= chunk.len() {
                    break;
                }
                let bits = length_bits(pos);
                let max_len = ((1usize << bits) - 1 + 3).min(chunk.len() - pos);
                let max_offset = (1usize << (16 - bits)).min(pos);
                let (mut best_len, mut best_off) = (0, 0);
                for offset in 1..=max_offset {
                    let mut len = 0;
                    while len < max_len && chunk[pos + len - offset] == chunk[pos + len] {
                        len += 1;
                    }
                    if len > best_len {
                        (best_len, best_off) = (len, offset);
                        if len == max_len {
                            break;
                        }
                    }
                }
                if best_len >= 3 {
                    let token = ((best_off - 1) << bits) | (best_len - 3);
                    body.extend_from_slice(&(token as u16).to_le_bytes());
                    body[flag_at] |= 1 << bit;
                    pos += best_len;
                } else {
                    body.push(chunk[pos]);
                    pos += 1;
                }
            }
        }
        body
    }

    fn compress(data: &[u8], force_stored: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(CHUNK_OUTPUT) {
            let body = compress_chunk(chunk);
            if force_stored || body.len() >= chunk.len() {
                out.extend_from_slice(&(0x3000 | (chunk.len() - 1) as u16).to_le_bytes());
                out.extend_from_slice(chunk);
            } else {
                out.extend_from_slice(&(0xB000 | (body.len() - 1) as u16).to_le_bytes());
                out.extend_from_slice(&body);
            }
        }
        out
    }

    struct Rng(u32);

    impl Rng {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Text-like data with repeats at all distances, so every token split
    /// and long overlapping copies get exercised.
    fn repetitive(n: usize, rng: &mut Rng) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            match rng.next() % 4 {
                0 => v.extend(std::iter::repeat_n(b'A', (rng.next() % 300) as usize)),
                1 if !v.is_empty() => {
                    let back = 1 + rng.next() as usize % v.len().min(5000);
                    let start = v.len() - back;
                    for i in 0..(rng.next() % 200) as usize {
                        v.push(v[start + i]);
                    }
                }
                _ => v.extend_from_slice(format!("line {} ", rng.next() % 97).as_bytes()),
            }
        }
        v.truncate(n);
        v
    }

    const SIZES: [usize; 9] = [0, 1, 15, 16, 17, 4095, 4096, 4097, 65536];

    #[test]
    fn length_split_matches_spec() {
        assert_eq!(length_bits(1), 12);
        assert_eq!(length_bits(16), 12);
        assert_eq!(length_bits(17), 11);
        assert_eq!(length_bits(32), 11);
        assert_eq!(length_bits(33), 10);
        assert_eq!(length_bits(2048), 5);
        assert_eq!(length_bits(2049), 4);
        assert_eq!(length_bits(4095), 4);
    }

    /// The worked example from [MS-XCA] §3.5 (reproduced from memory; its
    /// final literal is the string's NUL terminator).
    #[test]
    fn decodes_spec_example() {
        const PACKED: [u8; 59] = [
            0x38, 0xB0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xA2,
            0x47, 0x01, 0xA0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xC0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xB4, 0x02, 0x4A, 0x44, 0xEF, 0x03, 0x58,
            0x02, 0x8C, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xBE, 0x00, 0x9E, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let text: &[u8] = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D \
            E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";
        assert_eq!(decompress(&PACKED, text.len()).unwrap(), text);
        assert!(decompress(&PACKED, text.len() - 1).is_err());
        let got = decompress(&PACKED, 4096).unwrap();
        assert_eq!(&got[..text.len()], text);
        assert!(got[text.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn round_trips() {
        let mut rng = Rng(0x1234_5678);
        for size in SIZES {
            let inputs = [
                rng.bytes(size),
                repetitive(size, &mut rng),
                vec![0x5A; size],
            ];
            for (kind, data) in inputs.iter().enumerate() {
                for stored in [false, true] {
                    let packed = compress(data, stored);
                    let got = decompress(&packed, size)
                        .unwrap_or_else(|e| panic!("size {size} kind {kind}: {e}"));
                    assert!(got == *data, "size {size} kind {kind} stored {stored}");
                }
            }
        }
    }

    #[test]
    fn zero_header_ends_stream_with_zero_fill() {
        let data = b"hello hello hello hello";
        let mut packed = compress(data, false);
        packed.extend_from_slice(&[0, 0, 0xFF, 0xFF, 0xFF]);
        let got = decompress(&packed, 65536).unwrap();
        assert_eq!(&got[..data.len()], data);
        assert!(got[data.len()..].iter().all(|&b| b == 0));
        assert_eq!(decompress(&[], 100).unwrap(), vec![0; 100]);
    }

    #[test]
    fn short_chunks_are_padded_to_4k() {
        let mut packed = compress(b"abcabcabcabc", false);
        packed.extend(compress(b"xyz", true));
        let got = decompress(&packed, 8192).unwrap();
        assert_eq!(&got[..12], b"abcabcabcabc");
        assert!(got[12..4096].iter().all(|&b| b == 0));
        assert_eq!(&got[4096..4099], b"xyz");
    }

    #[test]
    fn rejects_bad_streams() {
        // Back-reference at position 0.
        assert!(decompress(&[0x02, 0xB0, 0x01, 0x00, 0x00], 4096).is_err());
        // Offset 2 when only one byte has been written.
        assert!(decompress(&[0x03, 0xB0, 0x02, b'a', 0x00, 0x10], 4096).is_err());
        // Header claims more data than present.
        assert!(decompress(&[0x10, 0xB0, 0x00, b'a'], 4096).is_err());
        // Truncated token.
        assert!(decompress(&[0x02, 0xB0, 0x02, b'a', 0x00], 4096).is_err());
        // Stored chunk larger than the output.
        assert!(decompress(&compress(&[7; 100], true), 50).is_err());
        // Compressed chunk expanding past the output.
        assert!(decompress(&compress(&[7; 100], false), 50).is_err());
        // More chunks than the output holds.
        assert!(decompress(&compress(&[7; 8192], false), 4096).is_err());
        // Copy running past the 4 KiB chunk window.
        let mut packed = compress(&[7; 4096], false);
        let n = packed.len();
        packed[n - 2] = 0xFF;
        packed[n - 1] = 0x0F;
        assert!(decompress(&packed, 65536).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        let mut rng = Rng(0xDEAD_BEEF);
        for i in 0..20_000 {
            let n = (rng.next() % 600) as usize;
            let mut data = rng.bytes(n);
            if i % 2 == 0 && n >= 2 {
                // Plausible headers make the chunk decoder do real work.
                let size = (n - 2).min(4096) as u16;
                let h = 0xB000 | size.saturating_sub(1 + rng.next() as u16 % 4);
                data[..2].copy_from_slice(&h.to_le_bytes());
            }
            let out_size = (rng.next() % 9000) as usize;
            if let Ok(out) = decompress(&data, out_size) {
                assert_eq!(out.len(), out_size);
            }
        }
        // Truncations of a valid stream.
        let mut rng = Rng(7);
        let packed = compress(&repetitive(20_000, &mut rng), false);
        for cut in 0..packed.len() {
            if let Ok(out) = decompress(&packed[..cut], 20_000) {
                assert_eq!(out.len(), 20_000);
            }
        }
    }

    #[cfg(windows)]
    mod native {
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

        /// Compresses with Windows' own LZNT1 encoder (format 2).
        pub fn compress(data: &[u8]) -> Vec<u8> {
            let (mut ws, mut frag) = (0u32, 0u32);
            assert!(unsafe { RtlGetCompressionWorkSpaceSize(2, &mut ws, &mut frag) } >= 0);
            let mut workspace = vec![0u8; ws as usize];
            let mut out = vec![0u8; data.len() + data.len() / 8 + 64];
            let mut n = 0u32;
            let status = unsafe {
                RtlCompressBuffer(
                    2,
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

    /// Decodes output of Windows' own LZNT1 encoder.
    #[cfg(windows)]
    #[test]
    fn matches_windows_encoder() {
        let mut rng = Rng(0x0BAD_F00D);
        for size in SIZES.into_iter().filter(|&s| s > 0) {
            for data in [rng.bytes(size), repetitive(size, &mut rng), vec![0; size]] {
                let packed = native::compress(&data);
                let got = decompress(&packed, size).unwrap_or_else(|e| panic!("size {size}: {e}"));
                assert!(got == data, "size {size}: output differs");
            }
        }
    }
}
