// SPDX-FileCopyrightText: 2017 The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-3-Clause

//! Port of puffin's PuffinStream, reduced to whole-buffer puffing and huffing.
//! The bit bookkeeping around deflates that start or end mid-byte follows
//! PuffinStream::Read and PuffinStream::Write exactly.

use anyhow::{Context, Result, ensure};

use super::bits::{BitReader, BitWriter};
use super::puff::{Huffer, PuffReader, PuffWriter, Puffer};

#[derive(Clone, Copy)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

impl Extent {
    fn end(&self) -> u64 {
        self.offset + self.length
    }
}

/// Deflate locations (in bits) of a stream and the matching puff locations
/// (in bytes) of its puffed form.
pub struct StreamLayout {
    deflates: Vec<Extent>,
    puffs: Vec<Extent>,
    puff_size: u64,
}

struct Cursor {
    cur: usize,
    puff_pos: u64,
    deflate_bit_pos: u64,
}

impl StreamLayout {
    pub fn new(deflates: Vec<Extent>, puffs: Vec<Extent>, puff_size: u64) -> Result<Self> {
        ensure!(
            deflates.len() == puffs.len(),
            "puffin deflate/puff extent count mismatch"
        );
        if let Some(last) = puffs.last() {
            ensure!(puff_size >= last.end(), "puff extents exceed the puff size");
        }
        let overlaps = |e: &[Extent]| e.windows(2).any(|w| w[0].end() > w[1].offset);
        ensure!(
            !overlaps(&deflates) && !overlaps(&puffs),
            "puffin extents overlap"
        );

        let deflate_stream_size = match (deflates.last(), puffs.last()) {
            (Some(d), Some(p)) => d.end() / 8 + puff_size - p.end(),
            _ => puff_size,
        };
        let mut layout = Self {
            deflates,
            puffs,
            puff_size,
        };
        // Sentinels covering the raw bytes after the last deflate.
        layout.deflates.push(Extent {
            offset: deflate_stream_size * 8,
            length: 0,
        });
        layout.puffs.push(Extent {
            offset: puff_size,
            length: 0,
        });
        Ok(layout)
    }

    pub fn deflate_stream_size(&self) -> u64 {
        self.deflates.last().unwrap().offset / 8
    }

    /// PuffinStream::Seek(0).
    fn seek_start(&self) -> Result<Cursor> {
        let cur = self.puffs[..self.puffs.len() - 1]
            .iter()
            .position(|p| p.end() > 0)
            .unwrap_or(self.puffs.len() - 1);
        let (puff, deflate) = (self.puffs[cur], self.deflates[cur]);
        if puff.offset > 0 {
            let mut deflate_bit_pos = deflate
                .offset
                .div_ceil(8)
                .checked_sub(puff.offset)
                .context("puff extents don't match deflate extents")?
                * 8;
            if cur > 0 {
                deflate_bit_pos = deflate_bit_pos.max(self.deflates[cur - 1].end());
            }
            Ok(Cursor {
                cur,
                puff_pos: 0,
                deflate_bit_pos,
            })
        } else {
            Ok(Cursor {
                cur,
                puff_pos: puff.offset,
                deflate_bit_pos: deflate.offset,
            })
        }
    }

    /// Converts the deflate stream `src` into its puffed form.
    pub fn puff(&self, src: &[u8]) -> Result<Vec<u8>> {
        let length = self.puff_size as usize;
        let mut out = vec![0u8; length];
        let mut c = self.seek_start()?;
        let mut puffer = Puffer::new();
        let mut bytes_read = 0;

        while bytes_read < length {
            let (puff, deflate) = (self.puffs[c.cur], self.deflates[c.cur]);
            if c.puff_pos < puff.offset {
                // Raw bytes between deflates. Bits belonging to the neighbouring
                // deflates are masked off the first and last byte.
                let start_byte = c.deflate_bit_pos / 8;
                let end_byte = deflate.offset.div_ceil(8);
                let n = ((length - bytes_read) as u64).min(end_byte - start_byte) as usize;
                ensure!(n >= 1, "puffin extents are inconsistent");
                let start = start_byte as usize;
                let raw = src
                    .get(start..start + n)
                    .context("deflate extents exceed the source")?;
                out[bytes_read..bytes_read + n].copy_from_slice(raw);

                if (start_byte + n as u64) * 8 > deflate.offset {
                    out[bytes_read + n - 1] &= ((1u16 << (deflate.offset & 7)) - 1) as u8;
                }
                if start_byte * 8 < c.deflate_bit_pos {
                    out[bytes_read] >>= c.deflate_bit_pos & 7;
                }

                c.deflate_bit_pos -= c.deflate_bit_pos & 7;
                c.deflate_bit_pos = (c.deflate_bit_pos + n as u64 * 8).min(deflate.offset);
                bytes_read += n;
                c.puff_pos += n as u64;
                ensure!(c.puff_pos <= puff.offset, "puffin extents are inconsistent");
            } else {
                let start_byte = (deflate.offset / 8) as usize;
                let end_byte = deflate.end().div_ceil(8) as usize;
                let bytes = src
                    .get(start_byte..end_byte)
                    .context("deflate extents exceed the source")?;
                let mut br = BitReader::new(bytes);
                let skip = (deflate.offset & 7) as usize;
                ensure!(br.cache_bits(skip), "deflate extent is empty");
                br.drop_bits(skip)?;

                let mut pw = PuffWriter::new(puff.length as usize);
                puffer.puff_deflate(&mut br, &mut pw)?;
                ensure!(
                    br.offset() == bytes.len(),
                    "deflate extent has trailing data"
                );
                let puffed = pw.finish();
                ensure!(
                    puffed.len() as u64 == puff.length,
                    "puffed deflate is {} bytes, expected {}",
                    puffed.len(),
                    puff.length
                );

                let n = (length - bytes_read).min(puffed.len());
                out[bytes_read..bytes_read + n].copy_from_slice(&puffed[..n]);
                bytes_read += n;
                if n == puffed.len() {
                    c.puff_pos += n as u64;
                    c.deflate_bit_pos = deflate.end();
                    c.cur += 1;
                    if c.cur == self.puffs.len() {
                        break;
                    }
                }
            }
        }
        ensure!(bytes_read == length, "puff stream is shorter than expected");
        Ok(out)
    }

    /// PuffinStream::SetExtraByte: whether the byte holding the end of the
    /// current deflate also holds raw bits that are stored in the puff stream.
    fn extra_byte(&self, cur: usize) -> usize {
        if cur + 1 == self.deflates.len() {
            return 0;
        }
        let end_bit = self.deflates[cur].end();
        usize::from(end_bit & 7 != 0 && end_bit.div_ceil(8) * 8 <= self.deflates[cur + 1].offset)
    }

    /// Converts the puffed stream `puffed` back into deflate form.
    pub fn huff(&self, puffed: &[u8]) -> Result<Vec<u8>> {
        let length = puffed.len();
        let mut out = Vec::with_capacity(self.deflate_stream_size() as usize);
        let mut c = self.seek_start()?;
        let mut huffer = Huffer::new();
        let mut extra_byte = self.extra_byte(c.cur);
        let max_puff_length = self.puffs.iter().map(|p| p.length).max().unwrap_or(0) as usize;
        let mut puff_buffer: Vec<u8> = Vec::with_capacity(max_puff_length + 1);
        let mut last_byte: u8 = 0;
        let mut bytes_written = 0;

        while bytes_written < length {
            let (puff, deflate) = (self.puffs[c.cur], self.deflates[c.cur]);
            if c.deflate_bit_pos < deflate.offset & !7 {
                // Raw bytes up to (but excluding) the byte the next deflate starts in.
                ensure!(
                    c.deflate_bit_pos & 7 == 0,
                    "puffin extents are inconsistent"
                );
                let n = ((deflate.offset / 8 - c.deflate_bit_pos / 8) as usize)
                    .min(length - bytes_written);
                out.extend_from_slice(&puffed[bytes_written..bytes_written + n]);
                bytes_written += n;
                c.puff_pos += n as u64;
                c.deflate_bit_pos += n as u64 * 8;
            } else {
                if c.deflate_bit_pos < deflate.offset {
                    // The raw low bits of the byte this deflate starts in.
                    last_byte |= puffed[bytes_written] << (c.deflate_bit_pos & 7);
                    bytes_written += 1;
                    puff_buffer.clear();
                    c.deflate_bit_pos = deflate.offset;
                    c.puff_pos += 1;
                    ensure!(c.puff_pos == puff.offset, "puffin extents are inconsistent");
                }

                let wanted = puff.length as usize + extra_byte;
                let n = (length - bytes_written).min(wanted - puff_buffer.len());
                ensure!(
                    puff_buffer.len() + n <= max_puff_length + 1,
                    "puff exceeds its extent"
                );
                puff_buffer.extend_from_slice(&puffed[bytes_written..bytes_written + n]);
                bytes_written += n;

                if puff_buffer.len() == wanted {
                    let start_byte = deflate.offset / 8;
                    let end_byte = deflate.end().div_ceil(8);
                    let mut to_write = (end_byte - start_byte) as usize;

                    let mut bw = BitWriter::new(to_write);
                    bw.write_bits((deflate.offset & 7) as usize, last_byte as u32)?;
                    last_byte = 0;
                    let mut pr = PuffReader::new(&puff_buffer[..puff.length as usize]);
                    huffer.huff_deflate(&mut pr, &mut bw)?;
                    ensure!(bw.size() == to_write, "huffed deflate has the wrong size");
                    ensure!(pr.bytes_left() == 0, "puff has trailing data");
                    let mut deflated = bw.into_bytes();

                    c.deflate_bit_pos = deflate.end();
                    if extra_byte == 1 {
                        deflated[to_write - 1] |=
                            puff_buffer[puff.length as usize] << (c.deflate_bit_pos & 7);
                        c.deflate_bit_pos = (c.deflate_bit_pos + 7) & !7;
                    } else if c.deflate_bit_pos & 7 != 0 {
                        // The next deflate starts in this same byte; finish it there.
                        last_byte = deflated[to_write - 1];
                        to_write -= 1;
                    }
                    out.extend_from_slice(&deflated[..to_write]);

                    c.puff_pos += puff_buffer.len() as u64;
                    puff_buffer.clear();
                    c.cur += 1;
                    if c.cur == self.puffs.len() {
                        break;
                    }
                    extra_byte = self.extra_byte(c.cur);
                }
            }
        }
        ensure!(bytes_written == length, "puff stream has trailing data");
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    fn deflate(data: &[u8], level: u32) -> Vec<u8> {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(level));
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Puffs a single deflate with an oversized writer to learn its puff length.
    fn puff_length(deflate: &[u8]) -> u64 {
        let mut br = BitReader::new(deflate);
        let mut pw = PuffWriter::new(1 << 24);
        Puffer::new().puff_deflate(&mut br, &mut pw).unwrap();
        pw.finish().len() as u64
    }

    #[test]
    fn puff_huff_round_trip() {
        let mut text = Vec::new();
        for i in 0..20000u32 {
            write!(text, "line {i} {}\n", i.wrapping_mul(2654435761) % 977).unwrap();
        }
        let noise: Vec<u8> = (0..100_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();

        // Raw gaps around stored (level 0), fixed/dynamic (levels 1-9) deflates.
        let mut stream = b"header".to_vec();
        let (mut deflates, mut puffs) = (Vec::new(), Vec::new());
        let mut puff_pos = stream.len() as u64;
        for (data, level) in [
            (&text, 0),
            (&text, 1),
            (&noise, 6),
            (&text[..300].to_vec(), 9),
            (&text, 9),
        ] {
            let d = deflate(data, level);
            let plen = puff_length(&d);
            deflates.push(Extent {
                offset: stream.len() as u64 * 8,
                length: d.len() as u64 * 8,
            });
            puffs.push(Extent {
                offset: puff_pos,
                length: plen,
            });
            stream.extend_from_slice(&d);
            stream.extend_from_slice(b"gap");
            puff_pos += plen + 3;
        }
        let layout = StreamLayout::new(deflates, puffs, puff_pos).unwrap();
        let puffed = layout.puff(&stream).unwrap();
        assert_eq!(puffed.len() as u64, puff_pos);
        assert_eq!(layout.huff(&puffed).unwrap(), stream);
    }
}
