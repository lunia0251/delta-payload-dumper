// SPDX-FileCopyrightText: 2017 The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-3-Clause

//! Ports of puffin's Puffer/Huffer and the puff stream format they exchange.
//!
//! Puff stream items:
//! - block metadata: u16be (len - 1), then `len` bytes (header byte first)
//! - literals: 0x00 | (n - 1) for n <= 127, else 0x7F + u16be (n - 128); then the bytes
//! - length/distance: 0x80 | (len - 3) for len < 130, else 0xFF + (len - 130); then u16be (dist - 1)
//! - end of block: 0xFF 0x81 (a length of 259)

use anyhow::{Context, Result, bail, ensure};

use super::bits::{BitReader, BitWriter};
use super::huffman::{
    DISTANCE_BASES, DISTANCE_EXTRA_BITS, HuffmanTable, LENGTH_BASES, LENGTH_EXTRA_BITS,
};

const LEN_DIST_HEADER: u8 = 0x80;
/// The longest literal run a single puff item can describe.
const LITERALS_MAX_LENGTH: usize = (1 << 16) + 127;

const BLOCK_STORED: u8 = 0;
const BLOCK_FIXED: u8 = 1;
const BLOCK_DYNAMIC: u8 = 2;

pub struct PuffWriter {
    out: Vec<u8>,
    capacity: usize,
    literals: Vec<u8>,
}

impl PuffWriter {
    pub fn new(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            capacity,
            literals: Vec::new(),
        }
    }

    fn check_capacity(&self) -> Result<()> {
        ensure!(
            self.out.len() + self.literals.len() <= self.capacity,
            "puff overflows its extent"
        );
        Ok(())
    }

    fn literal(&mut self, byte: u8) -> Result<()> {
        self.literals.push(byte);
        if self.literals.len() == LITERALS_MAX_LENGTH {
            self.flush_literals();
        }
        self.check_capacity()
    }

    fn literals(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.literals.extend_from_slice(bytes);
        if self.literals.len() == LITERALS_MAX_LENGTH {
            self.flush_literals();
        }
        self.check_capacity()
    }

    fn len_dist(&mut self, length: usize, distance: usize) -> Result<()> {
        self.flush_literals();
        ensure!(
            (3..=258).contains(&length),
            "invalid deflate length {length}"
        );
        ensure!(
            (1..=32768).contains(&distance),
            "invalid deflate distance {distance}"
        );
        if length < 130 {
            self.out.push(LEN_DIST_HEADER | (length - 3) as u8);
        } else {
            self.out
                .extend_from_slice(&[LEN_DIST_HEADER | 127, (length - 3 - 127) as u8]);
        }
        self.out
            .extend_from_slice(&((distance - 1) as u16).to_be_bytes());
        self.check_capacity()
    }

    fn block_metadata(&mut self, metadata: &[u8]) -> Result<()> {
        self.flush_literals();
        self.out
            .extend_from_slice(&((metadata.len() - 1) as u16).to_be_bytes());
        self.out.extend_from_slice(metadata);
        self.check_capacity()
    }

    fn end_of_block(&mut self) -> Result<()> {
        self.flush_literals();
        self.out
            .extend_from_slice(&[LEN_DIST_HEADER | 127, (259 - 3 - 127) as u8]);
        self.check_capacity()
    }

    fn flush_literals(&mut self) {
        let n = self.literals.len();
        if n == 0 {
            return;
        }
        if n <= 127 {
            self.out.push((n - 1) as u8);
        } else {
            self.out.push(127);
            self.out
                .extend_from_slice(&((n - 127 - 1) as u16).to_be_bytes());
        }
        self.out.append(&mut self.literals);
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.flush_literals();
        self.out
    }
}

pub enum PuffItem<'a> {
    BlockMetadata(&'a [u8]),
    Literals(&'a [u8]),
    LenDist { length: usize, distance: usize },
    EndOfBlock,
}

pub struct PuffReader<'a> {
    buf: &'a [u8],
    index: usize,
    reading_metadata: bool,
}

impl<'a> PuffReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            index: 0,
            reading_metadata: true,
        }
    }

    pub fn bytes_left(&self) -> usize {
        self.buf.len() - self.index
    }

    fn read_u16(&self, at: usize) -> usize {
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]]) as usize
    }

    pub fn next_item(&mut self) -> Result<PuffItem<'a>> {
        let size = self.buf.len();
        if self.reading_metadata {
            ensure!(self.index + 2 < size, "puff stream is truncated");
            let length = self.read_u16(self.index) + 1;
            self.index += 2;
            ensure!(self.index + length <= size, "puff stream is truncated");
            ensure!(
                length <= 1 + super::huffman::MAX_DYNAMIC_METADATA,
                "block metadata is too large"
            );
            let metadata = &self.buf[self.index..self.index + length];
            self.index += length;
            self.reading_metadata = false;
            return Ok(PuffItem::BlockMetadata(metadata));
        }

        ensure!(self.index < size, "puff stream is truncated");
        let header = self.buf[self.index];
        if header & 0x80 != 0 {
            let mut length = if header & 0x7F < 127 {
                (header & 0x7F) as usize
            } else {
                self.index += 1;
                ensure!(self.index < size, "puff stream is truncated");
                self.buf[self.index] as usize + 127
            };
            length += 3;
            ensure!(length <= 259, "invalid puff length {length}");
            self.index += 1;

            if length == 259 {
                self.reading_metadata = true;
                return Ok(PuffItem::EndOfBlock);
            }

            ensure!(self.index + 1 < size, "puff stream is truncated");
            let distance = self.read_u16(self.index);
            ensure!(distance < 1 << 15, "invalid puff distance {distance}");
            self.index += 2;
            Ok(PuffItem::LenDist {
                length,
                distance: distance + 1,
            })
        } else {
            let length = if header & 0x7F < 127 {
                self.index += 1;
                (header & 0x7F) as usize
            } else {
                self.index += 1;
                ensure!(self.index + 1 < size, "puff stream is truncated");
                let length = self.read_u16(self.index) + 127;
                self.index += 2;
                length
            } + 1;
            ensure!(self.index + length <= size, "puff stream is truncated");
            let literals = &self.buf[self.index..self.index + length];
            self.index += length;
            Ok(PuffItem::Literals(literals))
        }
    }
}

pub struct Puffer {
    fixed: HuffmanTable,
    dynamic: HuffmanTable,
}

impl Puffer {
    pub fn new() -> Self {
        Self {
            fixed: HuffmanTable::new_fixed(),
            dynamic: HuffmanTable::new_dynamic(),
        }
    }

    /// Converts every deflate block in `br` into puff items, until fewer than
    /// 8 bits are left (the smallest possible block).
    pub fn puff_deflate(&mut self, br: &mut BitReader, pw: &mut PuffWriter) -> Result<()> {
        while br.cache_bits(8) {
            let final_bit = br.read_bits(1) as u8;
            br.drop_bits(1)?;
            let block_type = br.read_bits(2) as u8;
            br.drop_bits(2)?;
            let mut header = (final_bit << 7) | (block_type << 5);

            let table = match block_type {
                BLOCK_STORED => {
                    let skipped_bits = br.read_boundary_bits();
                    br.skip_boundary_bits();
                    ensure!(br.cache_bits(32), "deflate stream is truncated");
                    let len = br.read_bits(16);
                    br.drop_bits(16)?;
                    let nlen = br.read_bits(16);
                    br.drop_bits(16)?;
                    ensure!(
                        len ^ nlen == 0xFFFF,
                        "invalid stored block length {len}/{nlen}"
                    );
                    // puffin ORs the padding bits into the header unshifted.
                    header |= skipped_bits;
                    pw.block_metadata(&[header])?;
                    pw.literals(br.take_bytes(len as usize)?)?;
                    pw.end_of_block()?;
                    continue;
                }
                BLOCK_FIXED => {
                    pw.block_metadata(&[header])?;
                    &self.fixed
                }
                BLOCK_DYNAMIC => {
                    let mut metadata = vec![header];
                    self.dynamic.build_dynamic_from_deflate(br, &mut metadata)?;
                    pw.block_metadata(&metadata)?;
                    &self.dynamic
                }
                _ => bail!("invalid deflate block type {block_type}"),
            };

            loop {
                let mut max_bits = table.lit_len_max_bits();
                if !br.cache_bits(max_bits) {
                    // The end-of-block code can be shorter than the longest code.
                    max_bits = table.end_of_block_bit_length()?;
                }
                ensure!(br.cache_bits(max_bits), "deflate stream is truncated");
                let (symbol, nbits) = table.lit_len_alphabet(br.read_bits(max_bits))?;
                br.drop_bits(nbits)?;
                match symbol {
                    0..=255 => pw.literal(symbol as u8)?,
                    256 => {
                        pw.end_of_block()?;
                        break;
                    }
                    257..=285 => {
                        let code = (symbol - 257) as usize;
                        let extra_bits = LENGTH_EXTRA_BITS[code] as usize;
                        let mut extra = 0;
                        if extra_bits > 0 {
                            ensure!(br.cache_bits(extra_bits), "deflate stream is truncated");
                            extra = br.read_bits(extra_bits) as usize;
                            br.drop_bits(extra_bits)?;
                        }
                        let length = LENGTH_BASES[code] as usize + extra;

                        let mut bits_to_cache = table.distance_max_bits();
                        if !br.cache_bits(bits_to_cache) {
                            // crbug.com/915559: the distance code ends right at the stream end.
                            bits_to_cache = br.bits_remaining();
                            ensure!(br.cache_bits(bits_to_cache), "deflate stream is truncated");
                        }
                        let (dist_symbol, nbits) =
                            table.distance_alphabet(br.read_bits(bits_to_cache))?;
                        br.drop_bits(nbits)?;
                        let dist_code = dist_symbol as usize;
                        let extra_bits = *DISTANCE_EXTRA_BITS
                            .get(dist_code)
                            .context("invalid distance symbol")?
                            as usize;
                        let mut extra = 0;
                        if extra_bits > 0 {
                            ensure!(br.cache_bits(extra_bits), "deflate stream is truncated");
                            extra = br.read_bits(extra_bits) as usize;
                            br.drop_bits(extra_bits)?;
                        }
                        pw.len_dist(length, DISTANCE_BASES[dist_code] as usize + extra)?;
                    }
                    _ => bail!("invalid literal/length symbol {symbol}"),
                }
            }
        }
        Ok(())
    }
}

pub struct Huffer {
    fixed: HuffmanTable,
    dynamic: HuffmanTable,
}

impl Huffer {
    pub fn new() -> Self {
        Self {
            fixed: HuffmanTable::new_fixed(),
            dynamic: HuffmanTable::new_dynamic(),
        }
    }

    pub fn huff_deflate(&mut self, pr: &mut PuffReader, bw: &mut BitWriter) -> Result<()> {
        while pr.bytes_left() != 0 {
            let PuffItem::BlockMetadata(metadata) = pr.next_item()? else {
                bail!("expected block metadata in puff stream");
            };
            let header = metadata[0];
            let block_type = (header & 0x60) >> 5;
            bw.write_bits(1, ((header & 0x80) >> 7) as u32)?;
            bw.write_bits(2, block_type as u32)?;

            let table = match block_type {
                BLOCK_STORED => {
                    bw.write_boundary_bits(header & 0x1F)?;
                    match pr.next_item()? {
                        PuffItem::Literals(bytes) => {
                            let len = bytes.len() as u32;
                            bw.write_bits(16, len)?;
                            bw.write_bits(16, !len)?;
                            bw.write_bytes(bytes)?;
                            ensure!(
                                matches!(pr.next_item()?, PuffItem::EndOfBlock),
                                "stored block did not end properly"
                            );
                        }
                        PuffItem::EndOfBlock => {
                            bw.write_bits(16, 0)?;
                            bw.write_bits(16, !0)?;
                        }
                        _ => bail!("stored block did not end properly"),
                    }
                    continue;
                }
                BLOCK_FIXED => &self.fixed,
                BLOCK_DYNAMIC => {
                    self.dynamic.build_dynamic_from_puff(&metadata[1..], bw)?;
                    &self.dynamic
                }
                _ => bail!("invalid deflate block type {block_type}"),
            };

            loop {
                match pr.next_item()? {
                    PuffItem::Literals(bytes) => {
                        for &byte in bytes {
                            let (code, nbits) = table.lit_len_huffman(byte as u16)?;
                            bw.write_bits(nbits, code)?;
                        }
                    }
                    PuffItem::LenDist { length, distance } => {
                        ensure!((3..=258).contains(&length), "invalid puff length {length}");
                        let index = base_index(&LENGTH_BASES, length);
                        let (code, nbits) = table.lit_len_huffman(index as u16 + 257)?;
                        bw.write_bits(nbits, code)?;
                        let extra_bits = LENGTH_EXTRA_BITS[index] as usize;
                        if extra_bits > 0 {
                            bw.write_bits(
                                extra_bits,
                                (length - LENGTH_BASES[index] as usize) as u32,
                            )?;
                        }

                        let index = base_index(&DISTANCE_BASES, distance);
                        let (code, nbits) = table.distance_huffman(index as u16)?;
                        bw.write_bits(nbits, code)?;
                        let extra_bits = DISTANCE_EXTRA_BITS[index] as usize;
                        if extra_bits > 0 {
                            bw.write_bits(
                                extra_bits,
                                (distance - DISTANCE_BASES[index] as usize) as u32,
                            )?;
                        }
                    }
                    PuffItem::EndOfBlock => {
                        let (code, nbits) = table.lit_len_huffman(256)?;
                        bw.write_bits(nbits, code)?;
                        break;
                    }
                    PuffItem::BlockMetadata(_) => bail!("unexpected block metadata in puff stream"),
                }
            }
        }
        bw.flush()
    }
}

/// Index of the last base that is <= `value`, matching puffin's linear search
/// (which picks code 285 rather than 284 + 31 for a length of 258).
fn base_index(bases: &[u16], value: usize) -> usize {
    let mut index = 0;
    while value > bases[index] as usize {
        index += 1;
    }
    if value < bases[index] as usize {
        index -= 1;
    }
    index
}
