// SPDX-FileCopyrightText: 2017 The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-3-Clause

//! Port of puffin's HuffmanTable.

use anyhow::{Context, Result, bail, ensure};

use super::bits::{BitReader, BitWriter};

const MAX_HUFFMAN_BITS: usize = 15;

const PERMUTATIONS: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// The last element is a guard.
pub const LENGTH_BASES: [u16; 30] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0xFFFF,
];

pub const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// The last element is a guard.
pub const DISTANCE_BASES: [u16; 31] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0xFFFF,
];

pub const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Room puffin reserves for a dynamic block's metadata after the block header
/// byte: sizeof(PuffData::block_metadata) - 1.
pub const MAX_DYNAMIC_METADATA: usize = 3 + 286 + 30 + 19;

#[derive(Clone, Copy)]
struct CodeIndexPair {
    code: u16,
    index: u16,
}

/// Canonical codes (bit-reversed, as they appear in the stream) for every
/// symbol with a non-zero length.
fn init_huffman_codes(lens: &[u8]) -> Result<(Vec<CodeIndexPair>, usize)> {
    let mut len_count = [0u16; MAX_HUFFMAN_BITS + 1];
    let mut next_code = [0u16; MAX_HUFFMAN_BITS + 1];
    for &len in lens {
        len_count[len as usize] += 1;
    }

    let max_bits = (1..=MAX_HUFFMAN_BITS)
        .rev()
        .find(|&b| len_count[b] != 0)
        .unwrap_or(0);
    for bits in 1..=max_bits {
        ensure!(
            len_count[bits] as u32 <= 1 << bits,
            "oversubscribed Huffman code lengths"
        );
    }

    let mut code: u16 = 0;
    len_count[0] = 0;
    for bits in 1..=MAX_HUFFMAN_BITS {
        code = (code + len_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    let mut pairs = Vec::with_capacity(lens.len());
    for (index, &len) in lens.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let code = next_code[len as usize].reverse_bits() >> (16 - len as u32);
        next_code[len as usize] += 1;
        pairs.push(CodeIndexPair {
            code,
            index: index as u16,
        });
    }
    Ok((pairs, max_bits))
}

/// Builds the decoding table indexed by the next `max_bits` input bits.
fn build_huffman_codes(lens: &[u8], hcodes: &mut [u16]) -> Result<usize> {
    let (mut pairs, max_bits) = init_huffman_codes(lens)?;
    pairs.sort_by(|a, b| lens[b.index as usize].cmp(&lens[a.index as usize]));

    hcodes[..1 << max_bits].fill(0);
    for cip in &pairs {
        let len = lens[cip.index as usize] as usize;
        hcodes[cip.code as usize] = cip.index | 0x8000;
        for idx in 1..1usize << (max_bits - len) {
            let location = (idx << len) | cip.code as usize;
            if hcodes[location] & 0x8000 == 0 {
                hcodes[location] = cip.index | 0x8000;
            }
        }
    }
    Ok(max_bits)
}

/// Builds the encoding table indexed by symbol.
fn build_huffman_reverse_codes(lens: &[u8], rcodes: &mut [u16]) -> Result<()> {
    let (pairs, _) = init_huffman_codes(lens)?;
    rcodes.fill(0);
    for cip in pairs {
        rcodes[cip.index as usize] = cip.code;
    }
    Ok(())
}

fn check_array_lengths(num_lit_len: usize, num_distance: usize, num_codes: usize) -> Result<()> {
    ensure!(
        num_lit_len <= 286 && num_distance <= 30 && num_codes <= 19,
        "invalid dynamic Huffman table lengths ({num_lit_len}, {num_distance}, {num_codes})"
    );
    Ok(())
}

pub struct HuffmanTable {
    lit_len_lens: Vec<u8>,
    lit_len_hcodes: Vec<u16>,
    lit_len_rcodes: Vec<u16>,
    lit_len_max_bits: usize,
    distance_lens: Vec<u8>,
    distance_hcodes: Vec<u16>,
    distance_rcodes: Vec<u16>,
    distance_max_bits: usize,
    code_lens: [u8; 19],
    code_hcodes: Vec<u16>,
    code_rcodes: [u16; 19],
    code_max_bits: usize,
}

impl HuffmanTable {
    pub fn new_fixed() -> Self {
        let mut lit_len_lens = vec![0u8; 288];
        lit_len_lens[..144].fill(8);
        lit_len_lens[144..256].fill(9);
        lit_len_lens[256..280].fill(7);
        lit_len_lens[280..].fill(8);
        let distance_lens = vec![5u8; 30];

        let mut table = Self::empty(1 << 9, 288, 1 << 5);
        table.lit_len_max_bits =
            build_huffman_codes(&lit_len_lens, &mut table.lit_len_hcodes).unwrap();
        table.distance_max_bits =
            build_huffman_codes(&distance_lens, &mut table.distance_hcodes).unwrap();
        build_huffman_reverse_codes(&lit_len_lens, &mut table.lit_len_rcodes).unwrap();
        build_huffman_reverse_codes(&distance_lens, &mut table.distance_rcodes).unwrap();
        table.lit_len_lens = lit_len_lens;
        table.distance_lens = distance_lens;
        table
    }

    pub fn new_dynamic() -> Self {
        Self::empty(1 << 15, 286, 1 << 15)
    }

    fn empty(lit_len_hcodes: usize, lit_len_rcodes: usize, distance_hcodes: usize) -> Self {
        Self {
            lit_len_lens: Vec::new(),
            lit_len_hcodes: vec![0; lit_len_hcodes],
            lit_len_rcodes: vec![0; lit_len_rcodes],
            lit_len_max_bits: 0,
            distance_lens: Vec::new(),
            distance_hcodes: vec![0; distance_hcodes],
            distance_rcodes: vec![0; 30],
            distance_max_bits: 0,
            code_lens: [0; 19],
            code_hcodes: vec![0; 1 << 7],
            code_rcodes: [0; 19],
            code_max_bits: 0,
        }
    }

    pub fn lit_len_max_bits(&self) -> usize {
        self.lit_len_max_bits
    }

    pub fn distance_max_bits(&self) -> usize {
        self.distance_max_bits
    }

    pub fn end_of_block_bit_length(&self) -> Result<usize> {
        Ok(*self
            .lit_len_lens
            .get(256)
            .context("no end-of-block symbol")? as usize)
    }

    fn decode(hcodes: &[u16], lens: &[u8], bits: u32) -> Result<(u16, usize)> {
        let hc = hcodes[bits as usize];
        ensure!(hc & 0x8000 != 0, "invalid Huffman code in deflate stream");
        let alphabet = hc & 0x7FFF;
        Ok((alphabet, lens[alphabet as usize] as usize))
    }

    pub fn lit_len_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        Self::decode(&self.lit_len_hcodes, &self.lit_len_lens, bits)
    }

    pub fn distance_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        Self::decode(&self.distance_hcodes, &self.distance_lens, bits)
    }

    pub fn lit_len_huffman(&self, alphabet: u16) -> Result<(u32, usize)> {
        let i = alphabet as usize;
        ensure!(
            i < self.lit_len_lens.len(),
            "invalid literal/length symbol {alphabet}"
        );
        Ok((self.lit_len_rcodes[i] as u32, self.lit_len_lens[i] as usize))
    }

    pub fn distance_huffman(&self, alphabet: u16) -> Result<(u32, usize)> {
        let i = alphabet as usize;
        ensure!(
            i < self.distance_lens.len(),
            "invalid distance symbol {alphabet}"
        );
        Ok((
            self.distance_rcodes[i] as u32,
            self.distance_lens[i] as usize,
        ))
    }

    /// Reads a dynamic block header from `br`, appending its puffed form to `metadata`.
    pub fn build_dynamic_from_deflate(
        &mut self,
        br: &mut BitReader,
        metadata: &mut Vec<u8>,
    ) -> Result<()> {
        ensure!(br.cache_bits(14), "deflate stream is truncated");
        let hlit = br.read_bits(5) as u8;
        br.drop_bits(5)?;
        let hdist = br.read_bits(5) as u8;
        br.drop_bits(5)?;
        let hclen = br.read_bits(4) as u8;
        br.drop_bits(4)?;
        metadata.extend_from_slice(&[hlit, hdist, hclen]);
        let num_lit_len = hlit as usize + 257;
        let num_distance = hdist as usize + 1;
        let num_codes = hclen as usize + 4;
        check_array_lengths(num_lit_len, num_distance, num_codes)?;

        // Two 3-bit code lengths per byte, high nibble first.
        self.code_lens = [0; 19];
        for idx in 0..num_codes {
            ensure!(br.cache_bits(3), "deflate stream is truncated");
            let len = br.read_bits(3) as u8;
            br.drop_bits(3)?;
            self.code_lens[PERMUTATIONS[idx]] = len;
            if idx % 2 == 0 {
                metadata.push(len << 4);
            } else {
                *metadata.last_mut().unwrap() |= len;
            }
        }
        self.code_max_bits = build_huffman_codes(&self.code_lens, &mut self.code_hcodes)?;

        let lens = self.read_code_lengths(br, metadata, num_lit_len + num_distance)?;
        self.lit_len_lens = lens[..num_lit_len].to_vec();
        self.distance_lens = lens[num_lit_len..].to_vec();
        self.lit_len_max_bits = build_huffman_codes(&self.lit_len_lens, &mut self.lit_len_hcodes)?;
        self.distance_max_bits =
            build_huffman_codes(&self.distance_lens, &mut self.distance_hcodes)?;
        ensure!(
            metadata.len() <= 1 + MAX_DYNAMIC_METADATA,
            "dynamic block header is too large"
        );
        Ok(())
    }

    fn read_code_lengths(
        &self,
        br: &mut BitReader,
        metadata: &mut Vec<u8>,
        num_codes: usize,
    ) -> Result<Vec<u8>> {
        let mut lens: Vec<u8> = Vec::with_capacity(num_codes);
        while lens.len() < num_codes {
            ensure!(
                br.cache_bits(self.code_max_bits),
                "deflate stream is truncated"
            );
            let bits = br.read_bits(self.code_max_bits);
            let (code, nbits) = Self::decode(&self.code_hcodes, &self.code_lens, bits)?;
            br.drop_bits(nbits)?;
            let (extra_bits, puff_base, copy_base, copy_val) = match code {
                0..=15 => {
                    metadata.push(code as u8);
                    lens.push(code as u8);
                    continue;
                }
                16 => (
                    2,
                    16,
                    3,
                    *lens
                        .last()
                        .context("repeat code without a previous length")?,
                ),
                17 => (3, 20, 3, 0),
                18 => (7, 28, 11, 0),
                _ => bail!("invalid code length symbol {code}"),
            };
            ensure!(br.cache_bits(extra_bits), "deflate stream is truncated");
            let extra = br.read_bits(extra_bits) as u8;
            br.drop_bits(extra_bits)?;
            metadata.push(puff_base + extra);
            lens.extend(std::iter::repeat_n(copy_val, (copy_base + extra) as usize));
        }
        ensure!(lens.len() == num_codes, "code lengths overflow the table");
        Ok(lens)
    }

    /// Writes a dynamic block header described by puffed `metadata` into `bw`.
    pub fn build_dynamic_from_puff(&mut self, metadata: &[u8], bw: &mut BitWriter) -> Result<()> {
        ensure!(metadata.len() >= 3, "dynamic block metadata is truncated");
        let num_lit_len = metadata[0] as usize + 257;
        let num_distance = metadata[1] as usize + 1;
        let num_codes = metadata[2] as usize + 4;
        bw.write_bits(5, metadata[0] as u32)?;
        bw.write_bits(5, metadata[1] as u32)?;
        bw.write_bits(4, metadata[2] as u32)?;
        check_array_lengths(num_lit_len, num_distance, num_codes)?;

        let mut index = 3;
        ensure!(
            metadata.len() - index >= num_codes.div_ceil(2),
            "dynamic block metadata is truncated"
        );
        self.code_lens = [0; 19];
        for idx in 0..num_codes {
            let len = if idx % 2 == 0 {
                metadata[index] >> 4
            } else {
                index += 1;
                metadata[index - 1] & 0x0F
            };
            self.code_lens[PERMUTATIONS[idx]] = len;
            bw.write_bits(3, len as u32)?;
        }
        if num_codes % 2 == 1 {
            index += 1;
        }
        build_huffman_reverse_codes(&self.code_lens, &mut self.code_rcodes)?;

        let (lens, consumed) =
            self.write_code_lengths(&metadata[index..], bw, num_lit_len + num_distance)?;
        ensure!(
            index + consumed == metadata.len(),
            "trailing bytes in dynamic block metadata"
        );
        self.lit_len_lens = lens[..num_lit_len].to_vec();
        self.distance_lens = lens[num_lit_len..].to_vec();
        build_huffman_reverse_codes(&self.lit_len_lens, &mut self.lit_len_rcodes)?;
        build_huffman_reverse_codes(&self.distance_lens, &mut self.distance_rcodes)?;
        Ok(())
    }

    fn write_code_lengths(
        &self,
        metadata: &[u8],
        bw: &mut BitWriter,
        num_codes: usize,
    ) -> Result<(Vec<u8>, usize)> {
        let mut lens: Vec<u8> = Vec::with_capacity(num_codes);
        let mut index = 0;
        while lens.len() < num_codes {
            let pcode = *metadata
                .get(index)
                .context("dynamic block metadata is truncated")?;
            index += 1;
            ensure!(pcode <= 155, "invalid puffed code length {pcode}");
            let code = match pcode {
                0..=15 => pcode,
                16..=19 => 16,
                20..=27 => 17,
                _ => 18,
            };
            let (hcode, nbits) = (
                self.code_rcodes[code as usize] as u32,
                self.code_lens[code as usize] as usize,
            );
            bw.write_bits(nbits, hcode)?;
            let (extra_bits, extra, copy_num, copy_val) = match code {
                0..=15 => {
                    lens.push(code);
                    continue;
                }
                16 => (
                    2,
                    pcode - 16,
                    3 + pcode - 16,
                    *lens
                        .last()
                        .context("repeat code without a previous length")?,
                ),
                17 => (3, pcode - 20, 3 + pcode - 20, 0),
                _ => (7, pcode - 28, 11 + pcode - 28, 0),
            };
            bw.write_bits(extra_bits, extra as u32)?;
            lens.extend(std::iter::repeat_n(copy_val, copy_num as usize));
        }
        ensure!(lens.len() == num_codes, "code lengths overflow the table");
        Ok((lens, index))
    }
}
