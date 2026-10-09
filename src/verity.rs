// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: Apache-2.0

//! Regenerates the dm-verity hash tree and FEC that update_engine computes on
//! device (VerityWriterAndroid) instead of shipping them in the payload.

use anyhow::{Result, bail, ensure};
use rayon::prelude::*;
use sha2::Digest;

use crate::manifest::{Extent, PartitionUpdate};

fn byte_range(e: &Extent, block_size: u64) -> (usize, usize) {
    let start = (e.start_block.unwrap_or(0) * block_size) as usize;
    (
        start,
        start + (e.num_blocks.unwrap_or(0) * block_size) as usize,
    )
}

fn present(e: Option<&Extent>) -> Option<&Extent> {
    e.filter(|e| e.num_blocks.unwrap_or(0) > 0)
}

type BlockHasher<'a> = Box<dyn Fn(&[u8], &mut [u8]) + Sync + 'a>;

/// Salted digest of one block, zero-padded to a power-of-two size.
fn hasher<'a>(algorithm: &str, salt: &'a [u8]) -> Result<(usize, BlockHasher<'a>)> {
    fn salted<D: Digest>(salt: &[u8], block: &[u8], out: &mut [u8]) {
        let digest = D::new().chain_update(salt).chain_update(block).finalize();
        out[..digest.len()].copy_from_slice(&digest);
    }
    let (raw_size, f): (usize, BlockHasher<'a>) = match algorithm.to_ascii_lowercase().as_str() {
        "sha1" => (20, Box::new(move |b, o| salted::<sha1::Sha1>(salt, b, o))),
        "sha256" => (32, Box::new(move |b, o| salted::<sha2::Sha256>(salt, b, o))),
        "sha384" => (48, Box::new(move |b, o| salted::<sha2::Sha384>(salt, b, o))),
        "sha512" => (64, Box::new(move |b, o| salted::<sha2::Sha512>(salt, b, o))),
        _ => bail!("unsupported verity hash algorithm {algorithm}"),
    };
    Ok((raw_size.next_power_of_two(), f))
}

/// HashTreeBuilder: levels are built bottom-up and written top-down, each
/// padded with zeros to a whole number of blocks.
fn build_hash_tree(
    data: &[u8],
    block_size: usize,
    algorithm: &str,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let (hash_size, hash) = hasher(algorithm, salt)?;
    ensure!(
        hash_size * 2 < block_size,
        "verity hash is too large for the block size"
    );
    ensure!(
        data.len().is_multiple_of(block_size),
        "verity data is not block aligned"
    );

    let hash_level = |input: &[u8]| {
        let mut level = vec![0u8; input.len() / block_size * hash_size];
        level
            .par_chunks_mut(hash_size)
            .zip(input.par_chunks(block_size))
            .for_each(|(out, block)| hash(block, out));
        level.resize(level.len().next_multiple_of(block_size), 0);
        level
    };

    let mut levels = vec![hash_level(data)];
    while levels.last().unwrap().len() > block_size {
        let next = hash_level(levels.last().unwrap());
        levels.push(next);
    }
    Ok(levels.into_iter().rev().flatten().collect())
}

const FEC_RSM: usize = 255;
const FEC_BLOCKSIZE: u64 = 4096;
const GF_POLY: u16 = 0x11D;

/// Phil Karn's encode_rs_char as used by libfec: GF(2^8), poly 0x11d, fcr 0, prim 1.
struct ReedSolomon {
    alpha_to: [u8; 256],
    index_of: [u8; 256],
    /// Generator polynomial in index form.
    genpoly: Vec<u8>,
    nroots: usize,
}

impl ReedSolomon {
    const A0: u8 = 255;

    fn new(nroots: usize) -> Self {
        let mut alpha_to = [0u8; 256];
        let mut index_of = [0u8; 256];
        index_of[0] = Self::A0;
        alpha_to[Self::A0 as usize] = 0;
        let mut sr: u16 = 1;
        for i in 0..FEC_RSM {
            index_of[sr as usize] = i as u8;
            alpha_to[i] = sr as u8;
            sr <<= 1;
            if sr & 0x100 != 0 {
                sr ^= GF_POLY;
            }
            sr &= 0xFF;
        }

        let modnn = |x: usize| (x % FEC_RSM) as u8;
        let mut genpoly = vec![0u8; nroots + 1];
        genpoly[0] = 1;
        for i in 0..nroots {
            // root = fcr + i * prim = i
            genpoly[i + 1] = 1;
            for j in (1..=i).rev() {
                genpoly[j] = if genpoly[j] != 0 {
                    genpoly[j - 1]
                        ^ alpha_to[modnn(index_of[genpoly[j] as usize] as usize + i) as usize]
                } else {
                    genpoly[j - 1]
                };
            }
            genpoly[0] = alpha_to[modnn(index_of[genpoly[0] as usize] as usize + i) as usize];
        }
        for g in &mut genpoly {
            *g = index_of[*g as usize];
        }
        Self {
            alpha_to,
            index_of,
            genpoly,
            nroots,
        }
    }

    fn encode(&self, data: &[u8], parity: &mut [u8]) {
        let n = self.nroots;
        parity.fill(0);
        for &d in data {
            let feedback = self.index_of[(d ^ parity[0]) as usize];
            if feedback != Self::A0 {
                for j in 1..n {
                    parity[j] ^=
                        self.alpha_to[(feedback as usize + self.genpoly[n - j] as usize) % FEC_RSM];
                }
            }
            parity.copy_within(1.., 0);
            parity[n - 1] = if feedback != Self::A0 {
                self.alpha_to[(feedback as usize + self.genpoly[0] as usize) % FEC_RSM]
            } else {
                0
            };
        }
    }
}

/// VerityWriterAndroid::EncodeFEC.
fn encode_fec(data: &[u8], block_size: usize, roots: usize, fec_size: usize) -> Result<Vec<u8>> {
    ensure!(roots > 0 && roots < FEC_RSM, "invalid FEC roots {roots}");
    ensure!(
        data.len().is_multiple_of(block_size),
        "FEC data is not block aligned"
    );
    let rs_n = FEC_RSM - roots;
    let rounds = (data.len() / block_size).div_ceil(rs_n);
    ensure!(
        rounds * roots * block_size == fec_size,
        "FEC size doesn't match its data"
    );
    let rs = ReedSolomon::new(roots);

    let mut fec = vec![0u8; fec_size];
    fec.par_chunks_mut(block_size * roots)
        .enumerate()
        .for_each(|(i, out)| {
            let mut rs_blocks = vec![0u8; block_size * rs_n];
            for j in 0..rs_n {
                // fec_ecc_interleave(i * rs_n * block_size + j, rs_n, rounds)
                let offset = (i * block_size) as u64 + j as u64 * rounds as u64 * FEC_BLOCKSIZE;
                if offset < data.len() as u64 {
                    let block = &data[offset as usize..offset as usize + block_size];
                    for (k, &byte) in block.iter().enumerate() {
                        rs_blocks[k * rs_n + j] = byte;
                    }
                }
            }
            for (symbols, parity) in rs_blocks.chunks(rs_n).zip(out.chunks_mut(roots)) {
                rs.encode(symbols, parity);
            }
        });
    Ok(fec)
}

/// Writes the hash tree and FEC described by `part` into `image`, which
/// already holds the output of every operation.
pub fn write_verity(part: &PartitionUpdate, image: &mut [u8], block_size: u64) -> Result<()> {
    let bs = block_size as usize;
    if let (Some(data), Some(tree)) = (
        present(part.hash_tree_data_extent.as_ref()),
        present(part.hash_tree_extent.as_ref()),
    ) {
        let (data_start, data_end) = byte_range(data, block_size);
        let (tree_start, tree_end) = byte_range(tree, block_size);
        ensure!(
            data_end <= image.len() && tree_end <= image.len(),
            "hash tree extents exceed the partition"
        );
        let algorithm = part.hash_tree_algorithm.as_deref().unwrap_or("sha256");
        let salt = part.hash_tree_salt.as_deref().unwrap_or_default();
        let hash_tree = build_hash_tree(&image[data_start..data_end], bs, algorithm, salt)?;
        ensure!(
            hash_tree.len() == tree_end - tree_start,
            "hash tree is {} bytes, but its extent is {}",
            hash_tree.len(),
            tree_end - tree_start
        );
        image[tree_start..tree_end].copy_from_slice(&hash_tree);
    }

    if let (Some(data), Some(fec)) = (
        present(part.fec_data_extent.as_ref()),
        present(part.fec_extent.as_ref()),
    ) {
        let (data_start, data_end) = byte_range(data, block_size);
        let (fec_start, fec_end) = byte_range(fec, block_size);
        ensure!(
            data_end <= image.len() && fec_end <= image.len(),
            "FEC extents exceed the partition"
        );
        let roots = part.fec_roots.unwrap_or(2) as usize;
        let encoded = encode_fec(&image[data_start..data_end], bs, roots, fec_end - fec_start)?;
        image[fec_start..fec_end].copy_from_slice(&encoded);
    }
    Ok(())
}

pub fn needs_verity(part: &PartitionUpdate) -> bool {
    present(part.hash_tree_extent.as_ref()).is_some() || present(part.fec_extent.as_ref()).is_some()
}
