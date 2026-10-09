// SPDX-FileCopyrightText: 2003-2005 Colin Percival
// SPDX-FileCopyrightText: The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-2-Clause

//! bspatch for the "BSDIFF40" and "BSDF2" formats, following external/bsdiff.

use std::io::Read;

use anyhow::{Context, Result, bail, ensure};

const LEGACY_MAGIC: &[u8] = b"BSDIFF40";
const BSDF2_MAGIC: &[u8] = b"BSDF2";
const HEADER_SIZE: usize = 32;

const COMPRESSOR_BZ2: u8 = 1;
const COMPRESSOR_BROTLI: u8 = 2;

/// bsdiff's sign-magnitude little-endian integer encoding.
fn parse_int64(buf: &[u8]) -> i64 {
    let magnitude = i64::from_le_bytes(buf[..8].try_into().unwrap()) & i64::MAX;
    if buf[7] & 0x80 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

fn decompressor<'a>(kind: u8, data: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
    Ok(match kind {
        COMPRESSOR_BZ2 => Box::new(bzip2::read::BzDecoder::new(data)),
        COMPRESSOR_BROTLI => Box::new(brotli_decompressor::Decompressor::new(data, 64 * 1024)),
        _ => bail!("unsupported bsdiff compressor type {kind}"),
    })
}

fn read_int64(stream: &mut dyn Read) -> Result<i64> {
    let mut buf = [0u8; 8];
    stream
        .read_exact(&mut buf)
        .context("reading bsdiff control stream")?;
    Ok(parse_int64(&buf))
}

pub fn bspatch(old: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    ensure!(patch.len() >= HEADER_SIZE, "bsdiff patch is too small");
    let compressors = if patch.starts_with(LEGACY_MAGIC) {
        [COMPRESSOR_BZ2; 3]
    } else if patch.starts_with(BSDF2_MAGIC) {
        [patch[5], patch[6], patch[7]]
    } else {
        bail!("not a bsdiff patch");
    };

    let ctrl_len = parse_int64(&patch[8..]);
    let diff_len = parse_int64(&patch[16..]);
    let new_size = parse_int64(&patch[24..]);
    let body = (patch.len() - HEADER_SIZE) as i64;
    ensure!(
        ctrl_len >= 0
            && diff_len >= 0
            && new_size >= 0
            && ctrl_len <= body
            && diff_len <= body - ctrl_len,
        "corrupt bsdiff header"
    );
    let (ctrl_len, diff_len, new_size) = (ctrl_len as usize, diff_len as usize, new_size as usize);

    let ctrl_start = HEADER_SIZE;
    let diff_start = ctrl_start + ctrl_len;
    let extra_start = diff_start + diff_len;
    let mut ctrl = decompressor(compressors[0], &patch[ctrl_start..diff_start])?;
    let mut diff = decompressor(compressors[1], &patch[diff_start..extra_start])?;
    let mut extra = decompressor(compressors[2], &patch[extra_start..])?;

    let mut new = Vec::with_capacity(new_size);
    let mut old_pos: i64 = 0;
    while new.len() < new_size {
        let diff_size = read_int64(&mut ctrl)?;
        let extra_size = read_int64(&mut ctrl)?;
        let seek = read_int64(&mut ctrl)?;
        ensure!(
            diff_size >= 0 && extra_size >= 0,
            "corrupt bsdiff control entry"
        );
        let (diff_size, extra_size) = (diff_size as usize, extra_size as usize);

        ensure!(new.len() + diff_size <= new_size, "corrupt bsdiff patch");
        let start = new.len();
        new.resize(start + diff_size, 0);
        diff.read_exact(&mut new[start..])
            .context("reading bsdiff diff stream")?;
        // Bytes outside the old file are taken from the diff stream as-is.
        for (i, byte) in new[start..].iter_mut().enumerate() {
            let pos = old_pos + i as i64;
            if pos >= 0 && (pos as usize) < old.len() {
                *byte = byte.wrapping_add(old[pos as usize]);
            }
        }
        old_pos += diff_size as i64;

        ensure!(new.len() + extra_size <= new_size, "corrupt bsdiff patch");
        let start = new.len();
        new.resize(start + extra_size, 0);
        extra
            .read_exact(&mut new[start..])
            .context("reading bsdiff extra stream")?;
        old_pos = old_pos.checked_add(seek).context("corrupt bsdiff seek")?;
    }
    Ok(new)
}
