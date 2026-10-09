// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use indicatif::ProgressBar;
use memmap2::{Mmap, MmapMut};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::bspatch::bspatch;
use crate::manifest::{Extent, InstallOperation, OpType, PartitionUpdate};
use crate::payload::Payload;
use crate::puffin::puffpatch;
use crate::verity;

const SPARSE_MAGIC: u32 = 0xED26FF3A;

pub struct Source {
    map: Mmap,
}

impl Source {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening source image {}", path.display()))?;
        // SAFETY: source images are only read.
        let map =
            unsafe { Mmap::map(&file) }.with_context(|| format!("mapping {}", path.display()))?;
        ensure!(
            !map.starts_with(&SPARSE_MAGIC.to_le_bytes()),
            "{} is an Android sparse image; convert it with simg2img first",
            path.display()
        );
        Ok(Self { map })
    }
}

fn extents_len(extents: &[Extent], block_size: u64) -> u64 {
    extents
        .iter()
        .map(|e| e.num_blocks.unwrap_or(0))
        .sum::<u64>()
        * block_size
}

fn read_extents(src: &[u8], extents: &[Extent], block_size: u64) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(extents_len(extents, block_size) as usize);
    for e in extents {
        let start = (e.start_block.unwrap_or(0) * block_size) as usize;
        let len = (e.num_blocks.unwrap_or(0) * block_size) as usize;
        let chunk = src.get(start..start + len).with_context(|| {
            format!(
                "source extent {start}+{len} is past the end of the source image ({} bytes)",
                src.len()
            )
        })?;
        data.extend_from_slice(chunk);
    }
    Ok(data)
}

fn write_extents(out: &File, extents: &[Extent], block_size: u64, mut data: &[u8]) -> Result<()> {
    let total = extents_len(extents, block_size);
    ensure!(
        data.len() as u64 <= total,
        "operation produced {} bytes for {total} bytes of destination extents",
        data.len()
    );
    for e in extents {
        if data.is_empty() {
            break;
        }
        let len = ((e.num_blocks.unwrap_or(0) * block_size) as usize).min(data.len());
        out.write_all_at(&data[..len], e.start_block.unwrap_or(0) * block_size)?;
        data = &data[len..];
    }
    Ok(())
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn apply_op(
    payload: &Payload,
    op: &InstallOperation,
    source: Option<&Source>,
    out: &File,
    verify: bool,
) -> Result<()> {
    let op_type = OpType::try_from(op.r#type)
        .map_err(|_| anyhow::anyhow!("unknown operation type {}", op.r#type))?;
    let block_size = payload.block_size();
    let data = payload.op_data(op)?;
    if verify && let Some(expected) = &op.data_sha256_hash {
        ensure!(
            sha256(data) == *expected,
            "operation data hash mismatch (corrupt payload?)"
        );
    }

    let src = if op_type.needs_source() {
        let source = source.context("operation needs a source image")?;
        let src = read_extents(&source.map, &op.src_extents, block_size)?;
        if verify && let Some(expected) = &op.src_sha256_hash {
            ensure!(
                sha256(&src) == *expected,
                "source data hash mismatch: the source image isn't the build this OTA was generated from"
            );
        }
        src
    } else {
        Vec::new()
    };

    let dst = match op_type {
        OpType::Replace => return write_extents(out, &op.dst_extents, block_size, data),
        OpType::ReplaceBz => {
            let mut buf = Vec::new();
            bzip2::read::MultiBzDecoder::new(data)
                .read_to_end(&mut buf)
                .context("bzip2 decompression")?;
            buf
        }
        OpType::ReplaceXz => {
            let mut buf = Vec::new();
            liblzma::read::XzDecoder::new_multi_decoder(data)
                .read_to_end(&mut buf)
                .context("xz decompression")?;
            buf
        }
        // The output file starts out sparse and zero-filled.
        OpType::Zero | OpType::Discard => return Ok(()),
        OpType::SourceCopy => src,
        OpType::SourceBsdiff | OpType::BrotliBsdiff => bspatch(&src, data)?,
        OpType::Puffdiff => puffpatch(&src, data)?,
        OpType::Move | OpType::Bsdiff => {
            bail!("in-place {op_type:?} operations (minor version 1) are not supported")
        }
        OpType::Zucchini | OpType::Lz4diffBsdiff | OpType::Lz4diffPuffdiff => {
            bail!("{op_type:?} operations are not supported yet")
        }
    };
    write_extents(out, &op.dst_extents, block_size, &dst)
}

/// Writes `part` to `out_path`, applying its operations in parallel. Ops of
/// a non-in-place extraction never overlap in their destination extents.
pub fn extract_partition(
    payload: &Payload,
    part: &PartitionUpdate,
    source: Option<&Source>,
    out_path: &Path,
    verify: bool,
    progress: &ProgressBar,
) -> Result<()> {
    let out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .with_context(|| format!("creating {}", out_path.display()))?;
    out.set_len(part.new_size())?;

    part.operations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, op)| {
            apply_op(payload, op, source, &out, verify).with_context(|| {
                let name = OpType::try_from(op.r#type)
                    .map_or_else(|_| op.r#type.to_string(), |t| format!("{t:?}"));
                format!("{}: operation {i} ({name})", part.partition_name)
            })?;
            progress.inc(1);
            Ok::<_, anyhow::Error>(())
        })?;

    let needs_verity = verity::needs_verity(part);
    let expected = part.new_hash().filter(|_| verify);
    if !needs_verity && expected.is_none() {
        return Ok(());
    }
    // SAFETY: the output file is private to this extraction.
    let mut image = unsafe { MmapMut::map_mut(&out) }?;
    if needs_verity {
        progress.set_message("hash tree");
        verity::write_verity(part, &mut image, payload.block_size())
            .with_context(|| format!("{}: generating verity data", part.partition_name))?;
    }
    if let Some(expected) = expected {
        progress.set_message("verifying");
        let actual = sha256(&image);
        ensure!(
            actual == expected,
            "{}: output hash mismatch (expected {}, got {})",
            part.partition_name,
            hex::encode(expected),
            hex::encode(&actual)
        );
    }
    image.flush()?;
    Ok(())
}

/// Writes a short human-readable listing of the payload's partitions.
pub fn list(payload: &Payload, mut w: impl Write) -> Result<()> {
    let m = &payload.manifest;
    writeln!(
        w,
        "block size {}, minor version {}, {}",
        payload.block_size(),
        m.minor_version.unwrap_or(0),
        if m.partitions.iter().any(PartitionUpdate::is_delta) {
            "incremental"
        } else {
            "full"
        }
    )?;
    if let Some(spl) = &m.security_patch_level {
        writeln!(w, "security patch level {spl}")?;
    }
    for part in &m.partitions {
        writeln!(
            w,
            "  {:<24} {:>14} bytes  {:>6} ops  {}",
            part.partition_name,
            part.new_size(),
            part.operations.len(),
            if part.is_delta() { "delta" } else { "full" }
        )?;
    }
    Ok(())
}
