// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use memmap2::Mmap;
use prost::Message;

use crate::manifest::{DeltaArchiveManifest, InstallOperation};

const MAGIC: &[u8] = b"CrAU";
const SUPPORTED_MAJOR_VERSION: u64 = 2;
const HEADER_SIZE: usize = 4 + 8 + 8 + 4;

/// A payload.bin, either standalone or stored inside an OTA zip.
pub struct Payload {
    map: Mmap,
    /// Offset of payload.bin inside the mapped file.
    base: usize,
    /// Offset of the data blobs relative to `base`.
    data_offset: usize,
    pub manifest: DeltaArchiveManifest,
}

impl Payload {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: the file is only read, and OTA files aren't expected to change underneath us.
        let map =
            unsafe { Mmap::map(&file) }.with_context(|| format!("mapping {}", path.display()))?;
        let base = if map.starts_with(b"PK\x03\x04") {
            zip_entry_offset(&file, "payload.bin")
                .with_context(|| format!("locating payload.bin in {}", path.display()))?
        } else {
            0
        };

        let header = map
            .get(base..base + HEADER_SIZE)
            .context("payload is truncated")?;
        ensure!(
            &header[..4] == MAGIC,
            "{} is not an update payload",
            path.display()
        );
        let major = u64::from_be_bytes(header[4..12].try_into().unwrap());
        ensure!(
            major == SUPPORTED_MAJOR_VERSION,
            "unsupported payload major version {major}"
        );
        let manifest_size = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
        let metadata_signature_size =
            u32::from_be_bytes(header[20..24].try_into().unwrap()) as usize;

        let manifest_start = base + HEADER_SIZE;
        let manifest_bytes = map
            .get(manifest_start..manifest_start + manifest_size)
            .context("payload manifest is truncated")?;
        let manifest = DeltaArchiveManifest::decode(manifest_bytes).context("parsing manifest")?;

        Ok(Self {
            map,
            base,
            data_offset: HEADER_SIZE + manifest_size + metadata_signature_size,
            manifest,
        })
    }

    pub fn block_size(&self) -> u64 {
        self.manifest.block_size.unwrap_or(4096) as u64
    }

    pub fn op_data(&self, op: &InstallOperation) -> Result<&[u8]> {
        let len = op.data_length.unwrap_or(0) as usize;
        if len == 0 {
            return Ok(&[]);
        }
        let start = self.base + self.data_offset + op.data_offset.unwrap_or(0) as usize;
        self.map
            .get(start..start + len)
            .context("operation data lies outside the payload")
    }
}

fn zip_entry_offset(file: &File, name: &str) -> Result<usize> {
    let mut archive = zip::ZipArchive::new(file)?;
    let entry = archive.by_name(name)?;
    if entry.compression() != zip::CompressionMethod::Stored {
        bail!("{name} is compressed inside the zip; extract it first");
    }
    Ok(entry
        .data_start()
        .context("payload.bin has no data offset")? as usize)
}
