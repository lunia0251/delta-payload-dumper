// SPDX-FileCopyrightText: 2017 The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-3-Clause

//! puffpatch: bspatch applied to the puffed (deflate-decoded, but
//! reversibly re-encodable) form of the source, then huffed back to deflate.

mod bits;
mod huffman;
mod puff;
mod stream;

use anyhow::{Context, Result, bail, ensure};
use prost::Message;

use crate::bspatch::bspatch;
use crate::manifest::puffin::{PatchHeader, PatchType, StreamInfo};
use stream::{Extent, StreamLayout};

const MAGIC: &[u8] = b"PUF1";

fn layout(info: Option<&StreamInfo>) -> Result<StreamLayout> {
    let info = info.context("puffin patch has no stream info")?;
    let extents = |list: &[crate::manifest::puffin::BitExtent], coef: u64| {
        list.iter()
            .map(|e| Extent {
                offset: e.offset / coef,
                length: e.length / coef,
            })
            .collect::<Vec<_>>()
    };
    // Deflates are bit extents, puffs are stored as bit extents but used as bytes.
    StreamLayout::new(
        extents(&info.deflates, 1),
        extents(&info.puffs, 8),
        info.puff_length,
    )
}

pub fn puffpatch(src: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        patch.len() >= MAGIC.len() + 4 && patch.starts_with(MAGIC),
        "not a puffin patch"
    );
    let header_size = u32::from_be_bytes(patch[4..8].try_into().unwrap()) as usize;
    let header_bytes = patch
        .get(8..8 + header_size)
        .context("puffin patch header is truncated")?;
    let header = PatchHeader::decode(header_bytes).context("parsing puffin patch header")?;
    let raw_patch = &patch[8 + header_size..];

    match PatchType::try_from(header.r#type) {
        Ok(PatchType::Bsdiff) => {}
        Ok(PatchType::Zucchini) => bail!("puffin patches using zucchini are not supported"),
        Err(_) => bail!("unknown puffin patch type {}", header.r#type),
    }

    let src_layout = layout(header.src.as_ref())?;
    let dst_layout = layout(header.dst.as_ref())?;
    let puffed_src = src_layout.puff(src).context("puffing source")?;
    let puffed_dst = bspatch(&puffed_src, raw_patch)?;
    dst_layout.huff(&puffed_dst).context("huffing destination")
}
