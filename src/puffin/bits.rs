// SPDX-FileCopyrightText: 2017 The ChromiumOS Authors
// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: BSD-3-Clause

//! Ports of puffin's BufferBitReader and BufferBitWriter. The writer keeps
//! puffin's exact semantics (including not masking `bits` to `nbits`), since
//! the huffed output has to be bit-identical to what update_engine produces.

use anyhow::{Result, ensure};

pub struct BitReader<'a> {
    buf: &'a [u8],
    index: usize,
    cache: u64,
    cache_bits: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            index: 0,
            cache: 0,
            cache_bits: 0,
        }
    }

    pub fn cache_bits(&mut self, nbits: usize) -> bool {
        if (self.buf.len() - self.index) * 8 + self.cache_bits < nbits || nbits > 32 {
            return false;
        }
        while self.cache_bits < nbits {
            self.cache |= (self.buf[self.index] as u64) << self.cache_bits;
            self.index += 1;
            self.cache_bits += 8;
        }
        true
    }

    pub fn read_bits(&self, nbits: usize) -> u32 {
        (self.cache & ((1u64 << nbits) - 1)) as u32
    }

    pub fn drop_bits(&mut self, nbits: usize) -> Result<()> {
        ensure!(nbits <= self.cache_bits, "deflate stream is truncated");
        self.cache >>= nbits;
        self.cache_bits -= nbits;
        Ok(())
    }

    pub fn read_boundary_bits(&self) -> u8 {
        (self.cache & ((1 << (self.cache_bits & 7)) - 1)) as u8
    }

    pub fn skip_boundary_bits(&mut self) {
        let nbits = self.cache_bits & 7;
        self.cache >>= nbits;
        self.cache_bits -= nbits;
    }

    /// Returns the next `len` raw bytes, discarding the cached bits.
    pub fn take_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.index -= self.cache_bits.div_ceil(8);
        self.cache = 0;
        self.cache_bits = 0;
        ensure!(
            len <= self.buf.len() - self.index,
            "stored block is truncated"
        );
        let bytes = &self.buf[self.index..self.index + len];
        self.index += len;
        Ok(bytes)
    }

    pub fn offset(&self) -> usize {
        self.index - self.cache_bits / 8
    }

    pub fn bits_remaining(&self) -> usize {
        (self.buf.len() - self.index) * 8 + self.cache_bits
    }
}

pub struct BitWriter {
    out: Vec<u8>,
    capacity: usize,
    holder: u32,
    holder_bits: usize,
}

impl BitWriter {
    pub fn new(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            capacity,
            holder: 0,
            holder_bits: 0,
        }
    }

    fn free_bits(&self) -> usize {
        (self.capacity - self.out.len()) * 8 - self.holder_bits
    }

    pub fn write_bits(&mut self, mut nbits: usize, mut bits: u32) -> Result<()> {
        ensure!(
            self.free_bits() >= nbits && nbits <= 32,
            "huffed deflate overflows its extent"
        );
        while nbits > 0 {
            while self.holder_bits >= 8 {
                self.out.push(self.holder as u8);
                self.holder >>= 8;
                self.holder_bits -= 8;
            }
            while self.holder_bits < 24 && nbits > 0 {
                self.holder |= (bits & 0xFF) << self.holder_bits;
                let n = nbits.min(8);
                self.holder_bits += n;
                bits >>= n;
                nbits -= n;
            }
        }
        Ok(())
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.free_bits() >= bytes.len() * 8,
            "huffed deflate overflows its extent"
        );
        ensure!(self.holder_bits.is_multiple_of(8), "unaligned stored block");
        self.flush()?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    pub fn write_boundary_bits(&mut self, bits: u8) -> Result<()> {
        self.write_bits((8 - (self.holder_bits & 7)) & 7, bits as u32)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.write_boundary_bits(0)?;
        while self.holder_bits > 0 {
            self.out.push(self.holder as u8);
            self.holder >>= 8;
            self.holder_bits -= 8;
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.out.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}
