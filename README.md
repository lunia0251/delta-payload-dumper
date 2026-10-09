# delta-payload-dumper

Extracts partition images from Android A/B OTA payloads (`payload.bin`),
including **incremental** OTAs.

Tools like [payload-dumper-go](https://github.com/ssut/payload-dumper-go) only
handle full OTAs. An incremental OTA stores most partitions as patches against
the previous build. To extract one, you have to apply those patches to the
source images, as update_engine does on the device. This tool does that and
produces the same images the device would end up with.

## Building

```sh
cargo install --path .
# or: cargo build --release  →  target/release/delta-payload-dumper
```

## Usage

```sh
# Full OTA
delta-payload-dumper ota.zip

# Incremental OTA, with the source build as a directory of <partition>.img
delta-payload-dumper -s old_images/ incremental.zip

# Incremental OTA, with the source build as its full OTA (zip or payload.bin)
delta-payload-dumper -s old_full_ota.zip incremental.zip
```

| Option | Description |
|---|---|
| `-s, --source <PATH>` | Source build for incremental OTAs: a directory of `<partition>.img`, or a full OTA zip / `payload.bin` |
| `-o, --output <DIR>` | Output directory (default: `extracted_<timestamp>`) |
| `-p, --partitions <a,b,...>` | Only extract these partitions |
| `-l, --list` | List the partitions in the payload and exit |
| `-c, --concurrency <N>` | Number of worker threads (default: CPU count) |
| `--no-verify` | Skip SHA-256 checks |

The input can be an OTA zip or a bare `payload.bin`. Each partition is written
to `<output>/<partition>.img`. To step through several incrementals in a row,
pass each run's output directory as the next run's `--source`.

When the source is a full OTA, the needed partitions are first extracted into a
temporary directory inside the output directory. They are checked against the
incremental's expected source hashes before any work starts. Source images must
be raw: convert Android sparse images with `simg2img` first.

## Verification

By default, the tool checks:

- each operation's data against its `data_sha256_hash`
- the source data each operation reads against its `src_sha256_hash`, so the
  wrong source build is reported at the first operation that reads it
- each finished image against `new_partition_info.hash`

## Supported operations

| Operation | Status |
|---|---|
| `REPLACE`, `REPLACE_BZ`, `REPLACE_XZ` | ✓ |
| `ZERO`, `DISCARD` | ✓ |
| `SOURCE_COPY` | ✓ |
| `SOURCE_BSDIFF`, `BROTLI_BSDIFF` (`BSDIFF40` / `BSDF2`) | ✓ |
| `PUFFDIFF` (bsdiff-based) | ✓ |
| `ZUCCHINI`, `LZ4DIFF_BSDIFF`, `LZ4DIFF_PUFFDIFF` | not yet |
| `MOVE`, `BSDIFF` (in-place, minor version 1) | not supported |

The tool also regenerates the dm-verity **hash tree** and **FEC** for
partitions whose payload sets `hash_tree_extent` / `fec_extent`. update_engine
computes these on the device instead of shipping them in the payload.

## How it works

- **bspatch**: implements the `BSDIFF40` and `BSDF2` formats (bzip2/brotli
  streams) from AOSP `external/bsdiff`.
- **puffin**: a port of AOSP `external/puffin`. Deflate streams in the source
  are converted ("puffed") into puffin's intermediate format, bspatched, then
  re-encoded ("huffed") into deflate. Re-encoding has to match puffin bit for
  bit, so the port keeps its quirks.
- **verity**: follows `HashTreeBuilder` (system/extras) and
  `VerityWriterAndroid::EncodeFEC` (update_engine), including libfec's
  Reed-Solomon parameters and block interleaving.

Operations within a partition write to disjoint destination extents, so they
are applied in parallel.

## License

Apache-2.0, except the files ported from AOSP:

- `src/puffin/`: BSD-3-Clause (The ChromiumOS Authors)
- `src/bspatch.rs`: BSD-2-Clause (Colin Percival, The ChromiumOS Authors)

Each file carries its SPDX header.
