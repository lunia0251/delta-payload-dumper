// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: Apache-2.0

mod bspatch;
mod extract;
mod manifest;
mod payload;
mod puffin;
mod verity;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tempfile::TempDir;

use extract::Source;
use manifest::PartitionUpdate;
use payload::Payload;

/// Extracts partition images from full and incremental Android OTA payloads.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// OTA zip or payload.bin
    payload: PathBuf,

    /// Output directory [default: extracted_<timestamp>]
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Source build for incremental OTAs: a directory of <partition>.img, or a
    /// full OTA zip / payload.bin of that build
    #[arg(short, long)]
    source: Option<PathBuf>,

    /// Only extract these partitions (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    partitions: Vec<String>,

    /// List the partitions in the payload and exit
    #[arg(short, long)]
    list: bool,

    /// Number of worker threads
    #[arg(short, long, default_value_t = std::thread::available_parallelism().map_or(4, |n| n.get()))]
    concurrency: usize,

    /// Skip SHA-256 checks of operation data, source data and output images
    #[arg(long)]
    no_verify: bool,
}

fn select<'a>(
    partitions: &'a [PartitionUpdate],
    names: &[String],
) -> Result<Vec<&'a PartitionUpdate>> {
    if names.is_empty() {
        return Ok(partitions.iter().collect());
    }
    names
        .iter()
        .map(|name| {
            partitions
                .iter()
                .find(|p| p.partition_name == *name)
                .with_context(|| format!("partition {name} is not in the payload"))
        })
        .collect()
}

struct Job<'a> {
    part: &'a PartitionUpdate,
    source: Option<&'a Source>,
    out_path: PathBuf,
}

fn run_jobs(mp: &MultiProgress, payload: &Payload, jobs: &[Job], verify: bool) -> Result<()> {
    let style = ProgressStyle::with_template("{prefix:>20} [{bar:40}] {pos:>5}/{len:5} ops {msg}")
        .unwrap()
        .progress_chars("=> ");
    jobs.par_iter().try_for_each(|job| {
        let pb = mp.add(ProgressBar::new(job.part.operations.len() as u64));
        pb.set_style(style.clone());
        pb.set_prefix(job.part.partition_name.clone());
        let result =
            extract::extract_partition(payload, job.part, job.source, &job.out_path, verify, &pb);
        pb.finish_with_message(if result.is_ok() { "done" } else { "FAILED" });
        result
    })
}

/// Opens the source image of every incremental partition in `parts`. Images
/// from a full OTA are extracted into a temporary directory in `out_dir`,
/// which is returned so it outlives the extraction.
fn open_sources(
    mp: &MultiProgress,
    source: &Path,
    parts: &[&PartitionUpdate],
    out_dir: &Path,
    verify: bool,
) -> Result<(HashMap<String, Source>, Option<TempDir>)> {
    let mut tmp_dir = None;
    let paths: Vec<(String, PathBuf)> = if source.is_dir() {
        parts
            .iter()
            .map(|p| {
                (
                    p.partition_name.clone(),
                    source.join(format!("{}.img", p.partition_name)),
                )
            })
            .collect()
    } else {
        let src_payload = Payload::open(source)?;
        let tmp = tmp_dir.insert(
            tempfile::Builder::new()
                .prefix(".source-")
                .tempdir_in(out_dir)?,
        );
        let mut jobs = Vec::new();
        for part in parts {
            let name = &part.partition_name;
            let src_part = src_payload
                .manifest
                .partitions
                .iter()
                .find(|p| p.partition_name == *name)
                .with_context(|| format!("source OTA has no {name} partition"))?;
            ensure!(
                !src_part.is_delta(),
                "source OTA must be a full OTA, but its {name} is incremental"
            );
            if let (Some(expected), Some(actual)) = (part.old_hash(), src_part.new_hash()) {
                ensure!(
                    expected == actual,
                    "{name}: the source OTA isn't the build this incremental was generated from"
                );
            }
            jobs.push(Job {
                part: src_part,
                source: None,
                out_path: tmp.path().join(format!("{name}.img")),
            });
        }
        eprintln!(
            "Extracting {} source partitions from {}",
            jobs.len(),
            source.display()
        );
        run_jobs(mp, &src_payload, &jobs, verify)?;
        jobs.into_iter()
            .map(|j| (j.part.partition_name.clone(), j.out_path))
            .collect()
    };
    let sources = paths
        .into_iter()
        .map(|(name, path)| Ok((name, Source::open(&path)?)))
        .collect::<Result<_>>()?;
    Ok((sources, tmp_dir))
}

fn run() -> Result<()> {
    let args = Args::parse();
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.concurrency)
        .build_global()?;
    let verify = !args.no_verify;

    let payload = Payload::open(&args.payload)?;
    if args.list {
        return match extract::list(&payload, std::io::stdout().lock()) {
            Err(e)
                if e.downcast_ref::<std::io::Error>().map(std::io::Error::kind)
                    == Some(ErrorKind::BrokenPipe) =>
            {
                Ok(())
            }
            result => result,
        };
    }

    let parts = select(&payload.manifest.partitions, &args.partitions)?;
    let delta_parts: Vec<&PartitionUpdate> =
        parts.iter().copied().filter(|p| p.is_delta()).collect();
    if !delta_parts.is_empty() && args.source.is_none() {
        let names: Vec<&str> = delta_parts
            .iter()
            .map(|p| p.partition_name.as_str())
            .collect();
        bail!(
            "this is an incremental OTA; pass the source build with --source (needed for: {})",
            names.join(", ")
        );
    }

    let out_dir = args.output.unwrap_or_else(|| {
        PathBuf::from(
            chrono::Local::now()
                .format("extracted_%Y%m%d_%H%M%S")
                .to_string(),
        )
    });
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let mp = MultiProgress::new();
    let (sources, _tmp_dir) = match &args.source {
        Some(source) if !delta_parts.is_empty() => {
            open_sources(&mp, source, &delta_parts, &out_dir, verify)?
        }
        _ => (HashMap::new(), None),
    };

    let jobs: Vec<Job> = parts
        .iter()
        .map(|part| Job {
            part,
            source: sources.get(&part.partition_name),
            out_path: out_dir.join(format!("{}.img", part.partition_name)),
        })
        .collect();
    eprintln!(
        "Extracting {} partitions to {}",
        jobs.len(),
        out_dir.display()
    );
    run_jobs(&mp, &payload, &jobs, verify)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
