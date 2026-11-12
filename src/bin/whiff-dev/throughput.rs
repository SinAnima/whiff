//! `whiff-dev throughput`: files per second per core over a corpus.
//!
//! The plan's target is ≥ 2,000 files/s/core with the `minimal` profile. The
//! corpus (default `tests/fixtures`) is read once to warm the page cache, then
//! cycled until `--files` extractions are done, so the figure is CPU time per
//! file, not disk speed. Point it at a real tree for a representative mix;
//! the fixtures over-represent rare formats, one folder each.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use whiff::{Engine, Profile};

pub struct Request {
    pub paths: Vec<PathBuf>,
    pub files: usize,
    pub profile: Profile,
    pub threads: usize,
    pub min: Option<f64>,
    pub top: usize,
}

#[derive(Default)]
struct Tally {
    count: u64,
    time: Duration,
    bytes: u64,
}

pub fn run(req: &Request) -> Result<(), String> {
    let mut corpus = Vec::new();
    for p in &req.paths {
        collect(p, &mut corpus);
    }
    corpus.sort();
    if corpus.is_empty() {
        return Err("no files in the corpus".into());
    }
    let engine = Engine::builder().profile(req.profile).build();
    // Warm-up: page cache, lazily built tables (regexes, the detector).
    let mut corpus_bytes = 0u64;
    for p in &corpus {
        if let Ok(r) = engine.extract_path(p) {
            corpus_bytes += r.system.size_bytes.unwrap_or(0);
        }
    }
    let threads = req.threads.max(1);
    let next = AtomicUsize::new(0);
    let tallies: Mutex<BTreeMap<String, Tally>> = Mutex::default();
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local: BTreeMap<String, Tally> = BTreeMap::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= req.files {
                        break;
                    }
                    let path = &corpus[i % corpus.len()];
                    let t = Instant::now();
                    let report = engine.extract_path(path);
                    let took = t.elapsed();
                    let (format, size) = report.map_or_else(
                        |_| ("(error)".to_string(), 0),
                        |r| (r.identification.format, r.system.size_bytes.unwrap_or(0)),
                    );
                    let e = local.entry(format).or_default();
                    e.count += 1;
                    e.time += took;
                    e.bytes += size;
                }
                let mut all = tallies.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                for (k, v) in local {
                    let e = all.entry(k).or_default();
                    e.count += v.count;
                    e.time += v.time;
                    e.bytes += v.bytes;
                }
            });
        }
    });
    let wall = start.elapsed().as_secs_f64();
    let tallies = tallies.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
    let done: u64 = tallies.values().map(|t| t.count).sum();
    let bytes: u64 = tallies.values().map(|t| t.bytes).sum();
    #[allow(clippy::cast_precision_loss)]
    let (files_s, mib_s) = (done as f64 / wall, bytes as f64 / wall / 1_048_576.0);
    #[allow(clippy::cast_precision_loss)]
    let per_core = files_s / threads as f64;
    println!(
        "corpus: {} files, {:.1} MiB; profile {}; {threads} thread(s)",
        corpus.len(),
        mib(corpus_bytes),
        profile_name(req.profile)
    );
    println!("{done} extractions in {wall:.2} s: {files_s:.0} files/s ({per_core:.0} files/s/core), {mib_s:.1} MiB/s");
    let mut slow: Vec<(&String, &Tally)> = tallies.iter().collect();
    slow.sort_by(|a, b| mean(b.1).cmp(&mean(a.1)).then(a.0.cmp(b.0)));
    if req.top > 0 {
        println!("\nslowest formats (mean time per file):");
        println!("  {:<24} {:>10} {:>8} {:>10}", "format", "mean", "files", "share");
        let total: Duration = tallies.values().map(|t| t.time).sum();
        for (id, t) in slow.iter().take(req.top) {
            let share = t.time.as_secs_f64() / total.as_secs_f64().max(f64::MIN_POSITIVE) * 100.0;
            println!("  {id:<24} {:>10} {:>8} {share:>9.1}%", fmt_duration(mean(t)), t.count);
        }
    }
    match req.min {
        Some(min) if per_core < min => Err(format!("{per_core:.0} files/s/core is below the target of {min:.0}")),
        Some(min) => {
            println!("\nok: {per_core:.0} files/s/core ≥ {min:.0}");
            Ok(())
        }
        None => Ok(()),
    }
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with('.') || name == "SOURCE.md" {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else { return };
    if meta.is_dir() {
        let Ok(rd) = std::fs::read_dir(path) else { return };
        for entry in rd.flatten() {
            collect(&entry.path(), out);
        }
    } else if meta.is_file() {
        out.push(path.to_path_buf());
    }
}

fn mean(t: &Tally) -> Duration {
    t.time / u32::try_from(t.count.max(1)).unwrap_or(u32::MAX)
}

fn fmt_duration(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us >= 1000.0 { format!("{:.2} ms", us / 1000.0) } else { format!("{us:.0} µs") }
}

#[allow(clippy::cast_precision_loss)]
fn mib(b: u64) -> f64 {
    b as f64 / 1_048_576.0
}

fn profile_name(p: Profile) -> &'static str {
    match p {
        Profile::Minimal => "minimal",
        Profile::Standard => "standard",
        Profile::Full => "full",
        Profile::Llm => "llm",
        _ => "other",
    }
}
