//! `whiff-dev`: contributor tooling. Run with
//! `cargo run --features dev --bin whiff-dev -- <command>`.
//! The `dev` feature implies `full`, so every extractor is visible.

mod catalogue;
mod checks;
mod new_extractor;
mod oracle;
mod throughput;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use whiff::{Profile, Registry};

#[derive(Parser)]
#[command(name = "whiff-dev", about = "whiff contributor tooling")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scaffold a new extractor: source file, module lines, fixture folder.
    NewExtractor {
        /// `<group>.<format>`, e.g. `image.qoi` (group = directory under src/formats/).
        id: String,
        /// Parser family from data/families.tsv, e.g. `image.raster`; decides the cargo feature.
        #[arg(long)]
        family: String,
        /// Human-readable format name.
        #[arg(long)]
        name: String,
        /// Extension without the dot (repeatable).
        #[arg(long = "ext")]
        extensions: Vec<String>,
        /// MIME type (repeatable, preferred first).
        #[arg(long = "mime")]
        mimes: Vec<String>,
        /// Magic as hex, optionally `offset:hex`, e.g. `716f6966` or `4:66747970` (repeatable).
        #[arg(long)]
        magic: Vec<String>,
        /// Print what would change without writing.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite an existing extractor file.
        #[arg(long)]
        force: bool,
    },
    /// Regenerate docs/metadata-extracted.md (from data/ and the registry) and
    /// docs/risks.md (from the risk vocabulary).
    Catalogue {
        /// Fail if the committed file is out of date instead of writing it.
        #[arg(long)]
        check: bool,
    },
    /// Fuzz one extractor, a shard of them, or the whole engine (needs
    /// nightly and cargo-fuzz).
    Fuzz {
        /// Extractor id, e.g. `image.qoi`; omit to fuzz the whole engine.
        #[arg(conflicts_with = "shard")]
        extractor: Option<String>,
        /// `I/N`: the I-th of N shards of the extractors (sorted by id, every
        /// N-th from I), with detection, seeded from their fixtures. The
        /// nightly CI job runs every shard.
        #[arg(long, value_name = "I/N")]
        shard: Option<String>,
        /// Run time in seconds.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Target triple for cargo-fuzz (the prebuilt cargo-fuzz defaults to
        /// musl; the address sanitizer needs e.g. `x86_64-unknown-linux-gnu`).
        #[arg(long)]
        target: Option<String>,
    },
    /// Check transitive dependency counts against the budgets, and that the
    /// dependency graph is pure Rust.
    CheckDeps,
    /// Check that format modules use only the plugin API.
    CheckBoundary,
    /// Files per second per core over a corpus (target: 2,000 with `minimal`).
    Throughput {
        /// Files or directories (default: tests/fixtures), cycled until `--files` are done.
        paths: Vec<PathBuf>,
        /// Extractions to run.
        #[arg(long, default_value_t = 100_000)]
        files: usize,
        /// Report profile: minimal, standard, full or llm.
        #[arg(long, default_value = "minimal")]
        profile: Profile,
        /// Worker threads; files/s/core divides by this.
        #[arg(long, default_value_t = 1)]
        threads: usize,
        /// Fail below this many files/s/core.
        #[arg(long)]
        min: Option<f64>,
        /// How many of the slowest formats to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Compare whiff with a reference tool (dev-time oracle; needs the tool installed).
    Oracle {
        #[command(subcommand)]
        family: OracleFamily,
    },
}

#[derive(Subcommand)]
enum OracleFamily {
    /// Normalised image metadata against `exiftool -use MWG`.
    Images {
        /// Files or directories (default: tests/fixtures). Build a larger corpus with
        /// `scripts/fixtures/oracle-corpus.sh`.
        paths: Vec<PathBuf>,
        /// Minimum agreement on the gated fields, in percent.
        #[arg(long, default_value_t = 95.0)]
        min: f64,
        /// List every disagreement, not the first 25.
        #[arg(long)]
        verbose: bool,
    },
    /// Audio / video duration, sample rate, channels, video codec, size and frame rate against `ffprobe`.
    Media {
        /// Files or directories (default: tests/fixtures).
        paths: Vec<PathBuf>,
        /// Largest duration difference that agrees, in seconds.
        #[arg(long, default_value_t = 0.1)]
        tolerance: f64,
        /// Minimum duration agreement, in percent.
        #[arg(long, default_value_t = 98.0)]
        min: f64,
        /// List every disagreement, not the first 25.
        #[arg(long)]
        verbose: bool,
    },
    /// Subtitle codec, cue count and end of the last cue against `ffprobe`'s packets.
    Subtitles {
        /// Files or directories (default: tests/fixtures).
        paths: Vec<PathBuf>,
        /// Largest difference in the end of the last cue that agrees, in seconds.
        #[arg(long, default_value_t = 0.05)]
        tolerance: f64,
        /// Minimum cue count agreement, in percent.
        #[arg(long, default_value_t = 98.0)]
        min: f64,
        /// List every disagreement, not the first 25.
        #[arg(long)]
        verbose: bool,
    },
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Cmd::NewExtractor { id, family, name, extensions, mimes, magic, dry_run, force } => {
            let extensions = extensions.into_iter().map(|e| e.trim_start_matches('.').to_ascii_lowercase()).collect();
            new_extractor::run(
                root(),
                &new_extractor::Request { id, family, name, extensions, mimes, magic, dry_run, force },
            )
        }
        Cmd::Catalogue { check } => catalogue_cmd(check),
        Cmd::Fuzz { extractor, shard, seconds, target } => {
            fuzz(extractor.as_deref(), shard.as_deref(), seconds, target.as_deref())
        }
        Cmd::CheckDeps => checks::deps(root()),
        Cmd::CheckBoundary => checks::boundary(root()),
        Cmd::Throughput { paths, files, profile, threads, min, top } => {
            let paths = if paths.is_empty() { vec![root().join("tests/fixtures")] } else { paths };
            throughput::run(&throughput::Request { paths, files, profile, threads, min, top })
        }
        Cmd::Oracle { family: OracleFamily::Images { paths, min, verbose } } => {
            let paths = if paths.is_empty() { oracle::default_paths(root()) } else { paths };
            oracle::images(&paths, min, verbose)
        }
        Cmd::Oracle { family: OracleFamily::Media { paths, tolerance, min, verbose } } => {
            let paths = if paths.is_empty() { oracle::default_paths(root()) } else { paths };
            oracle::media(&paths, tolerance, min, verbose)
        }
        Cmd::Oracle { family: OracleFamily::Subtitles { paths, tolerance, min, verbose } } => {
            let paths = if paths.is_empty() { oracle::default_paths(root()) } else { paths };
            oracle::subtitles(&paths, tolerance, min, verbose)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("whiff-dev: {e}");
            ExitCode::FAILURE
        }
    }
}

fn catalogue_cmd(check: bool) -> Result<(), String> {
    let registry = Registry::builtin();
    let docs = [
        ("docs/metadata-extracted.md", catalogue::render(root(), &registry)?),
        ("docs/risks.md", catalogue::render_risks()),
    ];
    for (name, rendered) in docs {
        let path = root().join(name);
        if check {
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            if current != rendered {
                return Err(format!(
                    "{name} is out of date; run `cargo run --features dev --bin whiff-dev -- catalogue`"
                ));
            }
            println!("{name}: up to date");
        } else {
            std::fs::write(&path, rendered).map_err(|e| format!("{}: {e}", path.display()))?;
            println!("wrote {}", path.display());
        }
    }
    Ok(())
}

fn fuzz(extractor: Option<&str>, shard: Option<&str>, seconds: u64, target: Option<&str>) -> Result<(), String> {
    let registry = Registry::builtin();
    // The extractors whose fixtures seed the run, and the corpus folder.
    let (ids, corpus): (Vec<&str>, String) = match (extractor, shard) {
        (Some(id), _) => {
            registry.extractor(id).ok_or_else(|| format!("no extractor `{id}` in this build"))?;
            (vec![id], id.to_string())
        }
        (None, Some(shard)) => {
            let (i, n) = parse_shard(shard)?;
            let mut all: Vec<&str> = registry.extractors().map(|e| e.meta().id).collect();
            all.sort_unstable();
            (all.into_iter().skip(i).step_by(n).collect(), format!("shard-{i}-of-{n}"))
        }
        (None, None) => (Vec::new(), "engine".to_string()),
    };
    let mut corpora: Vec<PathBuf> = vec![root().join("fuzz/corpus").join(&corpus)];
    for id in &ids {
        let Some(e) = registry.extractor(id) else { continue };
        for f in e.meta().formats {
            let dir = root().join("tests/fixtures").join(f.id);
            if dir.is_dir() && !corpora.contains(&dir) {
                corpora.push(dir);
            }
        }
    }
    std::fs::create_dir_all(&corpora[0]).map_err(|e| e.to_string())?;
    if shard.is_some() {
        println!("fuzzing {} extractors: {}", ids.len(), ids.join(", "));
    }
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root().join("fuzz")).args(["+nightly", "fuzz", "run", "extract"]);
    if let Some(t) = target {
        cmd.args(["--target", t]);
    }
    cmd.args(&corpora);
    // A hang (one input over 60 s) is reported as a timeout, not waited out.
    cmd.arg("--").arg(format!("-max_total_time={seconds}")).arg("-timeout=60");
    match (extractor, shard) {
        (Some(id), _) => {
            cmd.env("WHIFF_FUZZ_EXTRACTOR", id);
        }
        (None, Some(_)) => {
            cmd.env("WHIFF_FUZZ_EXTRACTORS", ids.join(","));
        }
        (None, None) => {}
    }
    let status = cmd.status().map_err(|e| format!("cannot run cargo-fuzz ({e}); install with `cargo install cargo-fuzz` and `rustup toolchain install nightly`"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("fuzzing failed ({status}); crashes are in fuzz/artifacts/extract/"))
    }
}

/// `I/N` with `I < N`.
fn parse_shard(s: &str) -> Result<(usize, usize), String> {
    let bad = || format!("--shard wants I/N with I < N, e.g. 0/8, not `{s}`");
    let (i, n) = s.split_once('/').ok_or_else(bad)?;
    let (i, n): (usize, usize) = (i.trim().parse().map_err(|_| bad())?, n.trim().parse().map_err(|_| bad())?);
    if n == 0 || i >= n {
        return Err(bad());
    }
    Ok((i, n))
}
