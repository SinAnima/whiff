//! `whiff`: describe files as JSON.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use whiff::{Engine, Hashes, Privacy, Profile, Registry, Report};

#[derive(Parser)]
#[command(
    name = "whiff",
    version,
    about = "Sniff files and describe them as JSON",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand)]
enum Command {
    /// List the formats this build can extract.
    Formats {
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print the JSON Schema of the report.
    Schema,
}

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // independent CLI flags
struct RunArgs {
    /// Files or directories (walked recursively); `-` reads stdin.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// How much work to do per file: `minimal`, `standard`, `full`, or `llm`
    /// (standard plus a summary, printed as the compact LLM view).
    #[arg(short, long, default_value = "standard", value_parser = parse_profile)]
    profile: Profile,
    /// Token budget of the LLM view (`--profile llm`).
    #[arg(long, value_name = "N", default_value_t = 800)]
    max_tokens: usize,
    /// One compact report per line (the default for several files).
    #[arg(long)]
    jsonl: bool,
    /// Indented JSON (the default for one file on a terminal).
    #[arg(long, conflicts_with = "jsonl")]
    pretty: bool,
    /// Recursion depth into embedded files.
    #[arg(long, value_name = "N")]
    max_depth: Option<u32>,
    /// Deadline per file, e.g. `30s`, `500ms`, `2m`, or `none`.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    timeout: Option<Deadline>,
    /// Bytes extractors may read per file, e.g. `256MiB`.
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    max_bytes: Option<u64>,
    /// Hashes: `sha256`, `blake3`, a comma list, or `none`.
    #[arg(long, value_name = "LIST", value_parser = parse_hashes)]
    hash: Option<Hashes>,
    /// Run only these extractors or groups (repeatable, e.g. `image`).
    #[arg(long, value_name = "ID")]
    only: Vec<String>,
    /// Never run these extractors or groups.
    #[arg(long, value_name = "ID")]
    skip: Vec<String>,
    /// Force a format id instead of detecting.
    #[arg(long, value_name = "ID")]
    format: Option<String>,
    /// Record which source set each normalised field.
    #[arg(long)]
    provenance: bool,
    /// Personal data: `strict` counts it and keeps only the domain of e-mail
    /// addresses; `off` gives the full details (addresses, phone numbers,
    /// account numbers and transactions, names) as found.
    #[arg(long, value_name = "MODE", default_value = "strict", value_parser = parse_privacy)]
    privacy: Privacy,
    /// Include hidden files when walking directories.
    #[arg(long)]
    hidden: bool,
    /// Do not respect .gitignore / .ignore files when walking directories.
    #[arg(long)]
    no_ignore: bool,
    /// Worker threads (default: number of CPUs).
    #[arg(short, long, value_name = "N")]
    jobs: Option<usize>,
}

fn parse_profile(s: &str) -> Result<Profile, String> {
    s.parse()
}

fn parse_privacy(s: &str) -> Result<Privacy, String> {
    s.parse()
}

/// `--timeout` value: a duration, or `none` for no deadline.
#[derive(Clone, Copy)]
struct Deadline(Option<Duration>);

fn parse_duration(s: &str) -> Result<Deadline, String> {
    if s == "none" {
        return Ok(Deadline(None));
    }
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("invalid duration `{s}`"))?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" | "" => n,
        "m" => n * 60.0,
        _ => return Err(format!("invalid duration unit in `{s}` (use ms, s or m)")),
    };
    Duration::try_from_secs_f64(secs).map(|d| Deadline(Some(d))).map_err(|e| e.to_string())
}

fn parse_size(s: &str) -> Result<u64, String> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("invalid size `{s}`"))?;
    let mult: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => return Err(format!("invalid size unit in `{s}` (use KiB, MiB or GiB)")),
    };
    n.checked_mul(mult).ok_or_else(|| format!("size `{s}` too large"))
}

fn parse_hashes(s: &str) -> Result<Hashes, String> {
    let mut h = Hashes::NONE;
    for part in s.split(',') {
        match part.trim() {
            "none" => {}
            "sha256" => h.sha256 = true,
            "blake3" => h.blake3 = true,
            other => return Err(format!("unknown hash `{other}` (use sha256, blake3 or none)")),
        }
    }
    Ok(h)
}

enum Input {
    Stdin,
    Path(PathBuf),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Formats { json }) => formats(json),
        Some(Command::Schema) => {
            let schema = schemars::schema_for!(Report);
            println!("{}", serde_json::to_string_pretty(&schema).expect("schema serialises"));
            ExitCode::SUCCESS
        }
        None => run(&cli.run),
    }
}

fn formats(json: bool) -> ExitCode {
    let registry = Registry::builtin();
    let rows: Vec<serde_json::Value> = registry
        .formats()
        .map(|(f, e)| {
            serde_json::json!({
                "id": f.id, "name": f.name, "family": f.family, "mimes": f.mimes,
                "extensions": f.extensions, "extractor": e.meta().id,
            })
        })
        .collect();
    if json {
        println!("{}", serde_json::Value::Array(rows));
    } else if rows.is_empty() {
        println!(
            "No format extractors in this build (whiff {}, features: {}).",
            env!("CARGO_PKG_VERSION"),
            whiff::enabled_features().join(", ")
        );
        println!("Every file still gets identification, system, temporal, security, physical and integrity sections.");
    } else {
        for (f, e) in registry.formats() {
            let exts =
                if f.extensions.is_empty() { "(by name or content)".to_string() } else { f.extensions.join(" ") };
            println!("{:<16} {:<32} {:<18} {exts}", f.id, f.name, e.meta().id);
        }
    }
    ExitCode::SUCCESS
}

fn build_engine(a: &RunArgs) -> Engine {
    let mut limits = a.profile.limits();
    if let Some(d) = a.max_depth {
        limits.max_depth = d;
    }
    if let Some(Deadline(t)) = a.timeout {
        limits.file_timeout = t;
    }
    if let Some(b) = a.max_bytes {
        limits.max_read_bytes = b;
    }
    let mut builder = Engine::builder()
        .profile(a.profile)
        .limits(limits)
        .only(a.only.clone())
        .skip(a.skip.clone())
        .provenance(a.provenance)
        .privacy(a.privacy);
    if let Some(h) = a.hash {
        builder = builder.hashes(h);
    }
    if let Some(f) = &a.format {
        builder = builder.format(f.clone());
    }
    builder.build()
}

fn collect_inputs(a: &RunArgs) -> (Vec<Input>, bool) {
    let mut inputs = Vec::new();
    let mut walked = false;
    for p in &a.paths {
        if p.as_os_str() == "-" {
            inputs.push(Input::Stdin);
        } else if p.is_dir() {
            walked = true;
            let walk = ignore::WalkBuilder::new(p)
                .hidden(!a.hidden)
                .git_ignore(!a.no_ignore)
                .git_global(!a.no_ignore)
                .git_exclude(!a.no_ignore)
                .ignore(!a.no_ignore)
                .parents(!a.no_ignore)
                .build();
            for entry in walk.filter_map(Result::ok) {
                if entry.file_type().is_some_and(|t| !t.is_dir()) {
                    inputs.push(Input::Path(entry.into_path()));
                }
            }
        } else {
            inputs.push(Input::Path(p.clone()));
        }
    }
    (inputs, walked)
}

/// Stack for worker threads. Parsers are bounded, but a generous stack keeps
/// deep (legitimate) documents well clear of the limit.
const WORKER_STACK: usize = 16 * 1024 * 1024;

fn run(a: &RunArgs) -> ExitCode {
    let mut pool = rayon::ThreadPoolBuilder::new().stack_size(WORKER_STACK);
    if let Some(n) = a.jobs {
        pool = pool.num_threads(n);
    }
    // Only fails if a global pool already exists, which cannot happen here.
    let _ = pool.build_global();
    let engine = build_engine(a);
    let (inputs, walked) = collect_inputs(a);
    let single = inputs.len() == 1 && !walked;
    let pretty = a.pretty || (single && !a.jsonl && std::io::stdout().is_terminal());

    let results: Vec<Result<Report, String>> = inputs
        .par_iter()
        .map(|input| match input {
            // Stdin has no name; detection works from the content alone.
            Input::Stdin => engine.extract_reader(None, std::io::stdin().lock()).map_err(|e| format!("-: {e}")),
            Input::Path(p) => engine.extract_path(p).map_err(|e| e.to_string()),
        })
        .collect();

    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut failed = false;
    for result in results {
        match result {
            Ok(report) => {
                let json = if a.profile == Profile::Llm {
                    let view = report.llm_view(a.max_tokens);
                    if pretty { serde_json::to_string_pretty(&view) } else { serde_json::to_string(&view) }
                } else if pretty {
                    serde_json::to_string_pretty(&report)
                } else {
                    serde_json::to_string(&report)
                };
                if writeln!(out, "{}", json.expect("reports serialise")).is_err() {
                    return ExitCode::FAILURE; // stdout closed (e.g. piped into `head`)
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("whiff: {e}");
            }
        }
    }
    let _ = out.flush();
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
