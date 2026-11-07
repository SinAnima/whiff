//! Extraction time per format family over the test fixtures, in memory (no
//! file system), for the `minimal` and `standard` profiles.
//!
//!     cargo bench --features full --bench families            # every family
//!     cargo bench --features full --bench families -- image   # one family
//!
//! A family is the first part of the format family (`image.raster` →
//! `image`). Throughput is in files. For files per second per core over a
//! corpus on disk, use `whiff-dev throughput`.

// `criterion_group!` declares an undocumented public function.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use whiff::{Engine, Profile};

type Corpus = BTreeMap<&'static str, Vec<(String, Arc<[u8]>)>>;

/// Fixtures by family: each fixture folder is named after its format id.
fn corpus(engine: &Engine) -> Corpus {
    let family: BTreeMap<&str, &'static str> = engine
        .registry()
        .formats()
        .map(|(spec, _)| (spec.id, spec.family.split('.').next().unwrap_or(spec.family)))
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Corpus::new();
    let mut dirs: Vec<_> = std::fs::read_dir(&root).expect("tests/fixtures").flatten().map(|e| e.path()).collect();
    dirs.sort();
    for dir in dirs {
        let Some(fam) = dir.file_name().and_then(|n| n.to_str()).and_then(|id| family.get(id)) else { continue };
        let mut files: Vec<_> = std::fs::read_dir(&dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            if name == "SOURCE.md" || name.starts_with('.') || !f.is_file() {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&f) {
                out.entry(*fam).or_default().push((name, bytes.into()));
            }
        }
    }
    out
}

fn families(c: &mut Criterion) {
    let standard = Engine::new();
    let corpus = corpus(&standard);
    for (label, profile) in [("minimal", Profile::Minimal), ("standard", Profile::Standard)] {
        let engine = Engine::builder().profile(profile).build();
        let mut group = c.benchmark_group(label);
        for (family, files) in &corpus {
            group.throughput(Throughput::Elements(files.len() as u64));
            group.bench_function(*family, |b| {
                b.iter(|| {
                    for (name, bytes) in files {
                        black_box(engine.extract_bytes(Some(name), Arc::clone(bytes)));
                    }
                });
            });
        }
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(1));
    targets = families
}
criterion_main!(benches);
