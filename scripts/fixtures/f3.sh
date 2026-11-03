#!/usr/bin/env bash
# Regenerate the F3 (Future-proof File Format) fixtures under
# tests/fixtures/f3/, and print the reference reader's view of them.
#
# F3 has no packaged writer: this clones the reference implementation
# (github.com/future-file-format/F3, MIT) at a fixed commit into target/,
# adds a small example program to its `fff-poc` crate, and builds and runs
# it with the repository's own toolchain in a podman Rust container. The
# program writes Saltmere Harbour tide readings (CC0-1.0), then reads each
# file back with `FileReaderV2` and prints the rows, row groups and column
# names as JSON lines (the oracle for scripts/fixtures/columnar_oracle.py).
#
#     scripts/fixtures/f3.sh            (F3_JOBS=1 if the build is still killed)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
commit=bd92506447dc1333820cfe9a34ebbf497fe0219e
src="$root/target/f3src/repo"
if [ ! -d "$src/.git" ]; then
    mkdir -p "$root/target/f3src"
    git clone -q https://github.com/future-file-format/F3 "$src"
fi
git -C "$src" fetch -q --depth 1 origin "$commit" 2>/dev/null || true
git -C "$src" -c advice.detachedHead=false checkout -q "$commit"

mkdir -p "$src/fff-poc/examples"
cat >"$src/fff-poc/examples/whiff_fixtures.rs" <<'EOF'
//! Writes whiff's F3 fixtures and prints what F3's reader sees in them.
use std::sync::Arc;

use arrow_array::{Float64Array, Int32Array, RecordBatch, StringArray, TimestampMillisecondArray};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use fff_poc::options::FileWriterOptions;
use fff_poc::reader::FileReaderV2Builder;
use fff_poc::writer::FileWriter;

fn readings(n: usize) -> RecordBatch {
    let schema = Schema::new(vec![
        Field::new("station", DataType::Utf8, false),
        Field::new("at", DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())), false),
        Field::new("height_m", DataType::Float64, true),
        Field::new("seq", DataType::Int32, false),
    ]);
    let stations = ["Saltmere Pier", "North Mole", "Lock Gate"];
    let t0 = 1_756_706_400_000i64;
    RecordBatch::try_new(
        Arc::new(schema),
        vec![
            Arc::new(StringArray::from_iter_values((0..n).map(|i| stations[i % 3]))),
            Arc::new(TimestampMillisecondArray::from_iter_values((0..n).map(|i| t0 + 600_000 * i as i64)).with_timezone("UTC")),
            Arc::new(Float64Array::from_iter_values((0..n).map(|i| 2.5 + 1.8 * ((i as f64) / 12.0).sin()))),
            Arc::new(Int32Array::from_iter_values(0..n as i32)),
        ],
    )
    .unwrap()
}

fn main() {
    let out = std::env::args().nth(1).expect("output folder");
    for (name, rows, group) in [("readings.f3", 120usize, u64::MAX), ("readings-groups.f3", 300, 100)] {
        let path = format!("{out}/{name}");
        let file = std::fs::File::create(&path).unwrap();
        let options = FileWriterOptions::builder().set_row_group_size(group).build();
        let batch = readings(rows);
        let mut w = FileWriter::try_new(batch.schema(), &file, options).unwrap();
        w.write_batch(&batch).unwrap();
        w.finish().unwrap();
        let mut r = FileReaderV2Builder::new(Arc::new(std::fs::File::open(&path).unwrap())).build().unwrap();
        let batches = r.read_file().unwrap();
        let read: usize = batches.iter().map(RecordBatch::num_rows).sum();
        let cols: Vec<String> = batches[0].schema().fields().iter().map(|f| format!("\"{}\"", f.name())).collect();
        println!("{{\"file\":\"{name}\",\"rows\":{read},\"columns\":[{}]}}", cols.join(","));
    }
}
EOF

mkdir -p "$root/tests/fixtures/f3"
# A debug build without debug info, two jobs at a time: F3's dependencies
# (Wasmtime, Arrow, Vortex) exhaust an 8 GiB podman VM when built in
# parallel with optimisation (rustc is killed). The build output stays in
# $src/target, so a rerun resumes.
podman run --rm -v "$src:/f3" -v "$root/tests/fixtures/f3:/out" -w /f3 \
    -e CARGO_BUILD_JOBS="${F3_JOBS:-2}" -e CARGO_PROFILE_DEV_DEBUG=0 \
    docker.io/library/rust:1.85-bookworm sh -euc '
apt-get update -qq >/dev/null && apt-get install -y -qq clang cmake protobuf-compiler >/dev/null
cargo run -q -p fff-poc --example whiff_fixtures -- /out
' | tee "$root/target/f3src/expected.jsonl"

# The reference writer's files replace the layout-built stand-in.
rm -f "$root/tests/fixtures/f3/layout-minimal.f3"
cat >"$root/tests/fixtures/f3/SOURCE.md" <<'EOF'
# Fixtures for `f3` (F3 (Future-proof File Format))

Files made for whiff's tests, CC0-1.0: Saltmere Harbour tide readings. Regenerate with `scripts/fixtures/f3.sh`.

| File | Origin | Licence |
|---|---|---|
| `readings.f3` | F3 reference writer (`fff-poc`, commit bd92506), one row group | CC0-1.0 |
| `readings-groups.f3` | F3 reference writer (`fff-poc`, commit bd92506), row groups of 100 rows | CC0-1.0 |
EOF
