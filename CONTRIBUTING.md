# Contributing to whiff

The most useful contribution is an **extractor** for a format listed in [`docs/metadata-extracted.md`](docs/metadata-extracted.md). Adding one touches no shared code apart from a `mod` line, which the tooling writes for you. [`docs/known-gaps.md`](docs/known-gaps.md) lists the gaps in formats that are already handled.

## Add a format

1. **Scaffold** (pick the family from `data/families.tsv`; it decides the cargo feature):

   ```sh
   cargo run --features dev --bin whiff-dev -- new-extractor image.qoi \
       --family image.raster --name "QOI image" --ext qoi --mime image/qoi --magic 716f6966
   ```

   This creates `src/formats/image/qoi.rs`, adds `pub(crate) mod qoi;` (and the group's feature-gated `mod` line if needed), and creates `tests/fixtures/qoi/SOURCE.md`. `--magic` takes hex, optionally with an offset: `4:66747970`. Use `--dry-run` to preview.

2. **Implement `extract`.** Binary formats: read with `src.head()` (first 64 KiB, pre-read), `src.read_vec(offset, len)?` or `src.reader()`, and parse with the bounds-checked `ByteReader`. Text formats: `cx.read_text(src)?` reads up to the profile's `max_parse_bytes` and decodes it (BOM, UTF-8, legacy encodings). Write only through the `Context`:
   * normalised fields: `cx.content().title(..)`, `cx.temporal().content_date(..)`, `cx.rights().copyright(..)`, `cx.security().risk(..)`, `cx.physical().image(w, h)`;
   * raw metadata in a standard's own names: `cx.metadata_set("id3", "TIT2", title)`;
   * technical details: `cx.format_set("quality_estimate", 92)`. Keys are `snake_case` with unit suffixes (`_bytes`, `_s`, `_px`, `_hz`);
   * embedded metadata goes to the shared decoders: `cx.emit_block(BlockKind::XMP, bytes)`. Don't parse EXIF/XMP/IPTC/ICC yourself;
   * text goes to the text analyzers: `cx.emit_text(TextRole::Body, text)` for prose, `TextRole::Code` / `TextRole::Data` for code and values (scanned for secrets, not treated as prose), `cx.emit_heading(level, text)` for headings (it also fills the outline). Don't count words, detect languages or extract keywords yourself; `wc` statistics are computed for every text file by the engine;
   * embedded files: `cx.emit_child(name, bytes)?`.

   Scalar fields are first-write-wins. Never panic, print or allocate based on unchecked lengths from the file.

   Helpers in `crate::plugin`: `parse_date` (RFC 3339, RFC 2822, log and civil formats), `identify_license` / `spdx_identifier` / `find_copyright`, `is_secret_key`, `redact_secrets` / `redact_sensitive` (for values that may hold credentials or personal data), `AnyValue` (any serde input as JSON, for YAML/TOML/JSON5), `squash_whitespace`, `truncate_chars`, `html_text` / `decode_entities` (lenient HTML to text, with headings), `latex_text`, `risky_file_name` (executables, double extensions, macro documents). Containers: `Zip` (ZIP / Zip64 entries, bounded reads), `Cfb` (OLE2 compound files) and `oleps` (property sets); `cx.inflate` / `cx.inflate_prefix` decompress within the zip-bomb budget. A container that finds another format inside (a compound file holding Word streams) calls `cx.redirect("doc")` and returns. People's addresses go through `cx.mailbox(name, address)`, which keeps only the domain under the default strict privacy mode (`cx.privacy_strict()`). Formats recognised by file name rather than content (`package.json`, `Dockerfile`) return a `Sniff` from `sniff` based on `probe.name`.

3. **Add 2–5 small sample files** to `tests/fixtures/<format>/` and list each in `SOURCE.md` with its origin and licence. Files must be ≤ 256 KiB and redistributable: self-made, CC0 or permissively licensed. Prefer files written by an independent implementation (a real application, or another library such as those `scripts/fixtures/documents.sh`, `scripts/fixtures/audio.sh`, `scripts/fixtures/video.sh`, `scripts/fixtures/subtitles.sh`, `scripts/fixtures/scores.sh`, `scripts/fixtures/archives.sh`, `scripts/fixtures/packages.sh`, `scripts/fixtures/disks.sh`, `scripts/fixtures/executables.sh`, `scripts/fixtures/bytecode.sh`, `scripts/fixtures/crypto.sh`, `scripts/fixtures/db.sh`, `scripts/fixtures/forensic.sh`, `scripts/fixtures/apple.sh`, `scripts/fixtures/binser.sh`, `scripts/fixtures/fonts.sh`, `scripts/fixtures/columnar.sh`, `scripts/fixtures/f3.sh`, `scripts/fixtures/science.sh`, `scripts/fixtures/geo.sh`, `scripts/fixtures/cad.sh` and `scripts/fixtures/games.sh` drive) over files assembled by hand: a parser tested only on files built to its own reading of the spec cannot catch where that reading is wrong.

4. **Test:**

   ```sh
   INSTA_UPDATE=always cargo test --features full
   ```

   An extractor handling several formats lists them all: `fixture_tests!("json", "ndjson")`. Risk kinds come from one vocabulary, `src/report/risk.rs`, which gives each its category and severity; add a new kind there (with its meaning) and regenerate `docs/risks.md` with `whiff-dev catalogue`. Tests fail on a kind that is missing. For behaviour no fixture shows (risk signals, damaged structures), unit-test small synthetic inputs with `crate::plugin::testing::report_for(name, bytes)`; keep them plainly benign (a neutral macro or script is enough to test detection). Review the new `tests/snapshots/<format>__*.snap` files: they are the extractor's output contract. The **conformance suite** (`tests/conformance.rs`) then checks your extractor automatically: detection, schema round-trip, determinism, `snake_case` keys, and that empty, truncated, bit-flipped, random and deeply nested inputs, plus a 4 KiB read budget, never cause a panic or hit a deadline.

5. **Regenerate the catalogue** so the "Extractor" column shows your work:

   ```sh
   cargo run --features dev --bin whiff-dev -- catalogue
   ```

6. Optional but appreciated: `cargo run --features dev --bin whiff-dev -- fuzz image.qoi` (needs nightly and `cargo install cargo-fuzz`).

## Rules

* **Pure Rust.** whiff as a library or tool is pure Rust: no crates that bind or build C/C++ code. `whiff-dev check-deps` fails on any `-sys` crate (other than the OS interfaces `windows-sys` and `linux-raw-sys`) and on native build tools such as `cc`, `cmake`, `bindgen` or `pkg-config` among the normal and build dependencies (the only exception is blake3's `cc`, unused with its `pure` feature). Development tooling is free to use anything (the fixture scripts use Python, Java, Ghostscript and others), as long as it lives outside the published crate: `scripts/ci.sh` checks that `cargo package` ships no `scripts/`, `fuzz/` or `tests/` files. Check the "Library" column of the catalogue, and prefer mature crates (a release in the last 18 months or clearly finished). Otherwise write a header parser with `ByteReader`.
* **Plugin boundary.** Format modules import only `crate::plugin::*` (checked by `whiff-dev check-boundary`).
* **Dependency budget.** CI counts transitive dependencies (`whiff-dev check-deps`). Exceeding a budget needs a justification in the PR.
* **Privacy.** Never output secret material (keys, passwords, cookie values). Count personal data such as e-mail addresses or patient fields; don't list it. Where a format is about people (e-mail, calendars, contacts), pass addresses through `cx.mailbox` and list phone numbers, street addresses and birthdays only when `cx.privacy_strict()` is false.
* **`unsafe` is forbidden** crate-wide.
* **Bounded work.** A stack overflow aborts the process (`catch_unwind` cannot contain it), so never recurse on input-controlled depth. Before a recursive third-party parser, check `nesting_depth(text) <= MAX_NESTING`. Avoid work that is quadratic in the input; call `cx.checkpoint()?` in long loops that do not read from the source. The conformance suite feeds every extractor deeply nested input and fails it if it overflows or hits a deadline; a watchdog abandons extractors that ignore deadlines, but that is a last resort, not a budget.

## Before opening a PR

```sh
cargo fmt
scripts/ci.sh
```

`scripts/ci.sh` runs the same checks as CI: fmt, clippy, tests, docs, a coverage gate of at least 80% of lines (needs `cargo install cargo-llvm-cov`), catalogue / risk-vocabulary / dependency-budget / pure-Rust / plugin-boundary checks, a check that the published crate holds no development tooling, and `cargo deny`. Checks whose tools are missing locally (`cargo-hack`, the MSRV toolchain, the wasm target, nightly fuzzing) are skipped with an install hint; CI still runs them.

## Extractors in other crates

A crate outside whiff can implement `whiff::plugin::Extractor` and add it explicitly:

```rust
let engine = whiff::Engine::builder()
    .registry(whiff::Registry::builtin().with(MyExtractor))
    .build();
```

## How built-in registration works

`build.rs` scans `src/formats/`, `src/meta/` and `src/engine/` for `register_extractor!(Name)`, `register_block_decoder!(Name)` and `register_analyzer!(Name)` lines. It generates the list behind `Registry::builtin()`, gated by each group's cargo feature. This is deterministic on every target, unlike linker-section registration.
