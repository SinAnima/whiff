# Stability

From 1.0, whiff follows [Semantic Versioning](https://semver.org/). This page says what a
version number promises, for each way you can depend on whiff: the command line, the JSON
report, the Rust library and the toolchain.

- A **patch release** (1.2.3 → 1.2.4) fixes bugs. It adds and removes nothing.
- A **minor release** (1.2 → 1.3) may add things: formats, fields, flags, API items. It may
  also raise the minimum Rust version.
- A **major release** (1.x → 2.0) is needed to remove or change anything promised below.

Before 1.0, a minor release (0.9 → 0.10) may break things, and the CHANGELOG lists each
breaking change under **Breaking**.

## Command line

**Stable in 1.x:**

- **Commands and flags.** `whiff <PATH>...`, `whiff formats [--json]`, `whiff schema`, every
  flag in `whiff --help`, and the syntax of their values: profile names, `--hash` lists,
  durations such as `30s`, sizes such as `256MiB`, and `-` for stdin. A flag may be
  deprecated but stays accepted until 2.0.
- **Privacy defaults.** `--privacy strict` and `--redaction on` stay the defaults, and what
  they hide is never reduced: a minor release may hide more, never less.
- **Output.** One JSON report per input on stdout:
  - **JSON Lines** (one compact report per line) for several inputs, for a directory, or
    with `--jsonl`;
  - **indented** for one file on a terminal, or with `--pretty`.

  Reports are written in input order.
- **Exit codes:**

  | Code | Meaning |
  |---|---|
  | 0 | Every input produced a report |
  | 1 | At least one input could not be read (the reason is on stderr; the other inputs still got reports), or stdout was closed |
  | 2 | Invalid command line |

  A file whiff cannot identify, or one that fails to parse, is not an error: it still gets
  a report, with what was found under `diagnostics`.
- **`whiff formats --json`.** An array of objects with the keys `id`, `name`, `family`,
  `mimes`, `extensions` and `extractor`.

**Not stable (may change in any minor release):**

- the default limits of each profile: time per file, bytes read, recursion depth;
- the default number of worker threads;
- the text of stderr messages, of `whiff formats` without `--json`, and of `--help`;
- the content of the LLM view (`--profile llm`), which is tuned for language models, not
  for parsing;
- how fast whiff is, and how much memory it uses.

## The report

The report's schema identifier is in its `whiff.schema` field (`whiff/1`). The current
schema is [`schema/whiff-1.schema.json`](schema/whiff-1.schema.json).

**Stable within `whiff/1`.** The report only grows: fields, enum values and sections may be
added. Nothing the 1.0 schema
([`schema/whiff-1-baseline.schema.json`](schema/whiff-1-baseline.schema.json)) promises is
removed, renamed or given another type. That would be `whiff/2`, in a major release. A test
checks every release against the baseline.

**Format ids and risk kinds.** These are stable, and only ever added:

- **Format ids** (`identification.format`, the ids in `whiff formats`). An id is never
  removed or renamed in 1.x. When detection improves, a file may get a more specific id
  that the old one is the parent of, for example `geoparquet` instead of `parquet`.
- **Risk kinds** (`security.risks[].kind`, listed in [risks.md](risks.md)). A kind is never
  removed or renamed in 1.x. Its category and severity may be adjusted in a minor release.

**Not covered:**

- **Format and metadata keys.** The keys under `format.<id>` and `metadata.<standard>` are
  each extractor's own. They may change in a minor release, and each extractor's `version`
  in `diagnostics.extractors` changes when they do.
- **Detection, extraction and text analysis.** These are heuristics, and a release that
  detects a file better, reads more of it or summarises it differently is not breaking.
- **Output details.** The order of keys in the JSON, and the exact text of warnings, are
  not promised.

## Rust library

**Stable public API:**

- the crate root: `Engine`, `EngineBuilder`, `Options`, `Limits`, `Hashes`, `Privacy`,
  `Redaction`, `Profile`, `Registry`, the risk vocabulary and `enabled_features`;
- `whiff::report`: the report types;
- `whiff::plugin`: writing and registering extractors, block decoders and analyzers;
- `whiff::io`: sources and byte readers.

CI checks every change against the latest release with
[cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks).

**How to use it so upgrades don't break your code:**

- Report and option structs, and the enums that can grow, are `#[non_exhaustive]`, so new
  fields and variants come in minor releases. Read their fields, set options through
  `Engine::builder()` or by changing the fields of `Options::default()`, and match enums
  with a wildcard arm.
- Deprecated items stay until 2.0.

**Not covered:**

- items marked `#[doc(hidden)]`, including `whiff::plugin::testing`, which is for whiff's
  own tests;
- anything that is not public;
- which extractors and formats a build has. That depends on its features (see the README).

**Cargo features.** The feature names (`common`, `cli`, `full`, `geo`, `science`, `data`,
`cad`, `forensics`, `games`) are stable. A minor release may add formats to a feature or
move formats into `common`. `dev` is for whiff's own tools and is not covered.

## Minimum supported Rust version

The MSRV is **1.89**. It is in `Cargo.toml` (`rust-version`), and CI builds with it.

From 1.0:

- The MSRV is raised only in a minor release, never in a patch release.
- It is raised to at most the stable Rust two minor versions behind the newest. When Rust
  1.N is the newest stable, whiff may require at most 1.(N-2), which is about three months
  old.
- The CHANGELOG says when it changes.

Raising the MSRV is not treated as a breaking change.
