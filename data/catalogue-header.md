# whiff: metadata extracted per file format

This is the reference for **what whiff extracts from each file format, why it is useful to an LLM, and which pure-Rust library (or in-house parser) produces it**. Stages (S0–S8) refer to the implementation plan. whiff is a single crate. The **Feature** column gives the cargo feature that compiles each format's extractor: `common` (default) or one of the opt-in specialist features `geo`, `science`, `data`, `cad`, `forensics`, `games` (`full` = all).

*Researched 2026-10-15. Crate versions were checked against the crates.io API on that date.*

*Library names dated 2026-10-15 are the survey. The parser is in-house unless `Cargo.toml` lists the crate; the Library columns below name only crates whiff depends on.*

## 1. How this list was built

* **No authoritative "top 1000 file formats" ranking exists.** This list was curated from common usage and cross-checked against the freedesktop `shared-mime-info` database, the IANA media-type registry, The National Archives PRONOM registry, and Wikipedia's list of file formats. Formats are sorted into three popularity **tiers**, not given an exact rank.
* Some rows cover a *format family that shares one parser* (for example "Canon CR2 / CR3 / CRW"). One row = one thing a contributor would implement and test as a unit.
* Rows with the same family share an extractor. The per-format column lists only what that format adds on top of its family.
* **Pure Rust is a hard constraint.** Crates that wrap C libraries are listed only as rejected alternatives: `rusqlite` (bundled SQLite), `unrar`, `xmp_toolkit`, `netcdf`, `hdf5-metno`, `libheif-rs`, `tree-sitter`, `ffmpeg-next`, `lcms2`, `minimp3`, `opus` and `sequoia-openpgp` (Nettle backend). Where the only option was C, the format is marked **impl**: whiff writes the parser, usually header-only, which covers the metadata.

### Library verification against the reviewed article

The article [*Rust libraries for file formats* (2026-10-13)](https://thanos.github.io/articles/2026-10-13-rust-libraries-for-file-formats/) was the starting point. Each crate it names was looked up on crates.io:

| Article claim | Finding on crates.io (2026-10-15) | Decision |
|---|---|---|
| `file-format` is the main detection crate | 0.29.0, ~2M downloads, actively maintained | **Use** as the primary magic database |
| `filetype` uses PRONOM signatures | `filetype` 0.2.0 dates from 2015 and is an unrelated `std::fs::File` extension | Reject. `infer` (132M downloads) and `mimetype-detector` (~500 types) are the real alternatives |
| `xberg` does lightweight magic inference | Actually a document-intelligence (text extraction) library | Not used for detection |
| `oxiarc` handles ZIP, TAR, GZIP, XZ, CAB and LZH | No crate named `oxiarc`; published as `oxiarc-core` and `oxiarc-archive` 0.4.2 (low adoption) | Prefer `zip`, `tar`, `cab` and `delharc`; evaluate `oxiarc-archive` |
| `spoor` reads ELF, PE, Mach-O and WASM metadata plus DWARF | `spoor` 0.1.0 (12 downloads) only recovers the crate manifest from Rust binaries | Use `goblin` / `object` + `gimli`. `spoor` is an optional extra for Rust binaries |
| `turbo-parsepdf-core` speedups | 0.1.1, about 40 downloads | Not used. whiff reads PDF with an in-house parser |
| `doc_loader` gives unified extraction | 0.3.2, about 2k downloads | Not used. Per-format crates instead |
| `oxigdal` / `oxigeo` as a pure-Rust GDAL | 0.1.7 / 0.2.4, about 1k downloads each | Evaluate later (S7). Use mature single-format crates first |
| `bitframe` for bit-level headers | 0.1.1, 32 downloads | Not used. `binrw` + `zerocopy` instead |
| `symphonia` as the pure-Rust audio demuxer/decoder | 0.6.1, 17M downloads | **Use** for codec parameters and duration. Tags come from `lofty` |
| `image` + `png`, `zune-jpeg`, `image-webp`, `tiff`, `exr` | All mature | **Use** (decode is opt-in; probing uses `imagesize` + `img-parts`) |
| HEIC, AVIF and JPEG XL need FFI | `jxl-oxide`, `avif-parse` and `heic` 0.1.6 are pure Rust | Metadata comes from ISOBMFF boxes (`mp4-atom`), so no FFI is needed |
| `rusqlite` for embedded databases | Bundles C SQLite | Reject. Implement a read-only SQLite b-tree reader for the schema |
| `arrow`, `parquet`, `lance`, `vortex-ipc` | All current | `parquet` / `arrow` footer-only by default. `lance` and `vortex` are feature-gated (heavy) |
| `monstertruck-io` for STEP/IGES | 0.4.1, about 600 downloads, full B-rep | Feature-gated. The default is an in-house ISO-10303-21 header lexer |

Crates the article missed that the survey considered (most were later replaced by in-house parsers; `Cargo.toml` has the current list): `lofty` (audio tags), `kamadak-exif`, `nom-exif`, `img-parts`, `imagesize`, `mail-parser`, `read-fonts` / `skrifa`, `x509-parser`, `pgp`, `goblin`, `object`, `gimli`, `mp4-atom`, `matroska`, `mpeg2ts-reader`, `hdf5-reader` (pure-Rust HDF5), `netcdf3`, `fitsrs`, `dicom-object`, `lava_torrent`, `tokei`, `whatlang`, `yake-rust`, `chardetng`, `feed-rs`, `ssh-key`, `midly`, `fitparser` and `serde-saphyr`.

## 2. Universal information (every file, every format)

These sections are filled for **every** file before format-specific extraction runs. They map directly onto the categories you asked for.

| Section | Fields | Source |
|---|---|---|
| **System identification** | path (as given + canonical), file name, stem, extension, detected format id + name + MIME + confidence + detector, extension/content mismatch flag, device id, inode, hard-link count, file kind (regular/dir/symlink/fifo/socket/device), symlink target, hidden flag, hostname (opt-in) | `std::fs::Metadata`, `std::os::unix::fs::MetadataExt`, `file-format` + `infer` + in-house sniffers |
| **Temporal data** | filesystem: modified, accessed, changed (ctime), created (birth time where available); content: every date the extractors found (EXIF DateTimeOriginal, PDF CreationDate, docProps created/modified, ID3 TDRC, archive entry mtime range...), normalised to RFC 3339 with `source` provenance and `tz_known` | `std::fs`, `jiff` for parsing and normalisation |
| **Security & rights** | Unix mode (octal + rwx string), owner uid/gid + names, setuid/setgid/sticky, extended attributes (names; values for `com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`, `user.xdg.origin.url`), Windows Zone.Identifier ADS (when present); content: encrypted?, signed?, signature validity (where checkable offline), macros/scripts/active content present, external references, DRM present, copyright / licence / usage terms gathered from EXIF, IPTC, XMP (`xmpRights`, `cc`), ID3 TCOP, font fsType, package licences | `rustix`, `uzers`, `xattr` + per-format extractors |
| **Physical properties** | size in bytes, allocated blocks, sparse?; for text: `wc` (bytes, chars, words, lines, max line length), line endings, encoding, BOM; for binaries: Shannon entropy + per-block profile; dimensions / duration / page count / entry count / row count as applicable | streaming counters, `unicode-segmentation` |
| **Integrity** | SHA-256 and BLAKE3 (configurable, streaming) and Shannon entropy. `integrity.phash` (a perceptual hash) and `security.acl` are reserved in the schema; this version fills neither | `sha2`, `blake3` |
| **Content (LLM view)** | title, authors, description, language (+ confidence), keywords (YAKE), keyword frequency (top N stemmed terms), headings outline, extractive summary (TextRank, N sentences), text excerpt (token-budgeted), tags (merged from metadata keywords + extracted keywords) | `whatlang`, `yake-rust`, `stop-words`, `rust-stemmers`; TextRank implemented in-house |
| **Embedded / children** | for containers (archives, emails, Office files, PDFs with attachments): each child gets its own (bounded, recursive) whiff record | engine recursion with depth, size and count limits |
| **Diagnostics** | extractors run + versions + timings, warnings, partial/truncated flags, limits hit | engine |

**Privacy and redaction.** Two switches, both on by default. Key material (private-key bytes) is never copied into a report.

| | `--redaction on` (default) | `--redaction off` |
|---|---|---|
| **`--privacy strict`** (default) | personal data counted and masked; secrets redacted | personal data counted and masked; secrets as found |
| **`--privacy off`** | personal data as found; secrets redacted | everything as found |

* *Personal data* (e-mail addresses, phone numbers, account numbers, birthdays, infrastructure values such as host names and IP addresses, DICOM patient fields, browser history URLs) is always counted in `security.personal_data`. Under strict privacy, e-mail addresses keep only their domain, the other values are counted or hidden, and personal data is replaced with `[redacted:<kind>]` in the excerpt, summary, keywords and tags. People's names (authors, senders, contacts) are kept. `--privacy off` lists all of it as found, derived text included.
* *Secrets* (API keys and tokens, passwords, credentials in URLs, private-key blocks, `.env` values, values under keys named like secrets) are always counted in `security.secrets` and raise the `embedded_secret` risk. With `--redaction on` they are replaced with `[redacted:<kind>]` everywhere in the report; `--redaction off` leaves them as found.
