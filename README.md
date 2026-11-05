# whiff

**whiff** (verb): to catch the scent of something. Point `whiff` at any file and it returns one JSON document describing it: what it is, where it came from, who owns it, when it was made, what rights apply, its physical properties, and a compact, LLM-ready view of its content. Pure Rust, safe on untrusted input.

> **Status: 0.7.0 (Stage 7: fonts, columnar data and models, scientific and medical files, geodata, 3D and CAD).** Every file gets the universal sections (identification, system, temporal, security, physical, integrity), plus `wc` statistics for text, owner names, extended attributes (macOS quarantine and "Where from", Finder tags, Windows `Zone.Identifier`), and a language, keywords, keyword frequency, excerpt and (in `full` / `llm`) a summary for any prose. Extractors cover plain text, logs, diffs, Markdown, HTML, XML, feeds, JSON / NDJSON / JSON5, YAML, TOML, INI / properties / dotenv, CSV / TSV, SQL, ~40 programming languages, package manifests, Jupyter notebooks, Dockerfiles and Makefiles, 41 image formats: JPEG, PNG, GIF, WebP, TIFF, HEIC / AVIF, JPEG XL, JPEG 2000, PSD, SVG, camera raw (DNG, CR2, CR3, NEF, ARW, ORF, RW2, PEF, RAF, SRW) and more, with EXIF, XMP, IPTC, ICC and Photoshop metadata reconciled the way the Metadata Working Group specifies, and documents: PDF, Word / Excel / PowerPoint / Visio (current and 97–2003), OpenDocument, RTF, EPUB, Kindle, FictionBook, comics, PostScript, BibTeX, e-mail (EML, mbox, MHTML, Outlook MSG), iCalendar and vCard, with macros, scripts, risky links and phishing signals flagged, and 23 audio formats: MP3, AAC / M4A / M4B, FLAC, Ogg Vorbis, Opus, Speex, WAV / Broadcast Wave / RF64 / Wave64, AIFF, CAF, WMA, WavPack, Monkey's Audio, Musepack, DSD, AMR and more, with ID3, Vorbis, APE, iTunes and ASF tags normalised, cover art, chapters and BWF / iXML production data, and video: MP4 / MOV / 3GP (fragmented too), Matroska / WebM, AVI, MPEG transport and program streams (TS, M2TS, MPG, VOB), FLV, WMV, RealMedia, Ogg Theora and H.264 / HEVC / AV1 / VP9 / MPEG-2 / YUV4MPEG2 elementary streams, with every stream's codec, profile, level, size, aspect ratio, frame rate, bit depth, colour and HDR format, rotation, chapters, tags, camera make, model and location, and the text of subtitle tracks, and subtitles: SRT, WebVTT, ASS / SSA, TTML, SAMI, SCC, EBU STL, PGS, VobSub, LRC and more, with cues, languages, speakers and the transcript, and playlists: M3U, HLS, DASH, Smooth Streaming, PLS, XSPF, ASX, WPL and CUE sheets, and scores: MIDI (with the tempo-map duration), tracker modules, MusicXML, MEI, MuseScore, Guitar Pro, ABC and LilyPond, and archives: ZIP, tar, 7z, RAR, CAB, LHA, ARJ, cpio and ar, with an inventory of their entries, encryption, and risk flags for zip bombs and paths that leave the target folder, and compressed files: gzip, bzip2, xz, lzip, Zstandard, LZ4, Brotli, `.Z` and Snappy, analysing the file inside (a `.tar.gz` lists the tar's entries), and packages: Debian, RPM, Arch, Alpine, Slackware and FreeBSD packages, Android APK / AAB, iOS IPA, npm, crates, wheels and sdists, gems, JAR / WAR / EAR, NuGet, conda, Windows Installer, MSIX, macOS `.pkg` and `.dmg`, Helm charts, container images, browser and VS Code extensions and Electron `asar`, Snap, AppImage and Flatpak, with name, version, licence, maintainer, dependencies, permissions, signatures and install-time scripts, and the payload listed, and (feature `forensics`) disk images: raw disks, file-system images, ISO 9660 / UDF, VDI, VMDK, VHD / VHDX, QCOW2, QED, E01 / AFF evidence files, Android sparse and boot images, firmware (uImage, FIT, Intel HEX, S-record, UEFI capsules), OVA / OVF and floppies, with the partition table, each file system's label, UUID, size and times, and the files of FAT, ext, ISO, UDF and squashfs volumes listed, and executables: ELF, PE / .NET / COFF / MS-DOS, Mach-O (universal binaries too) and WebAssembly, with architecture, sections and their entropy, linked libraries, imports and exports, hardening flags, the Authenticode or Apple code signature, PE version information and the toolchain that built them (compilers, Go build information, Rust, installers, packers), and bytecode: Java class files, Android DEX, Python `.pyc`, .NET metadata (assembly identity, references, P/Invoke imports, target framework), Lua / LuaJIT, Erlang BEAM, Emacs Lisp, mruby, Ruby YARV and OCaml, with the runtime version targeted, what the file defines and what it imports, and crypto: X.509 certificates and PEM bundles, requests, CRLs, PKCS#7 / CMS, Windows catalogs, PKCS#12, keys, SSH keys, certificates, `authorized_keys` and `known_hosts`, PuTTY keys, OpenPGP keys, messages and signatures, GnuPG keyboxes, Java key stores, Kerberos keytabs, KeePass databases, JWT / JWK, age, minisign and signify, with who a certificate or key names, its algorithm, size, validity and fingerprint, and how a private key is protected (never the key itself), and databases: SQLite (schema, columns, row counts and the application behind it: GeoPackage, MBTiles, browser histories, Core Data, Lightroom, Anki and more), DBF, Access, DuckDB, LMDB, Berkeley DB, LevelDB / RocksDB, Redis, `pg_dump` archives, MySQL / MariaDB table files and H2, and (feature `forensics`) forensic artefacts: packet captures, Windows event logs, registry hives, shortcuts, jump lists, Prefetch, minidumps and memory images, `$MFT`, login records, systemd journals, IDS alerts and rules, HAR archives, crash reports and Zeek logs, summarised as counts, time ranges and identifying facts, and Apple formats: property lists (Info.plist, launchd jobs, keyed archives, configuration and provisioning profiles, Shortcuts, iOS backups), `.strings` and string catalogs, `.DS_Store`, aliases and bookmarks, AppleDouble files, asset catalogs and Xcode projects, and binary serialisations: MessagePack, CBOR, BSON, UBJSON, Smile, Ion, bencode and torrents, PHP serialize, NBT, Avro, protobuf, FlatBuffers schemas, ASN.1, Android binary XML, Python pickles and Java serialization streams (walked, never loaded, with code-running globals and gadget classes flagged), and RON, KDL, HOCON, EDN and S-expressions, with an inferred schema for each, and fonts: TrueType, OpenType, collections, WOFF / WOFF2, EOT, Mac dfont, PostScript Type 1 with AFM / PFM metrics, BDF, PCF, Windows FNT / FON, PC Screen Font and FontForge / Glyphs / UFO sources, with names, version, designer, copyright and licence, the embedding permission, weight and width, variable axes and instances, Unicode coverage by script, colour formats and OpenType features, and (feature `data`) columnar data and models: Parquet and GeoParquet, Arrow IPC and Feather, ORC, Lance, Vortex, F3, Delta Lake and Iceberg metadata, TFRecord, R fst and qs, pandas pickles, safetensors, GGUF, ONNX, PyTorch, Keras, TensorFlow Lite, SavedModel and Core ML, with schemas, row counts and column statistics, and model architecture, operators, inputs and outputs and parameter counts (never the data or the weights), and (feature `science`) scientific and medical files: HDF5 and the layouts built on it (NetCDF-4, AnnData, Loom, MATLAB 7.3, NeXus), NetCDF, FITS, ASDF, Zarr, GRIB, ROOT, NumPy, MATLAB, SPSS, Stata, SAS and R data, genomics (FASTA, FASTQ, SAM / BAM / CRAM, VCF / BCF, BED, GFF), chemistry (PDB, mmCIF, MOL / SDF), instrument data (mzML, EDF, TDMS, VCD), electronics design files, DICOM, NIfTI, NRRD, HL7 and FHIR, with dimensions, variables, datasets and their shapes, types and attributes, and observation, study and series facts (patient-identifying values withheld), and (feature `geo`) geodata: GeoJSON, TopoJSON, KML / KMZ, GPX, GML, shapefiles, File Geodatabase tables, FlatGeobuf, MapInfo, OpenStreetMap, S-57 charts, WKT / WKB, GeoPackage, MBTiles, GeoTIFF / COG, DTED, ASCII grids, LAS / LAZ / COPC, E57, PMTiles, vector and 3D tiles, FIT, TCX, IGC and NMEA tracks, map styles and QGIS projects, with bounds, CRS and the extent in WGS84 (`content.extent`), and (feature `cad`) 3D and CAD: glTF / GLB, VRM, OBJ, STL, PLY, OFF, AMF, 3MF, COLLADA, X3D, VRML, Draco, FBX, Blender, USD, 3DS, MagicaVoxel, OpenVDB, LDraw, BVH and C3D motion capture, IES and EULUMDAT photometry, 3D-printing and CNC G-code, DXF, DGN, STEP, IFC, IGES, Gerber, Excellon, KiCad, GDSII, OASIS and OpenSCAD, with vertices, triangles, objects, materials and bounds, authoring applications, units, layers and entities, and (unreleased, feature `games`) games: NES, Super NES, Game Boy, Game Boy Advance, Nintendo 64 and Mega Drive ROMs, Switch and 3DS packages, chiptunes (NSF, SPC, VGM, SID, GBS), WAD, PAK, BSP, VPK, Bethesda, RPG Maker and Ren'Py archives, Godot and Unreal packs, Unity bundles and serialized files, Unreal packages, GameMaker and Godot projects, Paradox mods, Minecraft regions, schematics and worlds, Tiled maps, Aseprite sprites, Steam manifests, interactive fiction (Twee, Ink, Z-code, Glulx, Blorb) and emulator saves, with titles, header codes and verified checksums, engine versions, entries and maps, and (unreleased) the first of the long tail: lightweight markup (reStructuredText, AsciiDoc, Org, Textile, MediaWiki, POD, man pages, Texinfo, Creole, DokuWiki, Djot, Gemtext) with title, authors, outline, links and code blocks, Terraform, crontabs, SSH, nginx, Apache, Caddy and HAProxy configurations, ignore files, Procfiles, Justfiles and Vagrantfiles, NFO and ANSI art (code page 437 and SAUCE), hosts files, `CODEOWNERS`, Vim swap files, Kindle clippings and GNU info, `robots.txt` (with the AI crawlers it blocks), `security.txt`, proxy auto-config, Metalink, filter lists, cookie jars and bookmarks (counted, not listed), `.netrc` and curl / wget configurations (passwords flagged, never copied), WARC, Shockwave Flash, MATLAB scripts and (feature `cad`) AutoCAD DWG headers. Other formats are still identified by signature, and [`docs/known-gaps.md`](https://github.com/baoulo/whiff/blob/main/docs/known-gaps.md) lists what was deliberately left out of the formats already handled. [`docs/metadata-extracted.md`](https://github.com/baoulo/whiff/blob/main/docs/metadata-extracted.md) lists the 1008 formats planned, what is extracted from each, and which extractor handles it today.

## Install

```sh
brew install baoulo/tap/whiff                                    # macOS, Linux
scoop bucket add baoulo https://github.com/baoulo/scoop-bucket   # Windows
scoop install whiff
asdf plugin add whiff https://github.com/baoulo/asdf-whiff.git && asdf install whiff latest
mise use -g github:baoulo/whiff
curl -fsSL https://raw.githubusercontent.com/baoulo/whiff/main/scripts/install.sh | bash
cargo install whiff                                              # from source (Rust 1.89+)
```

Release binaries (Linux static, macOS, Windows) include every format collection; `cargo install whiff --features full` does the same from source. In GitHub Actions: `uses: baoulo/whiff/.github/actions/setup-whiff@main`.

## Use

```sh
whiff notes.md                        # one report (pretty-printed on a terminal)
whiff ~/projects/app                  # walks a directory (honours .gitignore); one JSON report per line
curl -s https://example.org/ | whiff -    # stdin: detection works from the content alone
whiff --profile llm README.md         # compact, token-budgeted view for language models
whiff --profile minimal --hash none disk.iso   # fast: stat and detection only, no hashing
whiff --only code.manifest package.json        # run only some extractors
whiff formats                         # formats this build extracts
whiff schema                          # JSON Schema of the report (whiff/1)
```

`whiff --profile llm guide.md` on a Markdown file with YAML front matter prints (abridged):

```json
{
  "format": "Markdown (markdown)",
  "title": "A Guide to the Old Harbour",
  "description": "Walks, boats and food around the old harbour.",
  "authors": ["Ada Example", "Ben Sample"],
  "language": "en",
  "dates": ["published: 2026-09-14", "modified: 2026-10-01T09:30:00+02:00"],
  "physical": { "lines": 48, "words": 158 },
  "rights": { "license": "CC-BY-4.0", "creators": ["Ada Example", "Ben Sample"] },
  "keywords": ["harbour", "boats", "quay", "harbour cafe", "fishing boats", "lighthouse"],
  "summary": "The old harbour is where the fishing boats come home. This guide covers the walk along the quay, the boats you will see and where to eat. Fish soup at the harbour cafe is the local favourite.",
  "outline": ["The Old Harbour", "  Walking the quay", "    Things to bring", "  Boats", "  Food"],
  "details": { "links": { "internal": 1, "external": 1 }, "code_languages": { "python": 1 }, "tasks": { "total": 3, "done": 1 } }
}
```

Images get their embedded metadata decoded (`metadata.exif`, `.xmp`, `.iptc`, `.icc`, `.photoshop`) and reconciled into the normalised fields. `whiff --profile llm harbour.jpg` prints (abridged):

```json
{
  "format": "JPEG image (jpeg)",
  "title": "Old harbour",
  "description": "Fishing boats in the old harbour at dusk",
  "authors": ["Mira Castell"],
  "dates": ["captured: 2024-05-01T19:42:10+02:00", "digitized: 2024-05-01T19:42:10"],
  "physical": { "pixels": "96x64" },
  "rights": { "copyright": "(c) 2024 Mira Castell, CC BY 4.0", "license": "https://creativecommons.org/licenses/by/4.0/", "creators": ["Mira Castell"] },
  "keywords": ["harbour", "boats", "dusk"],
  "details": { "process": "baseline", "chroma_subsampling": "4:2:0", "quality_estimate": 85 }
}
```

The full report adds the GPS location (`content.location`), camera settings, the ICC profile and the raw blocks. AI-generated images are flagged in `security.risks` (Stable Diffusion, ComfyUI and InvokeAI parameters in PNGs, the IPTC digital source type); SVGs with scripts or external references are flagged too.

Documents report their properties, outline and text; PDFs, Office files, RTF and e-mail also report active content (macros, JavaScript, DDE, external templates, launch actions) and phishing signals in `security.risks`, and their attachments and embedded files appear under `embedded`. Each risk carries a `category` (`active_content`, `phishing`, `external_reference`, `exploit`, …) and a `severity` (`info` to `high`); `security.risk_level` is the highest severity in the file or anything embedded in it, and `security.embedded_risks` counts the embedded files' risks. [`docs/risks.md`](https://github.com/baoulo/whiff/blob/main/docs/risks.md) lists every kind. Addresses are reduced to their domain unless you pass `--privacy off`.

Executables report their architecture, linked libraries, imports, hardening and toolchain. `whiff --profile llm tides-gcc-hardened` on a small Linux binary prints (abridged):

```json
{
  "format": "ELF executable / shared object (elf)",
  "details": {
    "bits": 64, "architecture": "arm64", "kind": "executable", "interpreter": "/lib/ld-linux-aarch64.so.1",
    "section_count": 25, "libraries": ["libc.so.6", "ld-linux-aarch64.so.1"],
    "imports": ["__libc_start_main", "__snprintf_chk", "__stack_chk_fail", "puts", "strcmp"],
    "os": "linux", "minimum_kernel": "3.7.0",
    "hardening": { "nx": true, "pie": true, "relro": "full", "stripped": true, "stack_canary": true, "fortify": true },
    "toolchain": { "compilers": ["GCC: (Debian 14.2.0-19) 14.2.0"] }
  }
}
```

PE files add their version information and Authenticode signer, Mach-O files their code signature and entitlements, and packed binaries and writable executable memory are flagged. Bytecode, serialised data and databases are read without running or loading anything: a Python pickle or Java serialization stream is walked opcode by opcode, and globals that run code or known gadget classes report `unsafe_deserialization`; a SQLite file gives its schema, row counts and the application behind it without a database engine. Certificates and keys report who they name, their algorithm, size, validity and fingerprint, and how a private key is protected, never the key itself. Apple property lists, profiles and Xcode projects report what they configure (bundle identifiers, entitlements, installed root certificates, scripts), and the self-describing binary formats (MessagePack, CBOR, BSON, Avro, protobuf …) get the same inferred schema as JSON. With the `forensics` feature, packet captures, event logs, registry hives and other artefacts are summarised as counts, time ranges and identifying facts; user names in paths and device identifiers are hidden unless you pass `--privacy off`.

Columnar data, scientific files, geodata and 3D models are read from their headers, footers and indexes through the source, never loaded whole, and the data itself is never decoded. The release binaries are built with every feature; as a library, enable `data`, `science`, `geo` or `cad` (or `full`). `whiff --profile llm readings-snappy.parquet` prints (abridged):

```json
{
  "format": "Apache Parquet (parquet)",
  "details": {
    "created_by": "parquet-cpp-arrow version 26.0.0", "rows": 120, "row_groups": 3,
    "columns": { "station": "string", "at": "timestamp[ms, UTC]", "height_m": "double", "flags": "list<int32>", "gauge": "struct<id: string, ok: boolean>" },
    "codecs": ["snappy"],
    "statistics": {
      "at": { "min": "2025-09-01T06:00:00Z", "max": "2025-09-02T01:50:00Z", "nulls": 0 },
      "height_m": { "min": 0.699, "max": 4.343, "nulls": 0 }
    },
    "metadata": { "harbour": "Saltmere Harbour", "source": "tide gauges" }
  }
}
```

Models report their architecture, operators, inputs and outputs and parameter counts, never their weights; HDF5, NetCDF and FITS files their datasets, dimensions and attributes; DICOM files their modality, study and series, with patient-identifying values withheld unless you pass `--privacy off`. Geodata gives its bounds and CRS, and every file that covers a place gets `content.extent`, its box in WGS84 (UTM and Web Mercator are reprojected). 3D models give their vertex and triangle counts, objects, materials and bounds; CAD and electronics files their application, units, layers and entities.

Game files report what their headers declare: a ROM its title, codes, region, mapper or cartridge type, and whether its checksums hold; a chiptune its title, author, copyright and songs; an archive or pack its files and maps; an engine file the engine version that wrote it. Nothing is run, decrypted or unpacked.

Formats without an extractor yet are still identified by signature, with every file-level section filled in.

As a library:

```rust
let engine = whiff::Engine::new();
let report = engine.extract_path("Cargo.toml")?;
println!("{}", serde_json::to_string_pretty(&report)?);
let compact = report.llm_view(800); // ~800 tokens
```

```toml
# library only, without the CLI's dependencies
whiff = { version = "0.7", default-features = false, features = ["common"] }
```

## The report

Every report has the same top-level sections: `whiff`, `source`, `identification`, `system`, `temporal`, `security`, `rights`, `physical`, `integrity`, `content`, `metadata` (raw metadata per standard: front matter, HTML meta, OpenGraph, JSON-LD, EXIF, XMP, IPTC, ICC, Photoshop resources), `format` (technical details per format), `embedded` (children of containers) and `diagnostics`. Empty fields are omitted; sections are always present. The schema is in [`docs/schema/whiff-1.schema.json`](https://github.com/baoulo/whiff/blob/main/docs/schema/whiff-1.schema.json).

Secrets found in content (keys, tokens, credentials in URLs) are counted under `security.secrets` and redacted from the report; personal data (e-mail addresses, phone numbers, card numbers, IBANs) is counted under `security.personal_data` and never listed in derived text.

Untrusted input is bounded: reads, decompression and time are budgeted per file, panics in extractors are contained, deeply nested input is refused before recursive parsers see it, and an extractor that ignores its deadline is abandoned by a watchdog.

## Features

| Feature | Default | Adds |
|---|---|---|
| `common` | yes | text, logs, diffs, Markdown, HTML, XML, feeds, JSON, YAML, TOML, INI, CSV, SQL, source code, package manifests, notebooks, Dockerfiles, Makefiles, raster / vector / layered images, camera raw, GPU textures, documents (PDF, Office, OpenDocument, RTF, ebooks, PostScript, BibTeX), e-mail, calendars and contacts, audio, video, subtitles, playlists, scores, archives and compressed files (squashfs too), packages, executables (ELF, PE / .NET, Mach-O, WebAssembly), bytecode (Java, DEX, Python, .NET, Lua, BEAM and more), certificates, keys and signatures (X.509, CMS, PKCS#12, SSH, OpenPGP, key stores, JOSE), databases (SQLite, DBF, Access, DuckDB, LMDB, RocksDB, Redis, pg_dump and more), Apple formats (plists, profiles, `.strings`, `.DS_Store`, aliases, asset catalogs, Xcode projects), binary serialisations (MessagePack, CBOR, BSON, Avro, protobuf, pickle, Java serialization and more), fonts (TrueType, OpenType, WOFF, Type 1, bitmap fonts, font sources); more in later releases |
| `cli` | yes | the `whiff` binary |
| `forensics` | no | disk images: partition tables, file systems, VM disks, evidence files, firmware; forensic artefacts: packet captures, event logs, registry hives, shortcuts, jump lists, Prefetch, dumps, `$MFT`, login records, journals, IDS alerts and rules, HAR, crash reports, Zeek logs (includes `common`) |
| `data` | no | columnar data and models: Parquet, GeoParquet, Arrow, Feather, ORC, Lance, Vortex, F3, Delta Lake, Iceberg, TFRecord, R fst / qs, safetensors, GGUF, ONNX, PyTorch, Keras, TensorFlow Lite, SavedModel, Core ML (includes `common`) |
| `science` | no | scientific and medical files: HDF5 (NetCDF-4, AnnData, Loom, MATLAB 7.3), NetCDF, FITS, ASDF, Zarr, GRIB, ROOT, NumPy, MATLAB, SPSS, Stata, SAS, R data, genomics (FASTA, FASTQ, SAM / BAM / CRAM, VCF / BCF, BED, GFF), chemistry (PDB, mmCIF, MOL / SDF), instruments (mzML, EDF, TDMS, VCD, OME-TIFF), simulation and EDA text formats, DICOM, NIfTI, NRRD, HL7, FHIR (includes `common`) |
| `geo` | no | geodata: GeoJSON, TopoJSON, KML / KMZ, GPX, GML, shapefiles, File Geodatabase tables, FlatGeobuf, MapInfo, OpenStreetMap, S-57, WKT / WKB, GeoTIFF / COG, DTED, ASCII grids, LAS / LAZ / COPC, E57, PMTiles, vector and 3D tiles, FIT, TCX, IGC, NMEA, map styles and QGIS projects (includes `common`) |
| `cad` | no | 3D and CAD: glTF / GLB, VRM, OBJ, STL, PLY, OFF, AMF, 3MF, COLLADA, X3D, VRML, Draco, FBX, Blender, USD, 3DS, MagicaVoxel, OpenVDB, LDraw, BVH, C3D, IES, EULUMDAT, G-code, DXF, DGN, STEP, IFC, IGES, Gerber, Excellon, KiCad, GDSII, OASIS, OpenSCAD (includes `common`) |
| `games` | no | games: cartridge ROMs, Switch and 3DS packages, chiptunes, WAD / PAK / BSP / VPK, Bethesda, RPG Maker and Ren'Py archives, Godot and Unreal packs, Unity and Unreal assets, GameMaker and Godot projects, Minecraft, Tiled, Aseprite, Steam manifests, interactive fiction, emulator saves (includes `common`; unreleased) |
| `full` | no | all collections |

The minimum supported Rust version is 1.89.

## Contributing

Adding a format is one file. See [CONTRIBUTING.md](https://github.com/baoulo/whiff/blob/main/CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](https://github.com/baoulo/whiff/blob/main/LICENSE).
