# Known gaps

What whiff deliberately leaves out of the formats it already handles, and
formats in an implemented family that are not read yet. Each item was set
aside on purpose, usually because no tool or sample was at hand to check
whiff against, or because it needs work planned for a later stage. Files
in these formats are still identified by signature, and partial support is
reported as such (a warning, or facts without a listing).

Contributions are welcome. A gap closes like any other format: a benign
fixture made by a real tool, a snapshot, and agreement with an independent
reader (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Compressed files and archives (0.5.0)

- **Entries listed but not decompressed:** RAR (only stored entries are
  handed on), LHA and ARJ (stored only), CAB Quantum and LZX folders, 7z
  PPMd and BCJ2 folders. Their names, sizes, times and methods are listed.
- **Headers only:** lzop and LZFSE files are described but not
  decompressed.
- **Read since the long tail (batch 4):** ZOO, ACE, StuffIt, ARC, WIM and
  shell archives; see "Older archives" below.
- **Multi-volume sets** (`.z01`, `.part2.rar`, `.7z.002` …): only the
  volume given is read; a later volume reports its set name and number.
- **Self-extractors inside executables:** ZIP, 7z, RAR and CAB archives
  appended to a PE image are handed on; NSIS and Inno Setup installers
  are recognised, but their payload is not unpacked.

## Packages (0.5.1)

- **Signatures are described, not verified:** whiff reports who signed a
  package and how, but does not check the signature or the certificate
  chain.
- **Not read:** Solaris SVR4 packages, Windows update packages (`.msu`),
  Unity packages, Homebrew bottles.

## Disk images (0.5.1, feature `forensics`)

- **File listings:** FAT, ext2 / 3 / 4, ISO 9660, UDF, squashfs, Amiga
  and C64 volumes are listed. NTFS, HFS+, APFS and exFAT volumes are
  described (label, UUID, sizes, times, APFS volumes) but not listed.
- **Encrypted volumes** (LUKS, BitLocker, encrypted APFS volumes and
  QCOW2 images) are detected and described, never unlocked.
- **UDF:** write-once discs with a virtual allocation table are described
  but not listed. The metadata partitions of UDF 2.50 and later are read
  but untested on a real disc; revisions 1.02, 1.50 and 2.01 are checked.
- **Evidence files:** EnCase `.Ex01` is not read, and of a split E01 set
  only the first segment is (the acquired disk is cut short there).
- **Not read:** Nero `.nrg`, Alcohol `.mds` / `.mdf`, Amstrad CPC `.dsk`,
  Atari ST specifics, sparse bundles (a folder, not a file), Android
  Verified Boot footers, UEFI firmware volumes, Flatpak `.flatpak`
  bundles.
- **Backing files:** a differencing or overlay disk (VHD, VMDK, QCOW2,
  QED) whose blocks live in a parent image reads those blocks as zeros;
  the parent's name is reported.

## Executables (0.6.0)

- **Signatures are described, not verified:** Authenticode and Apple code
  signatures report the signer, chain and times; the image hash and the
  certificate chain are not checked.
- **One slice of a universal binary** is described in full (arm64, else
  `x86_64`, else the first); the others are listed.
- **Imports are named, not resolved:** ELF imports are not matched to the
  library that provides them, and Mach-O imports are read from the symbol
  table (not from the dyld binding opcodes or chained fixups).
- **DWARF:** only the first compile unit's producer, name and language are
  read; in relocatable ELF objects the strings need relocations, so only
  the language is reported.
- **.NET assemblies:** the metadata tables are read (see Bytecode); the
  IL is not, and neither are the `#US` user strings, resources' contents
  or portable PDBs (tables past 0x2C stop the table reader).
- **Go build information** is read in the Go 1.18+ inline format; older
  binaries only report that it is there.
- **Not read:** PDB files, split DWARF (`.dwo`, `.dwp`) and dSYM bundles
  as folders, Windows minidumps, Linux kernel images, Android OAT / ART,
  Windows catalogs (`.cat`), Rust `rlib` / `rmeta`, AIX XCOFF, compiled
  AppleScript, Windows script hosts, device trees, FPGA bitstreams, and
  the WebAssembly component model beyond its header.

## Bytecode (0.6.0)

- **Nothing is decompiled:** method bodies are measured (Java code
  bytes) or scanned for one instruction (Python's `IMPORT_NAME`); no
  control flow, strings or constants are reported from them.
- **Python:** the `marshal` walk stops after 500,000 objects, 64 levels
  or 20,000 code objects; imports are found for CPython 2.0 to 3.14 only
  (3.15's opcodes are not fixed yet), and PyPy and other implementations'
  magic numbers are not named.
- **DEX:** the `cdex` (compact DEX), `vdex`, `odex` and OAT containers
  are not read; class names, packages and source files come from the
  class definitions, not from the code or debug items.
- **Lua 5.2** chunks give the version and number sizes but not the source
  name (5.2 stores it after the function body).
- **OCaml** files report their kind and release; the module name and
  imported units sit in OCaml's own (and, since 5.1, compressed) marshal
  format, which is not read.
- **YARV:** the Ruby version, byte order and word size; the source path
  and method names are in the object list, which is not read.
- **Not read:** Hermes, V8 snapshots and QuickJS bytecode, Smalltalk /
  Pharo images, Haskell `.hi` interfaces, Flash ActionScript ABC, and
  Guile `.go` files (ELF files, described by the executable extractor).

## Crypto (0.6.0)

- **Nothing is verified:** signatures, MACs, checksums and certificate
  chains are described, never checked; `expired` compares dates with the
  clock only. Revocation (CRL, OCSP) is not looked up.
- **Never read:** private key material, encrypted PKCS#12 safes, JKS key
  entries, KeePass contents, age and OpenPGP payloads: only what is in the
  clear is reported.
- **PEM bundles** describe the first 64 objects in full and count the
  rest; OpenPGP keyrings describe 64 keys, key lists 64 keys.
- **OpenPGP:** v3 keys give their key ID but no fingerprint; v5 / v6 keys
  are read from the RFC 9580 / LibrePGP layouts but only checked against
  the specification; bzip2-compressed messages are not opened.
  GnuPG reports a few old subkeys' expiry from the primary key's creation;
  whiff counts it from the subkey's, as RFC 9580 says.
- **JCEKS:** a secret-key entry is a serialised Java object of unknown
  length, so entries after the first one are not read.
- **Not read:** BKS / UBER (Bouncy Castle) key stores, PKCS#11 / TPM key
  blobs, macOS keychains, 1Password exports, VeraCrypt and BitLocker
  headers (LUKS is read by the disk extractors), S/MIME messages beyond
  their CMS part (see e-mail) and `.mobileprovision` (the Apple part of
  this stage).
- **Serials:** a negative certificate serial (invalid, but present in a
  few old roots) is shown as its bytes, as browsers do; openssl prints it
  with a minus sign.

## Databases (0.6.0)

- **SQLite:** pages are read within `max_parse_bytes`; beyond it row counts
  are estimated from the b-tree's fan-out (`rows_estimated`) and some may be
  missing. The first 256 tables are described (all are counted), 128
  columns each. A WAL file next to a database is described on its own: its
  frames are not applied when reading the database. Encrypted databases
  (SQLCipher, SEE) look like random data and are not recognised.
  Application summaries read rows only from small known tables and scan at
  most 200,000 rows for a date range.
- **Access:** encoded Jet files (a database key) and password-encrypted
  ACE files are recognised but their catalog is not read; Jet 3 text is
  read as Latin-1 whatever the code page. Tables, queries, forms, reports,
  macros and modules are counted from `MSysObjects`; query SQL, VBA source
  and table rows are not read. No Access 2007+ fixture fits the size limit:
  the ACE layout is checked by the oracle against a Jackcess file.
- **DBF:** memo files (`.dbt`, `.fpt`) are not read, and no `.cpg`
  sidecar is consulted for the encoding.
- **Header only:** LevelDB tables give their format but no entry count
  (that needs the Snappy-compressed blocks); Redis snapshots give the first
  database's key counts (later ones follow its values); Berkeley DB key
  counts are only there after `db_stat`; MySQL 8 `.ibd` SDI (the table
  definition inside the tablespace) is not decoded.
- **Not read:** SQL Server MDF / LDF and `.bak`, Firebird, Realm, Kafka
  segments, Prometheus blocks, Windows ESE databases (the forensic part of
  this stage), LevelDB / RocksDB logs and MANIFEST files, Redis AOF.

## Forensic artefacts (0.6.0, feature `forensics`)

- **EVTX:** histograms come from the `System` part of each record's
  template; `EventData` / `UserData` values are not read. Records in
  chunks past `max_parse_bytes` are counted from the chunk headers and
  dated from their first and last records only (`records_analysed`). The
  record count covers every valid chunk, including those a dirty log's
  header does not count yet (`header_chunks`).
- **Registry:** transaction logs (`.LOG1`, `.LOG2`) are recognised but not
  replayed; big-data (`db`) values and deleted cells are not read; value
  data is reported only for the few Windows facts listed.
- **Shortcuts and jump lists:** the shell item list gives volumes and
  file entries only (not control-panel or URI items); jump list
  `DestList` entries are counted, not decoded, and application IDs are not
  named.
- **Prefetch:** referenced files are counted, not listed; Windows 11's
  version 31 is read with the version 30 layout.
- **Minidumps:** memory, handles, the environment and command lines are not
  read; Windows kernel crash dumps give their header's bug check only (no
  dump type or time, not checked against a real file).
- **Captures:** the protocol histogram needs the `full` profile and reads
  128 bytes per packet (Ethernet, Linux cooked, raw IP); no reassembly,
  no endpoints.
- **Not read:** macOS unified logs (`tracev3`) and ASL,
  NetFlow / IPFIX, browser caches, `$UsnJrnl`, `$LogFile`, SRUM and other
  ESE tables (the header only), Suricata `eve.json` (read as JSON lines),
  legacy `.crash` text reports and hibernation file contents.
- **Fixtures:** EVTX, Prefetch, jump lists, a hive, two shortcuts and the
  minidumps are MIT-licensed samples (see their `SOURCE.md`); `$I`, EVT,
  ESE, crash dump, LiME, hibernation, unified2 and FSEvents files are
  built from the published layouts because no Linux tool writes them.

## Apple formats (0.6.0)

- **Property lists:** old-style (ASCII) plists with whitespace inside
  `<…>` data are not read (the `plist` crate's reader rejects them;
  Apple's accepts them). Keyed archives give their classes and root
  class, not the object graph. Configuration profile payloads are counted
  by type; their settings are not described one by one.
- **Signed profiles and shortcuts:** CMS signatures are described, not
  verified. Signed shortcuts (Apple Encrypted Archive, `AEA1`) are
  recognised but not decrypted, so their actions are unknown.
- **Bookmarks and aliases:** only CFURL bookmark data (macOS 10.6 and
  later) is read; legacy Alias Manager records (`alis`, in resource forks)
  are not. Sandbox security-scope data is noted, not decoded.
- **AppleDouble:** resource forks are sized, not parsed (no `rsrc` map).
- **Asset catalogs:** renditions are counted by type; image sizes, scales
  and idioms per asset are not read. Other BOM stores (package receipts)
  give their variable names only.
- **Not read:** `.watchface` bundles, Siri and other application plists
  beyond their generic schema, `.nib` / `.storyboardc`, `.xcuserstate`,
  `.xcscheme`.
- **Fixtures:** the alias, bookmark, AppleSingle and Godot binary files are
  built from the published layouts (real bookmarks record the creating
  user, a disk image's backing path and the boot volume); Foundation reads
  the bookmarks back in `apple.sh`.

## Binary serialisations (0.6.0)

- **Pickles and Java streams:** walked, never loaded; only known
  code-running globals and gadget classes are flagged, so an unflagged
  pickle is not proven safe. Protocol 1 `Externalizable` data in Java
  streams ends the walk (it is not self-delimiting).
- **Avro:** records are counted from block headers, not decoded (the
  writer schema describes them); Avro single-object encoding and
  Parquet / ORC (Stage 7) are not handled here.
- **Protobuf:** without a schema, length-delimited fields are guessed as
  message, string or bytes; packed repeated scalars appear as bytes; groups
  (wire types 3 and 4) end the walk. Field names come only with a schema
  (not read).
- **Ion:** decimals and shared symbol table imports are not resolved
  (decimals are reported as such, imported symbols as `$n`).
- **Smile:** big integers and big decimals are skipped, not decoded.
- **FlatBuffers and Cap'n Proto messages:** only FlatBuffers binary
  schemas (`.bfbs`) are read; other FlatBuffers and Cap'n Proto messages
  cannot be read without their schema.
- **Not read:** Thrift binary and compact
  protocols, Hessian, Bond, Kryo, .NET `BinaryFormatter` streams, Ruby
  Marshal, R `.rds` (Stage 7), the contents of compressed Godot resources
  (`RSCC`), Unity binary asset bundles.
- **Text formats:** RON, KDL, HOCON, EDN, S-expressions, textproto and Ion
  text are read by tolerant parsers into a tree; HOCON substitutions and
  includes are counted, not resolved.

## Fonts (0.7.0)

- **Not decoded:** glyph outlines, hinting programs and kerning values
  (only the feature tags), `CFF` / `CFF2` dictionaries (names come from
  the `name` table), WOFF2 transformed `glyf` / `loca` / `hmtx` tables
  (listed, not reconstructed), MicroType Express compressed EOT fonts
  (header facts only), the Unicode variation sequences of `cmap` format
  14, `STAT` axis values beyond what `fvar` names, `meta` and `ltag`.
- **Signatures:** `DSIG` signatures are counted, not verified.
- **Type 1:** multiple-master and CID-keyed fonts are described from
  their cleartext only; Type 3 and Type 42 PostScript fonts are not read.
- **Bitmap fonts:** strikes inside sfnt fonts (`EBLC`, `bloc`) are noted,
  not listed; Mac `NFNT` / `FONT` resources, suitcases without a data fork
  (the resource fork alone), Amiga and Atari fonts are not read.
- **Sources:** UFO is read through `fontinfo.plist` only (the other files
  of a `.ufo` folder are plain plists and glyph XML); zipped `.ufoz`,
  designspace documents, `.vfc` / `.vfj` (FontLab), `.fea` feature files
  and TeX font metrics (`.tfm`, `.vf`) are not read.

## Columnar data and models (0.7.0, feature `data`)

- **Not read:** Apache Hudi, Kudu and CarbonData tables, Hadoop
  SequenceFile and RCFile, MXNet RecordIO, legacy GGML / GGMF / GGJT
  containers, Core ML packages (`.mlpackage` folders: their
  `model.mlmodel` is read) and ML Program weights, LanceDB / Chroma
  stores as such (Chroma is a SQLite database; Lance data files are read).
- **Partly read:** Vortex files report their version only (the layout and
  type FlatBuffers are not decoded); Lance 0.x files their version only;
  R `qs` / `qs2` files their header (the serialised object is not
  decoded); fst column names stored compressed are not decoded.
- **Statistics:** Parquet statistics are combined as written (deprecated
  `min` / `max` used when the newer fields are absent, so signed /
  unsigned ordering follows the writer); INT96 timestamps and binary
  columns other than strings give no min / max; ORC decimal, binary and
  bucket statistics are not reported.
- **Models:** parameter counts come from tensor shapes (quantised GGUF and
  TFLite tensors count elements, not bytes); ONNX external data files are
  noted, not opened; Keras `.h5` weights (HDF5) are read by the science
  extractors, not here; SavedModel variables are not read.
- **Pickled data:** pandas pickles of timezone-aware columns import
  `builtins.getattr` and so report `unsafe_deserialization`, as any pickle
  importing it does.
- **F3:** the committed fixture is built from the published layout
  (`File.fbs`) until `scripts/fixtures/f3.sh` replaces it with the
  reference writer's files.

## Scientific files (0.7.0, feature `science`)

- **Raw data:** array values are never read, so there are no statistics
  of the data, no checks of chunk checksums and no decompression of
  data blocks; attribute and header values are read.
- **HDF5:** objects past the per-file limits, huge fractal-heap objects
  and filtered heaps are not read (counted in a warning); external and
  virtual dataset sources are not opened; HDF4 / HDF-EOS2 files
  are not read.
- **Formats read from their metadata only:** CRAM records (container
  headers, nothing decompressed but the header), GRIB data sections,
  ROOT objects (keys and classes, not trees or histograms), Zarr chunks,
  ASDF blocks (sizes and compression), OME-TIFF from the first page's
  OME-XML (BigTIFF descriptions are not read).
- **Statistics files:** value labels and missing-value definitions are
  skipped, not reported; SAS7BDAT compressed meta subheaders and column
  formats and labels are not read; R `qs` objects and native streams
  written on big-endian machines are not decoded (native streams are
  read as little-endian).
- **MATLAB:** v4 matrices give classes and sizes; v5 cells and structs
  give their size and field names, not their contents; MAT 7.3 is read
  as HDF5.
- **Chemistry:** formulas count the atoms listed (implicit hydrogens are
  not added); PDB and mmCIF give header records and counts, not
  secondary structure or sequences.
- **Tool outputs:** Gaussian, ORCA, SPICE, LTspice, IBIS, Liberty, LEF,
  DEF and ENVI are read line by line from their keywords; CP2K, VASP,
  GAMESS and NWChem outputs, Spectre and HSPICE binary waveforms and
  GDSII / OASIS layouts are not read.

## Medical files (0.7.0, feature `science`)

- **Privacy:** DICOM patient, physician, institution and accession
  attributes are reported by name only unless privacy is off; HL7 patient
  segments and FHIR Patient / Practitioner / RelatedPerson / Person
  resources are counted, never shown. Free-text attributes (study and
  series descriptions) are reported as written.
- **DICOM:** pixel data is not decoded (its size is reported);
  attributes inside sequences, private tags and DICOMDIR records are not
  listed; files without the `DICM` preamble are not claimed.
- **Volumes:** gzip-compressed NIfTI (`.nii.gz`) is described as the gzip
  file's member; MINC, MGH / MGZ and PAR / REC are not read; NRRD and MetaImage
  report their header fields, not the data files they name.
- **Messages:** HL7 v2 is read from the MSH segment and segment counts
  (no field parsing past MSH); HL7 v3 / CDA documents are read as XML;
  FHIR XML resources are read as XML.

## Geodata (0.7.0, feature `geo`)

- **Not read:** MrSID and ECW rasters (proprietary; no writer to make
  fixtures with), SRTM `.hgt` tiles (fixed sizes above the fixture
  limit), Esri I3S scene layer packages (`.slpk`), ArcGIS Pro projects
  (`.aprx`) and map documents (`.mxd`), ArcInfo export (`.e00`) and
  binary grids (`.adf`), S-101 (ISO 8211 like S-57, not yet told apart),
  personal geodatabases (read as Access databases), GeoJP2 / GMLJP2 boxes
  in JPEG 2000. NetCDF-CF and Zarr geodata are read by the science
  extractors.
- **Extents:** reprojection to WGS84 covers geographic CRSs, Web
  Mercator and UTM (WGS 84, ETRS89, NAD83); other projected CRSs keep
  their native bounds only. Files whose CRS lives beside them
  (shapefiles, ASCII grids, world files, MapInfo, E57 without coordinate
  metadata) give native bounds and no extent.
- **Bounds:** shapefile, File Geodatabase, LAS, FlatGeobuf and PMTiles
  bounds come from their headers; vector tiles have no geographic bounds
  without their tile address; 3D Tiles bounds come from the root's
  `region` or ECEF `box`.
- **Contents:** feature attributes are listed by name, not summarised;
  geometries are counted and bounded, not validated; LAZ points, raster
  pixels, vector tile geometries and OSM tags beyond the top keys are not
  decoded; GeoPackage tiles and extensions are not described beyond
  `gpkg_contents`.
- **Privacy:** OSM contributors are counted, not named; FIT and E57
  serial numbers and IGC pilots appear only with privacy off; track
  positions are reported as bounds, not as points.

## 3D and CAD (0.7.0, feature `cad`)

- **Not read:** AutoCAD DWG and Alembic (no free writer in the fixture
  toolchain), Maya, Cinema 4D, Houdini, Modo, SketchUp, SolidWorks,
  Inventor, Creo, CATIA, NX, Revit, JT, PRC / U3D, DWF / DWFx,
  Parasolid and ACIS (proprietary), Substance and MaterialX, PCD / PTS
  point clouds, Gaussian splats, MikuMikuDance and Valve models, Altium,
  Eagle and FreeCAD documents. Unreal and Unity assets belong to the games
  collection.
- **Geometry:** meshes are counted and bounded, not validated or
  decoded beyond what the counts need; glTF bounds are mesh space (node
  transforms not applied); FBX, X3D and Blender report objects and
  blocks, not triangles; Draco reports its header (connectivity is not
  decoded); USDC reports its sections (the compressed token table is not
  decoded).
- **Drawings:** DXF text goes to the text pipeline as written (MTEXT
  formatting stripped, fields not evaluated); `$LASTSAVEDBY` appears only
  with privacy off; DGN v7 element ranges are not converted to master
  units; DGN v8 (an OLE container) is not read.
- **Product data:** STEP and IFC are read from their clear text (no
  geometry, no unit conversion); IFC names come from the spatial
  structure, not property sets; IGES reports its global section and the
  directory's entity types.
- **Electronics:** Gerber bounds are those of the coordinates (aperture
  sizes not added); OASIS reports its START and END records (cells inside
  CBLOCKs are not decompressed).
- **Privacy:** C3D subject names appear only with privacy off; FBX
  document paths are dropped.

## Games (0.8.0, feature `games`)

- **Not read:** PlayStation, Saturn and Dreamcast disc images (their ISO
  9660 file systems are listed by the `disk` reader), Nintendo DS, Wii and
  GameCube images, Sega Master System and interleaved (`.smd`) Mega Drive
  ROMs, FDS disks, Valve GCF, Unity web builds (`.data`, `.wasm`), Unreal
  IoStore containers (`.utoc`, `.ucas`), Source models and textures (MDL,
  VTF), RPG Maker MV / MZ projects, Pyxel Edit files, Twine published
  HTML (read as HTML), TADS, Hugo and other story formats beyond Z-code
  and Glulx, Snes9x, ZSNES and other emulators' states, generic `.sav`
  files (`.sav` is SPSS).
- **Encrypted content:** NCA contents, XCI secure partitions, CIA
  contents, encrypted Godot packs and Unreal pak indexes are reported as
  encrypted; nothing is decrypted.
- **ROMs:** N64 CRCs are reported, not verified (the check needs the
  boot code); ROM data is not disassembled; titles come from headers
  only (iNES has none).
- **Unreal packages:** the summary is read up to the export and import
  counts for UE 5.3 and later (its layout changed); unversioned (cooked)
  packages report their version fields only. Package contents (exports,
  properties) are not parsed.
- **Unity:** bundles report their files (members are not opened);
  encrypted (UnityCN) bundles are not read; serialized files report
  objects by class, not their fields.
- **Minecraft:** region files report the first chunk's NBT only; Bedrock
  worlds' LevelDB databases are read by the `db` reader.
- **Interactive fiction:** Z-code titles are not decoded from the story
  (the Blorb iFiction record gives them); Ink and Twee text goes to the
  text pipeline as written.
- **Privacy:** Steam account lists are counted (names never shown);
  `LastOwner` Steam IDs appear only with privacy off; user folders in
  Steam paths are hidden unless privacy is off.

## Long tail (0.8.0)

The first long-tail batch reads each format line by line or from its
header; it never evaluates, expands or follows anything.

- **Lightweight markup:** inline markup is stripped, not parsed. reST
  roles and substitutions, AsciiDoc conditionals and attribute references,
  MediaWiki templates and parser functions, Texinfo macros and roff
  preprocessors (`tbl`, `eqn`, `pic`) are not expanded; included files are
  listed, not read. Nested lists and tables are counted from their first
  line. A text sitemap (one URL per line) is not recognised.
- **Configuration:** HCL expressions are not evaluated and Terraform's
  JSON syntax (`.tf.json`) is read as JSON; `.tfvars` give their variable
  names, not the values. `Include` in SSH, nginx and Apache files is
  listed, not followed. Whether a `.conf` file is nginx or Apache is
  guessed from its first directives.
- **Shockwave Flash:** ActionScript is counted and named, never
  decompiled; `DefineBinaryData` payloads, sounds and bitmaps are not
  extracted. The readers were tested on ffmpeg's SWF output and on files
  written from the specification; no Flash authoring tool was available.
- **AutoCAD DWG:** only the file header. The drawing (compressed from
  R13, encrypted page by page from R2004) is not decoded, so there is no
  title, author, layer or entity information; DXF exports carry it. The
  fixtures are headers written from the ODA specification, checked against
  libmagic.
- **WARC:** records are summarised, their payloads are not analysed as
  embedded files; `.warc.gz` goes through the gzip reader.
- **Vim swap files:** the header only; the edited text is not recovered.
- **Privacy:** cookie and bookmark hosts, `.netrc` machine names and SSH
  client host names are listed only with `--privacy off`; cookie values
  and passwords are never read into the report.
- **Programming languages (second batch):** like the first ~40, each
  language is a row of patterns: symbols are top-level definitions the
  patterns find, not a parse, and string syntax beyond simple quotes
  (heredocs, raw and nested strings) can misplace a comment marker.
  Fixed-form Fortran comments (`C` in column 1) are counted as code; use
  `!`. K and Q (`.k`, `.q`) and Unison's rarely used extensions are not
  recognised; `.d` Makefile dependency files read as D and `.pro` qmake
  projects as Prolog. Max patches list their object classes, not the
  objects' text. Line counts are checked against Pygments where it has a
  lexer; Astro, Odin, Move, Cairo, Metal, Apex, Ninja, Gleam, Roc, Unison,
  OpenQASM, Yacc, Lex, PL/SQL, Go templates, Nushell, Rego, TLA+,
  ShaderLab, Structured Text and Avro IDL have no reference lexer there.
- **SPIR-V:** the header and the instructions that describe the module;
  types, decorations and code are counted, not listed. spirv-dis reads
  big-endian modules' strings wrongly, so the big-endian fixture is
  checked against its little-endian twin.
- **Package manifests:** build scripts (`setup.py`, Gradle, `mix.exs`,
  `Package.swift`, `conanfile.py`, `flake.nix`, Podfiles, Homebrew
  formulae) are read as text with patterns, so values computed at build
  time (variables, version catalogues, loops) are missed or kept as
  written. PKGBUILD variables and RPM macros are expanded only for simple
  `%{name}` references; `%if` blocks are not evaluated. Gradle version
  catalogues (`libs.versions.toml`) are named, not resolved. Podfile,
  `Package.swift`, Homebrew, Gradle, Cabal, Mix, opam, `MODULE.bazel`,
  `flake.nix`, `build.zig.zon` and `.sln` readers have no reference
  parser in the oracle and are covered by their fixtures only. Nested
  CycloneDX components are counted with their parents.

- **Images (third batch):** headers and structure only, never pixels.
  - *Undocumented formats:* Affinity files are recognised by extension
    and report only their embedded thumbnail; FreeHand reports the
    version implied by its `AGD` signature; Figma reports the canvas
    version, not the document tree (its Kiwi schema is not decoded);
    Procreate's keyed archive is read for the canvas, DPI and layer names
    only. Corel Painter `.rif` and Unity `.tex` files are not recognised,
    nor `.lut` files (too many unrelated formats share the extension).
  - *Compressed layers not decoded:* DjVu's `ANTz`, `TXTz` and `NAVM`
    chunks use the BZZ coder, so compressed metadata, the hidden text
    layer and bookmarks are reported as present, not read (uncompressed
    `ANTa` metadata is). CorelDRAW X4+ packages give the version and the
    parts; their RIFF data is not walked for pages. Paint.NET layer names
    are in a .NET BinaryFormatter body that is not read.
  - *Text diagrams:* Mermaid and PlantUML are read line by line with
    patterns (diagram type, arrows, labels); nodes are approximate for
    diagram types other than flowcharts and sequences. Graphviz DOT is
    parsed (nodes, edges, subgraphs) but attributes other than `label`
    are skipped.
  - *Camera raw:* the new Kodak, Epson, Mamiya, Leaf, Phase One and GoPro
    files are read as TIFF structures (make, model, sensor, previews,
    EXIF); vendor maker notes (Phase One's IIQ directory, Leaf's `PKTS`)
    are not decoded. Older non-TIFF KDC files are not recognised.
  - *Whole-slide images:* the TIFF-based SVS, NDPI and SCN are read from
    the IFDs and descriptions; MIRAX (`.mrxs`, a folder of data files)
    and Ventana BIF are not recognised.
  - *Fixtures:* formats no available tool writes (ASTC, Basis, PVR, VTF,
    CDR, CGM, FreeHand, Photoshop presets, PDN, Procreate, Sketch, Figma,
    thumbcache, Photo CD, MRW, X3F) are built from their specifications;
    `media_oracle.py` checks 172 facts over 66 fixtures with independent
    readers (exiftool, ImageMagick, Pillow, olefile, ffprobe, djvudump,
    Graphviz, fig2dev, psd-tools, libmagic), and the rest are covered by
    their fixtures only.

### Older archives (long tail, batch 4)

Each reader lists entries from headers and hands on what is stored
uncompressed (and ALZip's deflated entries); nothing else is decompressed.

- **Compressed entries:** ARC (squeezed, crunched, squashed), Zoo (LZW,
  LZH), ACE (LZ77, blocked), StuffIt (all methods but stored), KGB (PAQ6)
  and ALZip bzip2 entries are listed, not decoded.
- **ZPAQ:** only the transactions (dates), fragment count and
  deduplicated size: the file list lives in a compressed index block.
  Streaming (non-journaling) archives give only the block level.
- **Not read:** PEA and EGG (no writer or published specification to
  check against), StuffIt 5 and StuffIt X (`.sitx`, undocumented), Java
  runtime images (`jimage`, the `lib/modules` file: no writer for a small
  sample), restic repositories (their `config` is encrypted) and
  duplicity manifests.
- **Apple Archive:** LZFSE-compressed archives (the default of `aa`) give
  their algorithm and sizes only, since LZFSE is not decoded; raw (`-a
  raw`) archives are listed. Fields whose size whiff does not know (hashes)
  end the reading of that entry's header.
- **dump:** the tape header only; the inode and directory records that
  list the files are not walked.
- **Shell archives and Makeself:** members are found from here-documents
  and `uudecode` blocks; shars that build files with other commands
  (`echo`, `printf`, compressed members) are not unpacked. Makeself's
  payload is handed on as one compressed tar; scripts are never run.
- **WIM:** split sets give the XML of the part that carries it; the
  directory trees inside the images (compressed metadata resources) are
  not listed, only the counts the XML records. The SWM form is covered by
  the same reader, without a fixture of its own (a split part is at least
  1 MiB).
- **PEX:** the fixture is pex 2.107.1 output with its `.bootstrap/`
  runtime removed (1 MB), which whiff counts but does not read anyway.
- **NSIS installers:** the product name, version and file list sit in the
  compressed installer header, which is not decoded; Inno Setup gives its
  version only.
- **Fixtures written from specifications:** Zoo, ACE, StuffIt, MacBinary,
  yEnc, ALZip and the OBB footer had no writer in the container; each is
  checked against an independent reader (lsar, acefile, macunpack,
  hexbin) or decoder.

### Executables and related images (long tail, batch 4)

- **PDB:** the PDB information, DBI and TPI headers and the module list;
  symbols, types and line tables are counted at most, never listed. Only
  MSF 7.00 files (Visual C++ 7 and later) are read.
- **Split DWARF:** a unit's first entry gives the producer, language and
  name; nothing below it is read. A `.dwp` package gives its index only.
  dSYM bundles are folders; their DWARF file is a Mach-O file, which the
  Mach-O reader describes.
- **Linux kernels:** the x86 setup header and the arm64 image header; the
  banner of an arm64 kernel is looked for in its first 8 MiB. Kernels
  for other architectures, and a compressed kernel's contents, are not
  read; an initramfs goes through the cpio and compression readers.
- **Android runtime files:** the version only, plus the VDEX section
  table and the OAT compiler filter. The OAT header's other fields move
  between Android versions; the fixtures are headers written from AOSP's
  sources, as no Android build was available.
- **XCOFF:** the file and section headers; the loader section (imports)
  and symbols are not listed.
- **Device trees:** the root's `model` and `compatible`; other nodes are
  counted. Sources are read line by line; macros and includes are not
  expanded.
- **Xilinx bitstreams:** the header fields; the configuration frames are
  not decoded. The fixture is written from the header layout (no
  open-source tool writes Xilinx 7-series bitstreams).
- **Script hosts:** tags are found by a tolerant scanner, not an HTML or
  XML parser; COM objects are found by their `CreateObject`,
  `GetObject` and `ActiveXObject` calls only, and obfuscated scripts
  are not decoded. The risk signals are tested with in-memory samples;
  the fixtures only show text.
- **Rust libraries:** the crate name comes from the member or file names,
  the rustc version from the metadata header; the crate's items and
  dependencies (in rustc's internal encoding) are not read.
- **AppleScript:** the format version only; script bundles (`.scptd`) are
  folders.

### Writing and older office files (long tail, batch 4)

- **Citations:** RIS, EndNote and MEDLINE records give type, title,
  authors, year and DOI; other tags are not kept. CSL-JSON (`.json`) is
  read by the JSON reader, not as citations. A `.csl` file is a style,
  not a list of citations.
- **Typst:** the `#set document(...)` title and authors, headings and
  imports; Typst code is not evaluated, so computed titles are missed.
  There was no Typst compiler to make fixtures with; the fixture is
  written by hand.
- **LyX and Scribus:** the fixtures are written by hand (`tex2lyx` needs
  a configured LyX, and Scribus is a GUI application); their layouts
  follow LyX 2.4 and Scribus 1.6.
- **Screenplays:** Fountain characters are found by the uppercase-line
  rule; boneyard and notes are not removed. Final Draft's title page is
  read as text, not as fields.
- **Scrivener:** the `.scrivx` binder only; the documents inside the
  `.scriv` folder are separate RTF files.
- **AbiWord / Gnumeric:** metadata, sections, sheets and cell counts;
  formulas, styles and cell values are not listed.
- **Marp:** slides are split on `---`; reveal.js decks in plain HTML go
  through the HTML reader.
- **StarOffice:** only the XML-based 6.0–7 packages (`.sxw`, `.sxc`,
  `.sxi`, `.sxd`); the older binary StarWriter files (`.sdw`) are not
  read. The fixtures are packages written from the OpenOffice.org 1.x
  layout, checked with libmagic.
- **iBooks:** read as EPUB 3; Apple's widgets and the `iTunesMetadata.plist`
  of purchased books are not read.
- **Mail merge data** is credited to the CSV reader; label layouts are not
  recognised.

### Document packages and older binary documents (long tail, batch 4)

- **Written from specifications, not by the applications:** the XPS,
  Word 2003 XML, iWork, HWPX, IDML, InDesign, FrameMaker, MIF, KFX,
  WordPerfect, Lotus, ClarisWorks, Write, Ami Pro, WinHelp, OneNote and
  spool fixtures; none of those applications runs here. libmagic, libwps
  (`wks2csv`) and Python's zip / XML / plist modules check what they can.
  The Windows `.shd` layout follows forensic write-ups and was not checked
  against a Windows spooler.
- **XPS:** text comes from the glyph runs' `UnicodeString`; glyph indices
  without one are not mapped back to characters. Fonts are listed, not
  read.
- **iWork:** the IWA objects (Snappy-compressed protobuf) are not decoded,
  so there is no text, title or page count; the Metadata property lists
  and file names give what is reported. iWork '09 (XML) files are not
  recognised.
- **HWPX / IDML / Flat OPC:** text is gathered from the run elements only;
  tables, footnotes and styles are not distinguished. Binary HWP (5.x,
  OLE) files go through the compound-file reader.
- **InDesign `.indd`, FrameMaker `.fm`:** the header (and the embedded XMP
  packet); the documents themselves are not decoded. MIF gives pages,
  paragraphs and strings, not the full markup.
- **Exports:** Notion and Confluence are recognised from their file names;
  other wiki exports are plain ZIP files. Page text goes through the
  Markdown and HTML readers only when a member is handed on.
- **KFX:** the container header; the Ion entities (and the book inside)
  are not decoded, and a DRM-wrapped file gives only that it is wrapped.
- **WordPerfect, ClarisWorks, OneNote:** headers only; document text and
  OneNote section / page titles (in the revision store) are not read.
  Works documents, Ichitaro and Quattro Pro `.qpw` files (OLE) go through
  the compound-file reader.
- **Lotus 1-2-3:** cell counts and label text; numbers, formulas and
  named ranges are not listed. WK3 and later sheet names are not read.
- **CHM:** the directory and the uncompressed `#SYSTEM` file; the topics
  (LZX-compressed) are listed, not decompressed, so there is no topic
  text.
- **WinHelp:** the directory and `|SYSTEM`; topic text (`|TOPIC`,
  phrase-compressed) is not decoded. Macros are flagged as active content,
  never run.
- **PCL:** pages are counted from form feeds outside data blocks (PCL 5);
  PCL XL and PostScript jobs give their language only.
- **Illustrator:** the PDF-compatible part is read as a PDF; the native
  artwork in `/AIPrivateData` (compressed) is counted, not decoded.

### Data and configuration files (long tail, batch 5)

- **Privacy:** by default bank statements give the last four characters
  of each account and no amounts; GEDCOM, LDIF and JSContact give counts
  and attribute names; Terraform state gives resource types and output
  names; and the JSON / YAML schema summary of these files leaves out
  its example values. With `--privacy off` they give the full details:
  whole account numbers, balances and transactions (up to 200), each
  individual's name and birth / death years, each directory entry's
  values, the JSContact card, Terraform resource attributes and output
  values, EDI party ids, the Drive account and a location history's
  exact bounding box. Terraform attributes and outputs marked sensitive,
  or named like secrets, stay hidden even then.
- **QIF:** dates are kept as written, since QIF does not say whether the
  day or the month comes first.
- **Ledger / Beancount:** read line by line; includes, automated
  transactions and periodic transactions are not expanded, and amounts
  are not checked to balance.
- **EDI:** segments are split on the declared separators; loops and
  segment contents beyond the envelope and the transaction-set ids are
  not interpreted.
- **GTFS:** only the files at the feed's root; frequencies, fares and
  calendar exceptions are not read.
- **Notebooks:** Mathematica cells are classified by their style string;
  Livebook dependencies come from `Mix.install`. Databricks `.dbc`
  archives are plain ZIP files.
- **Known schemas:** recognised inside the JSON / YAML report
  (`format.json.known_schema`); a Scratch `.sb3` is a ZIP whose
  `project.json` is recognised as it is handed on.

### XML vocabularies, mail stores and the web (long tail, batch 5c)

- **Mail stores, header only:** PST / OST / PAB report their header
  (content type, layout, encryption, declared size); the node and block
  B-trees, folders and messages are not read. Lotus Notes databases
  report their on-disk structure version and declared size; the title and
  replica id live in parts of the file whose layout is not published.
  Outlook Express DBX files report their kind and item count; messages
  are not extracted.
- **OLM:** folders and messages are counted from the archive's entry
  names, and message dates come from the first 500 messages; contacts,
  calendar items, tasks and notes are counted as files.
- **Mork:** cells are resolved from the dictionaries and rows; table
  scopes, row deletions inside transaction groups and cut-and-paste
  updates are not replayed.
- **TNEF:** OEM-code-page strings are read as Latin-1; embedded messages
  (attachments of type 5) are listed but not opened; MAPI properties
  beyond those listed in the reader are skipped.
- **SAML:** signatures are reported, not verified; encrypted assertions
  are counted as elements only.
- **Apple Health:** record dates give a range; values and units are not
  aggregated. Large exports are read up to the parse limit.
- **Watch faces:** there is no published layout; face type, complications
  and customisations are read from `face.json` and `metadata.json` as
  watchOS writes them.
- **Web Bundles / signed exchanges:** the bundle index and response
  headers are read; signatures and integrity proofs are not verified,
  and payloads are not handed on.

### Audio and video long tail (batch 5d)

- **Raw streams:** AC-3 / E-AC-3, DTS and TrueHD / MLP frames are walked
  for the duration; DTS extensions (DTS-HD, DTS:X) and E-AC-3 dependent
  substreams are noted, not decoded. Dialogic VOX has no header: 8 kHz
  mono is assumed. QCP, OpenMG, TwinVQ and Shorten are read from their
  headers; durations come from the declared sizes and rates.
- **RealAudio:** v3 – v5 headers and their four text fields; the data is
  not walked.
- **Instruments:** SoundFont generators and modulators, DLS articulation
  and EXS zone parameters are not interpreted; EXS24 follows the layout
  open-source converters read (there is no published specification).
- **Projects:** Audacity's `.aup3` (SQLite) is read as SQLite; Pro Tools
  and GarageBand / Logic sessions are covered in batch 5 part f below;
  Cubase / Nuendo projects are not read. FL Studio event coverage follows PyFLP's notes; automation,
  playlists and mixer routing are not reported. Ableton and REAPER
  devices and plug-ins are named, not their parameters.
- **DV / MXF:** DV reads the first frame's packs (SD only; DVCPRO HD and
  DV50 are not distinguished). MXF reads the header partition only (no
  index tables, body or footer); descriptors are matched by their static
  local tags, and picture coding is named from its UL.
- **Game and camera video:** Bink, Smacker and NSV report their headers;
  R3D reports only its version marker and ARRIRAW its byte order,
  version and image size. Blackmagic RAW, MTV and AMV variants other
  than FFmpeg's are not read.
- **Edit lists:** AAF is not read (no fixture fits the size limit);
  DaVinci Resolve `.drp` projects are not read. FCPXML and Kdenlive
  report counts and the sequence length, not the full edit.
- **asciinema:** keystrokes and terminal output are never copied, only
  event counts and the duration.
- **Insta360 `.insv` / `.osv`:** read as MP4; the camera's trailer
  (serial number, gyro, GPS) is not read.

### 3D and CAD long tail (batch 5e part 1)

- **Header-level readers:** Parasolid, ACIS, JT, PRC, U3D and DWF report
  their headers, tables of contents or block lists; geometry (B-rep
  topology, tessellations, U3D meshes) is not decoded. Binary ACIS
  (`.sab`) gives its version and body count only.
- **Alembic:** the archive metadata and object schemas are read from the
  Ogawa blocks (or the raw HDF5 file); sample data, time sampling and the
  object hierarchy are not.
- **Point clouds:** PCD bounds come from ASCII data only (binary and
  compressed PCD report the header); PTS and XYZ are read as text.
- **Maya:** ASCII scenes only; Maya binary (`.mb`), Cinema 4D, Houdini
  (`.hip`, `.bgeo`) and Modo files are not read.
- **SketchUp:** the version and thumbnail; the model itself is not read.
- **MMD / Valve:** PMX is read up to the bone count; PMD names are
  decoded with the generic text detector (Shift-JIS models may need it);
  Valve MDL gives header counts, not the bones or sequences themselves.
- **Revit:** only `BasicFileInfo` and PartAtom; elements are not read.
- **Not read:** Substance archives (`.sbsar`).

### Science and medical long tail (batch 5e part 2)

- **HDF4:** data descriptors, vgroups and attribute vdatas are read;
  data set shapes and types (in the SD descriptors) are not decoded, and
  only character attributes give their values. HDF-EOS structures are
  named from `StructMetadata`, not walked.
- **Maple / Mathcad:** element and region counts and the metadata; the
  mathematics is not evaluated or transcribed. Old binary Mathcad
  (`.mcd`) and Maple classic worksheets (`.mws`) are not read.
- **SCP-ECG:** sections 0, 1, 3 and 6; Huffman-coded and bimodally
  compressed rhythm data is not decoded, and measurements and
  interpretations (sections 7 – 11) are not read. CRCs are not checked.
- **aECG:** the first rhythm series' leads and sampling; annotations are
  counted, not interpreted.
- **Not read:** Wolfram `.mx` dumps and ECW
  rasters (no published layout); MrSID is identified by its signature
  only (size, bands and CRS need the vendor's decoder).

### Databases, logs and caches long tail (batch 5e part 3)

- **Realm / Firebird:** headers only; tables and records are not read.
- **SQL Server:** backups (MTF) give their TAPE and SSET blocks; the
  database name, pages and log in the MSSQL streams are not read. Data
  files (`.mdf`, `.ldf`) are not read (the boot page layout is not
  published).
- **Kafka:** record batches are framed and counted; records are not
  decompressed or decoded, and CRCs are not checked.
- **Prometheus TSDB:** the index gives its symbol table; series and
  postings are not walked. Chunks are counted by encoding, not decoded.
- **Anki:** `.anki21b` collections (zstd) are not handed on.
- **Unified log:** the header and chunk tags; firehose entries, catalogs
  and compressed chunksets are not decoded (no message text is read).
- **ASL:** records are walked through their `next` pointers; keys and
  messages are not copied.
- **nfdump / IPFIX:** headers and IPFIX sets; flow records are counted,
  not decoded. NetFlow v5 / v9 exports in pcap files are left to the
  packet-capture reader.
- **Browser caches:** Firefox cache2 entries, Chrome block files, index
  and simple-cache entries; Chrome entry blocks inside `data_*` files are
  not walked, and cached bodies are not handed on.

### Packages, bytecode, keys, big data and wrappers long tail (batch 5e part 4)

- **Hermes:** the header, function headers and string table; bytecode
  is not disassembled, and the version-dependent fields after the string
  storage size are read for bytecode version 87 and later only. Delta
  (`~MAGIC`) files give their header. V8 snapshots and QuickJS bytecode
  are not recognised (neither has a stable signature).
- **Smalltalk:** image headers only (no object memory is walked);
  `.image` and `.changes` are not claimed by extension (disk images and
  Debian upload files share them). Change logs are split on `!` chunks
  without handling doubled `!!` escapes.
- **ActionScript bytecode:** classes and counts; method code is not
  disassembled, and traits are counted, not listed.
- **TPM:** TPM 1.2 key blobs are recognised but not decoded; the private
  part of a TPM 2.0 key is never read. The TPM name is computed only for
  SHA-256 name algorithms. Context files written by newer `tpm2-tools`
  carry ESYS metadata after the context blob, which is not read.
- **SequenceFile / RCFile:** records are framed and counted, not
  decoded; compressed RCFile keys are inflated only for the zlib
  `DefaultCodec` (other codecs: row groups without the row count).
- **Hudi:** `hoodie.properties` and commit files; the timeline is not
  walked as a folder, and Kudu and CarbonData files are not recognised.
- **OCI layouts:** the `oci-layout`, `index.json` and manifest JSON are
  recognised one file at a time; a layout folder is not read as a whole
  (image tarballs are, by `package.tarball`).
- **Wrappers:** a partial download is not checked for completeness
  beyond its trailing zeros; `.tmp` names count only over another
  extension. Safari's `.download` bundles are folders and are not read.
- **Sparse files:** `system.sparse` compares allocated blocks with the
  size (filesystem compression gives the same answer); holes are not
  located (`SEEK_HOLE` is not available in the standard library).

### The last catalogue rows (batch 5 part f)

- **Fixed-width tables:** recognised by name only (`.fwf`, and `.prn`
  files whose lines form columns): aligned text is too common to claim by
  content. Columns are the runs of positions that hold a character in any
  of the first 100 lines, as pandas infers them; a column whose values
  touch the next one merges with it, and a value that spills into a gap
  merges two columns.
- **XDR:** there is no schema, so strings are found greedily (a length
  word, printable UTF-8, zero padding) and the other words are only
  classified; integers that look like string lengths can hide data.
  Record-marked ONC RPC calls and replies are recognised; their arguments
  are not decoded. Stellar and other XDR-based formats are not named.
- **ETW:** event payloads are not decoded (that needs each provider's
  manifest or TraceLogging metadata); providers are named from their
  TraceLogging traits or a short list of well-known GUIDs. Compressed
  buffers (Windows 8 and later, `EVENT_TRACE_COMPRESSED_MODE`) are counted
  but not decompressed. Checked against libmagic, Airbus CERT's
  etl-parser structures and two etl-parser sample traces (not committed:
  they come from real machines).
- **JMP:** column names come from the same search JMPReader.jl uses (a
  `07 00 08 00 00 00` mark and the column index lists); tables written
  before JMP's current layout give their layout only. Column data,
  formulas, scripts and row states are not read. Checked against
  JMPReader.jl's 19 test tables (rows, columns and names); its own reader
  was not run (no Julia toolchain in the fixture images).
- **Minitab:** release ranges from PRONOM's signatures (fmt/1430 –
  fmt/1438); worksheet columns, constants and project contents are not
  read (no published layout). Minitab 19+ `.mwx` / `.mpx` files are not
  recognised.
- **Pro Tools:** version, sample rate, files, tracks and regions as
  ptformat reads them; track lists include tracks without regions
  (ptformat's sample outputs list only placed tracks). Fades, playlists,
  automation and plug-in names are not read. Checked against ptformat's
  expected outputs for its sample sessions (41 / 42; the difference is
  that empty-track choice); the samples are LGPL and not committed.
- **GarageBand / Logic:** `ProjectData` gives chunk kinds only (chunk
  bodies are not decoded); `.band` / `.logicx` bundles are folders, read
  file by file (`MetaData.plist`, `ProjectInformation.plist`). The
  framing was checked on the six project templates GarageBand installs.
- **Cubase / Nuendo:** `.cpr` / `.npr` projects are not read (no
  published layout and no redistributable sample).
- **Fusion:** manifests, document structure, part counts and references;
  B-rep, mesh and T-spline geometry is not decoded, and per-asset
  manifests give their asset type only. Onshape exports are STEP,
  Parasolid or other exchange files and are read as such.

