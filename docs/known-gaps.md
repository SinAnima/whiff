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
- **Not read:** ZOO, ACE, StuffIt, ARC, WIM and shell archives (`shar`),
  for lack of a writer or reader to check against.
- **Multi-volume sets** (`.z01`, `.part2.rar`, `.7z.002` …): only the
  volume given is read.
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
- **Not read:** ETW `.etl`, macOS unified logs (`tracev3`) and ASL,
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
- **Not read:** XDR (no self-description), Thrift binary and compact
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
  Inventor, Creo, CATIA, NX, Fusion 360, Revit, JT, PRC / U3D, DWF / DWFx,
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

## Games (unreleased, feature `games`)

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
