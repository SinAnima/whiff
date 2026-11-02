# Changelog

All notable changes to whiff are recorded here. The report format is
versioned separately (`whiff.schema`, currently `whiff/1`); additive changes
keep the schema version.

## Unreleased

Fonts, columnar data and machine-learning models, scientific and medical
files (Stage 7, first three parts).

- **Fonts** (`common`), all in-house (WOFF2 through the existing Brotli
  decoder; no read-fonts / skrifa / allsorts):
  - TrueType and OpenType fonts, collections (`.ttc`, `.otc`), WOFF,
    WOFF2 (collections too), Embedded OpenType (header, root URLs, the
    font inside when it is not MicroType Express compressed) and Mac
    `dfont` resource files, each described from its sfnt tables: family,
    subfamily, typographic names, full and PostScript names, version,
    unique ID, manufacturer, designer, URLs, copyright, licence and
    licence URL (SIL OFL recognised), revision, units per em, creation
    and modification dates, glyph count, vendor ID, weight and width
    class, italic / bold / oblique, monospace, italic angle, x-height and
    cap height, the `fsType` embedding permission (into
    `rights.embedding`), Unicode coverage (code points and their scripts),
    variable axes and named instances, colour and bitmap glyph formats
    (COLR, CPAL palettes, SVG, sbix, CBDT), OpenType features and scripts,
    hinting and digital signatures; collections list their members. Fonts
    larger than the parse limit are read table by table;
  - PostScript Type 1 (PFB, PFA): the font dictionary and, from the
    decrypted `eexec` part, the glyph and subroutine counts; AFM metrics;
    PFM (Windows printer metrics);
  - bitmap fonts: BDF and PCF (XLFD name and properties, glyph and
    encoded character counts), Windows FNT and FON libraries (every
    face's size, weight and character set), PC Screen Font 1 and 2 (glyph
    count, cell size, Unicode table);
  - font sources: FontForge `.sfd`, Glyphs 2 and 3, UFO `fontinfo.plist`
    and Metafont `.mf` (names, version, designer, licence, embedding,
    dates, masters, instances, axes, glyph count, features).
- **Columnar data and models** (feature `data`, which now includes
  `common`), all in-house (no parquet / arrow / orc-rust / apache-avro
  crates); files are read from their footers and headers through the
  source, never loaded whole:
  - Apache Parquet (a Thrift compact reader): writer, rows, row groups, the
    schema as a type tree, codecs, encodings, sizes, column statistics
    (min, max and nulls across row groups; strings redacted like other
    sample values), key-value metadata (pandas index, Spark, Arrow) and
    encrypted footers; GeoParquet files also give their geometry columns
    (encoding, geometry types, CRS, bounding box);
  - Apache Arrow IPC files (Feather 2) and streams, Feather 1: schema,
    dictionaries, record batches, rows, body compression; ORC: version,
    writer, compression (zlib, Snappy, LZ4, Zstandard footers), stripes,
    rows, schema, column statistics, user metadata; Lance v2 data files
    (schema, rows), Vortex (version), F3 (version, checksums, Arrow schema,
    rows, row groups, embedded WebAssembly decoders);
  - Delta Lake commits (operation, engine, protocol, schema, partitions,
    files and rows added) and Iceberg table metadata (schema, partitioning,
    properties, snapshots); TFRecord (records, `tf.train.Example`
    features); R `fst` tables (columns, types, rows) and `qs` / `qs2`
    headers; pandas DataFrame pickles;
  - models, never their weights: safetensors (tensors, dtypes, parameters,
    metadata), GGUF (architecture, name, licence, context length,
    quantisation, hyper-parameters, vocabulary, tensor types), ONNX
    (producer, opsets, operator histogram, inputs and outputs, parameters;
    walked through the source, so inline weights are skipped), PyTorch
    checkpoints (ZIP and legacy: storages, storage types, TorchScript, the
    pickle's globals with `unsafe_deserialization` as for pickles), Keras
    archives, TensorFlow Lite (operators, tensors, signatures, runtime
    version), SavedModel (tags, TensorFlow version, signatures, graph ops)
    and Core ML (model type, typed inputs and outputs, author, licence,
    layers).
- **Scientific files** (feature `science`, which now includes `common`),
  all in-house (no hdf5 / netcdf / fitsrs / noodles / dicom crates);
  large files are read through the source, raw data is never decoded:
  - HDF5 (superblocks 0–3, v1 and v2 object headers, symbol-table,
    compact and dense groups, datasets with their shapes, types, layouts,
    chunks and filters, attributes) and the layouts built on it:
    NetCDF-4, AnnData `.h5ad`, Loom, MATLAB 7.3, Keras, HDF-EOS5 and
    NeXus; NetCDF classic (CDF-1, CDF-2, CDF-5) with dimensions,
    variables and CF attributes; FITS (every HDU, observation keywords,
    WCS, `CHECKSUM` / `DATASUM` verified); ASDF (tree, ndarrays, blocks);
    Zarr v2 and v3 metadata; GRIB 1 and 2 (messages, centres, parameters,
    reference times); ROOT (version, compression, keys and classes);
  - arrays and statistics: NumPy NPY and NPZ, MATLAB MAT v4 (both byte
    orders, sparse sizes) and v5 (compressed variables, structs, function
    workspaces); SPSS SAV / ZSAV (long variable names) and portable POR,
    Stata DTA (formats 113–119), SAS XPORT v5 and v8, SAS7BDAT (rows,
    columns, names, dates, host), R RDS and RData (XDR, ASCII and native
    streams; data frames, vectors, lists, S4 objects, environments,
    closures and byte code, ALTREP sequences and wrappers);
  - genomics: FASTA, FASTQ, SAM, BAM, CRAM, VCF (`vcf_variants`), BCF,
    BED and GFF / GTF; chemistry: PDB, mmCIF, MDL MOL and SDF, Tripos
    MOL2, XYZ; instruments: mzML and mzXML mass spectrometry, EDF / EDF+,
    BDF / BDF+, BrainVision headers, NI TDMS (both byte orders), VCD
    waveforms, sigrok sessions, OME-TIFF microscopy images;
  - tool outputs and electronics: Gaussian and ORCA outputs, SPICE
    netlists, LTspice schematics, Touchstone, IBIS, Liberty, LEF, DEF,
    ENVI raster headers.
- **Medical files** (feature `science`): DICOM (meta header, transfer
  syntax, SOP class, modality, equipment, study and series, image
  geometry; deflated, big-endian and mislabelled implicit-VR datasets),
  NIfTI-1 and NIfTI-2 (single file and pairs), Analyze 7.5, NRRD,
  MetaImage, HL7 v2 messages and FHIR JSON. Patient-identifying DICOM
  attributes are listed by name, their values withheld unless privacy is
  off; HL7 patient segments and FHIR personal resources are counted,
  never shown.
- **Plugin API:** `plugin::flatbuf` (FlatBuffers tables without a schema)
  and `plugin::protowire` (protobuf fields without a schema), shared by the
  columnar readers and the `.bfbs` extractor; raw Snappy and LZ4 block
  codecs (`Codec::SnappyBlock`, `Codec::Lz4Block`).
- **Licences:** the SIL Open Font License (1.0 and 1.1) and the Ubuntu
  Font Licence are recognised in licence texts.
- **Developer tools:** `scripts/fixtures/fonts.sh` makes the font fixtures
  in a podman container (fontTools FontBuilder, ufoLib2 and glyphsLib,
  FontForge, bdftopcf, bdf2psf, mkeot); `font_oracle.py` compares the
  reports with fontTools, pcf2bdf, psfgettable, wrestool and FontForge
  over macOS system and application fonts and Debian font packages.
  `scripts/fixtures/columnar.sh` makes the columnar and model fixtures
  with each format's own library (pyarrow, geopandas, pylance,
  vortex-data, deltalake, pyiceberg, tfrecord, safetensors, gguf, onnx,
  torch, Keras / TensorFlow, coremltools; R fst, qs and qs2), and
  `columnar_oracle.py` compares reports with those libraries over
  generated files and the models found in /Applications and Homebrew.
  `scripts/fixtures/f3.sh` builds F3's reference writer for its fixtures.
  `scripts/fixtures/science.sh` makes the science and medical fixtures
  with each format's own tools (h5py, netCDF4, astropy, asdf, zarr,
  samtools, bcftools, eccodes, NumPy, SciPy, pyreadstat, uproot, gemmi,
  RDKit, pyEDFlib, npTDMS, pyvcd, sigrok-cli, scikit-rf, tifffile,
  pydicom, nibabel, pynrrd, fhir.resources; R and haven);
  `science_oracle.py`, `science2_oracle.py` and `science_oracle.R` compare
  the reports with those libraries and with R over generated files and
  the test data the libraries ship.

## 0.6.0 — 2026-10-31

Executables, bytecode, crypto, databases, forensic artefacts, Apple formats
and binary serialisations: Stage 6 is complete. What was deliberately set
aside is listed in [`docs/known-gaps.md`](docs/known-gaps.md).

- **Executables** (`common`), all in-house: every binary reports its kind
  (executable, shared library, object, core dump, driver, EFI image),
  architecture, bitness, byte order, entry point and target OS; its
  sections with their entropy, segments, the libraries it links and the
  symbols it imports and exports; `hardening` (PIE / ASLR, NX / DEP,
  RELRO, stack canary, FORTIFY, CFG, SafeSEH, CET, BTI / PAC, hardened
  runtime, library validation, stripped); debug information; and
  `toolchain` from a bounded scan (compilers and linkers, Go build
  information with module, dependencies and build settings, rustc
  version and commit, NSIS / Inno Setup installers, PyInstaller bundles
  with their Python version, UPX):
  - ELF executables, shared objects, relocatable objects and kernel
    modules (interpreter, `SONAME`, `RPATH` / `RUNPATH`, GNU build id, ABI
    tag, GNU properties, FDO package metadata notes, Android API level,
    the DWARF compile unit's producer and language), core dumps (signal,
    process, command line, threads, mapped files) and eBPF objects
    (programs, licence, maps);
  - Windows PE32 / PE32+ images (subsystem, link time unless the build is
    reproducible, linker and OS versions, delay-loaded libraries, exports,
    resources by type, the version information: company, product,
    description, versions, copyright, original file name; the manifest's
    requested execution level; the PDB path, GUID and age; TLS callbacks;
    the Rich header's tool records; the Authenticode signer, digest,
    signing time, timestamp and chain; installers and archives appended to
    the image, handed on), .NET assemblies (CLI runtime and metadata
    versions, IL only, strong name), COFF objects, and the MS-DOS MZ,
    NE and LE / LX headers (target OS, module name, description);
  - Mach-O executables, dylibs, bundles, kernel extensions, objects and
    dSYM files, and universal binaries (the architectures, one slice
    described): file type and flags, install name and versions, run
    paths, UUID, platform and minimum OS / SDK, build tools, source
    version, FairPlay encryption, the code signature (identifier, team,
    hash type, flags, entitlements, the CMS signer and its chain);
  - WebAssembly modules: section counts, imports by module (WASI named),
    exports, memory limits, the start function, module name, `producers`,
    target features, source maps, relocatable objects and dynamic
    libraries.
- **Bytecode** (`common`), all in-house; nothing is run, unmarshalled into
  live objects or decompiled:
  - Java class files: class-file version and Java release (preview
    features), kind (class, interface, enum, record, annotation, module),
    name, superclass, interfaces, access flags, field and method counts
    with the method names, source file, record components, permitted
    subclasses of sealed types, nest and inner classes, annotations (and
    from them Kotlin, Scala or Groovy as the source language), referenced
    packages, debug information, and a module's requires, exports, opens,
    uses, provides and main class;
  - Android DEX: version and minimum Android API level, the verified
    checksum and SHA-1 signature, counts of strings, types, prototypes,
    fields, methods and classes, the classes defined with their packages
    and source files, referenced packages, the D8 / R8 marker (tool,
    version, mode, minimum API) and Kotlin;
  - Python `.pyc` (2.0 to 3.15): the Python version from the magic number
    (development builds too), timestamp or hash-based invalidation with the
    source time, size or hash, and from a bounded `marshal` walk the source
    file, module docstring, imported modules and top-level definitions;
  - .NET assemblies, through the ECMA-335 metadata tables: assembly name,
    version, culture and public-key token, module and MVID, referenced
    assemblies, native modules and P/Invoke imports, counts of types,
    methods, fields, properties, events and resources, namespaces and
    public types, the entry point, the target framework and the assembly
    attributes (title, company, product, copyright, versions,
    `InternalsVisibleTo`), ReadyToRun images, and known obfuscators;
  - Lua 5.1 to 5.4 and LuaJIT (version, source name, stripped, number
    sizes), Erlang BEAM (module, Elixir, exports, imported modules, `vsn`,
    behaviours, compiler version, options and source, debug information),
    Emacs Lisp `.elc` (Emacs version, functions, variables, features),
    mruby (format, compiler, sections, source files), Ruby YARV (Ruby
    version, byte order, word size) and OCaml compiled files (kind and
    OCaml release).
- **Crypto** (`common`), all in-house. Key material is never reported:
  private parts are skipped unread, nothing is decrypted and no signature
  is verified:
  - X.509 certificates, as DER or in PEM bundles: subject, issuer, serial,
    validity and whether it has passed, key algorithm, size and curve,
    signature algorithm, basic constraints, key usage, extended key usage,
    alternative names, SHA-256 and SHA-1 fingerprints; certificate
    requests, revocation lists (issuer, updates, revoked count, CRL
    number), PKCS#7 / CMS signed and enveloped data (signer, digest, times,
    chain; recipients, cipher), Microsoft security catalogs (member
    count), PKCS#12 (MAC, which safes are encrypted and how, bag types,
    the certificates of unencrypted safes) and keys (PKCS#8, encrypted
    PKCS#8 with its PBES2 / PBKDF2 / scrypt parameters, PKCS#1, SEC1,
    `SubjectPublicKeyInfo`, the old `DEK-Info` PEM form): type, size,
    curve and protection;
  - SSH: public keys (one per line and RFC 4716), `authorized_keys`
    (options used), `known_hosts` (hashed and named hosts, markers; host
    names are not listed), OpenSSH certificates (type, key ID, principals,
    validity, options, CA key), OpenSSH private keys (cipher, KDF and
    rounds; the comment when unencrypted) and PuTTY `.ppk` (versions 2 and
    3, Argon2 parameters), with the fingerprint `ssh-keygen -l` prints;
  - OpenPGP, binary or armoured, and GnuPG keyboxes: keys with
    fingerprint, key ID, algorithm, size or curve, creation, expiry and
    usage from the self-signatures, revocation, user IDs and subkeys,
    secret-key protection and GnuPG stubs; messages (recipients' key IDs,
    passphrase encryption, cipher, compression, the literal file name and
    date, inside zlib / ZIP compression too) and signatures (type, issuer,
    hash, time; clear-signed text);
  - key stores: Java JKS / JCEKS (entries with alias, type, date and the
    certificate), Kerberos keytabs (principals, encryption types, key
    versions; user principals hidden by strict privacy), KeePass 2 (KDBX
    3 / 4: cipher, compression, AES-KDF or Argon2 parameters) and KeePass 1
    headers;
  - JSON Web Tokens (JWS / JWE header, registered claims with times and
    expiry, the other claims' names), JSON Web Keys and key sets (type,
    curve, size, use, ID, whether a private part is present), age files
    (recipient types, scrypt work factor), minisign and signify keys and
    signatures (key ID, algorithm, comments, KDF) and TLS key logs (labels
    and session counts only).
- **Databases** (`common`), all in-house; read without a database engine,
  nothing executed, no row data beyond the application summaries:
  - SQLite, through a read-only b-tree reader that loads pages on demand
    within the parse budget: SQLite version, page size and count, text
    encoding, journal mode, auto-vacuum, user version, application ID, free
    pages; tables with their columns (declared type, primary key, NOT NULL,
    foreign keys), WITHOUT ROWID, STRICT and virtual tables, indexes, views
    and triggers; row counts (exact within the budget, estimated from the
    tree's fan-out beyond it); and the application: GeoPackage contents,
    MBTiles metadata, Chromium and Firefox histories (visit counts and
    date range, never URLs), cookie and login stores (counts only), Core
    Data entities, Apple Photos and Messages, Lightroom catalogs, Anki
    collections, iOS backup manifests, SpatiaLite, Fossil and Android app
    databases. Also SQLite write-ahead logs (frames, commits, pages) and
    rollback journals;
  - dBASE / FoxPro / Visual FoxPro tables: variant, last update, record
    count and size, code page, memo file, fields and deleted records;
  - Microsoft Access (Jet 3 to ACE 16): engine and Access version, code
    page, creation date, encoding, and from the `MSysObjects` catalog the
    user tables with row counts and columns, linked tables, queries,
    forms, reports, macros and modules (macros and VBA modules report the
    `macros` risk);
  - from their headers: DuckDB (storage and library version, blocks), LMDB
    (map and page size, entries, depth, transaction), Berkeley DB (access
    method, version, page size, pages), LevelDB and RocksDB tables (format
    and RocksDB's properties: entries, sizes, column family, comparator,
    compression, creation time), Redis RDB snapshots (versions, keys per
    database), PostgreSQL `pg_dump` custom archives (versions, database,
    compression, the table of contents by object type, schemas and
    tables), MySQL / MariaDB `.frm` (engine, server version), InnoDB `.ibd`
    tablespaces, MyISAM / Aria indexes and H2 MVStore files.
- **Forensic artefacts** (feature `forensics`), all in-house; counts, time
  ranges and identifying facts, never the content (user names in paths are
  hidden when privacy is strict):
  - packet captures: pcap (micro- and nanosecond), pcapng (OS, hardware,
    application, interfaces, block counts, comments, decryption secrets)
    and btsnoop: packets, bytes, truncation, time range, and with the
    `full` profile a protocol histogram;
  - Windows event logs: EVTX (version, chunks, dirty / full, record count
    and range, time range, and from each record's binary XML template the
    channels, providers, event IDs, levels and computer count) and EVT;
  - registry hives: version, dirty, last written, embedded file name, key
    and value counts, the hive's kind, and for SOFTWARE / SYSTEM / SAM /
    Amcache the Windows product, build, install date, control set, time
    zone and account or file counts;
  - shell artefacts: shortcuts (target, arguments, working folder, the
    target's times and attributes, volume or share, tracker machine ID and
    droid time, known folder), jump lists and custom destinations, Recycle
    Bin `$I` files, and Prefetch for Windows XP to 11 (LZXPRESS Huffman
    decompression in-house: executable, hash, run count, last run times,
    volumes, files loaded); shortcuts that start a command interpreter with
    arguments report the new `script_shortcut` risk;
  - dumps: minidumps (Windows, Breakpad, Crashpad: system, exception and
    the module it hit, modules, threads, process), Windows kernel crash
    dump headers (bug check), LiME images and hibernation files;
  - `$MFT` files (record counts, deleted records, time ranges, extension
    histogram), Linux utmp / wtmp / btmp, systemd journals, Snort unified2
    alerts, Snort / Suricata rule files, HAR archives (credential-carrying
    requests flagged), Apple `.ips` crash reports, Zeek logs, FSEvents
    pages and ESE database headers.
- **Apple formats** (`common`; property lists through the `plist` crate
  after a bounded first pass, the rest in-house):
  - property lists, XML, binary and old-style: encoding, top-level keys,
    value count, depth and an inferred schema, and what the common kinds
    hold: bundle `Info.plist` (identifier, name, version, build,
    executable, minimum OS, SDK and Xcode, document and exported types, URL
    schemes, privacy usage keys, App Transport Security, `LSEnvironment`),
    launchd jobs (label, program, run conditions), `NSKeyedArchiver`
    archives (objects, root class, class histogram), configuration
    profiles, signed or not (identifier, organisation, scope, removal
    date, payload types, signer; root certificates and embedded passwords
    flagged, never shown), provisioning profiles (team, app ID, platforms,
    dates, distribution kind, device count, entitlements, signer),
    Shortcuts and Automator workflows (actions; script actions flagged)
    and iOS backup `Info.plist` / `Manifest.plist` / `Status.plist`
    (device model, iOS version, backup date, encryption; device name,
    serial number and identifiers only with privacy off);
  - `.strings` (text, UTF-16 or compiled), `.stringsdict` (plural
    categories) and `.xcstrings` string catalogs (source language,
    languages, translation states), with the source text as body text;
  - `.DS_Store` (entry names, record types, view style, cached
    modification dates), bookmark data and Finder alias files (target
    path, name, kind and creation date, volume; the stored user name only
    with privacy off), AppleDouble and AppleSingle files (original name,
    Finder type and creator, dates, resource fork, extended attributes
    with the quarantine agent and download URLs);
  - compiled asset catalogs (`Assets.car`: CoreUI and storage versions,
    build time, authoring tool, platform, key format, asset names,
    appearances, rendition types) and Xcode projects and workspaces
    (targets and product types, configurations, deployment targets, SDKs,
    Swift versions, bundle identifiers, teams, Swift packages, script
    phases).
- **Binary serialisations and data formats** (`common`), all in-house;
  self-describing formats are decoded to a bounded tree for the same
  report JSON gets (top-level type and keys, documents in a stream,
  inferred schema, value count, depth, tags and extension types), and
  string values go to the secret and privacy scan:
  - MessagePack, CBOR (indefinite lengths, tags, dates), BSON documents
    and `mongodump` streams (ObjectId time range), UBJSON, Smile (shared
    names and values), Amazon Ion binary and text (symbol tables,
    annotations), bencode with torrent facts (name, files, size, piece
    length, trackers, private flag, info hash), PHP `serialize()` output,
    Minecraft NBT (Java and Bedrock byte orders);
  - Python pickles by an opcode walk that never unpickles (protocol,
    globals with `STACK_GLOBAL` resolved through the memo, what the
    globals say it holds: pandas, NumPy, scikit-learn, PyTorch …) and Java
    serialization streams by their grammar (classes, objects, arrays,
    strings, enum constants, proxy interfaces); known gadget classes and
    pickle globals that run code report the new `unsafe_deserialization`
    risk, as do PHP gadget-chain classes;
  - Avro containers (writer schema, codec, blocks, records) and schemas,
    protobuf messages without a schema (field numbers and wire types,
    nested messages guessed, length-delimited streams), FlatBuffers binary
    schemas, generic BER / DER (element tree, tags, object identifiers),
    Android binary XML and `resources.arsc` (also inside APKs), Godot
    scenes and resources, Unity YAML assets and `.meta` files;
  - text data formats: RON, KDL, HOCON, EDN, S-expressions, protobuf text
    format; Thrift, Cap'n Proto, FlatBuffers, Dhall, Jsonnet and CUE are
    read as source languages (`.edn` moved from Clojure to the EDN reader).
- **Signatures:** a shared reader for DER (and the BER indefinite lengths
  Apple uses), X.509 certificates (subject, issuer, serial, validity, key
  algorithm, size and curve, signature algorithm, CA and path length, key
  usage, extended key usage, alternative names, SHA-256 and SHA-1
  fingerprints) and CMS `SignedData` (signer,
  digests, signing time, RFC 3161 and legacy countersignature timestamps).
  Signatures are described, not verified; key material is never reported.
- **Risks:** `packed_executable`, `writable_executable_memory`,
  `tls_callbacks`, `weakened_runtime`, `requests_elevation`,
  `obfuscated_code`, `unprotected_key` (a private or secret key stored
  without a passphrase) and `weak_cryptography` (RSA / DSA under 2048
  bits, MD5 or SHA-1 signatures, DES or RC4 Kerberos keys, unsigned
  tokens), `installs_root_certificate` (configuration profiles),
  `shell_action` (Shortcuts and Automator actions that run scripts) and
  `unsafe_deserialization` (pickle globals that run code, Java and PHP
  gadget classes); Mach-O and provisioning-profile `get-task-allow`
  reports `debuggable`. JWTs, TLS key logs and configuration profiles
  holding passwords report `embedded_secret`.
- **Plugin API:** `plugin::proplist` parses property lists with limits on
  depth and on the values shared references expand to (the `plist` crate
  guards against cycles only); `plugin::user_path` (hide the user name in
  profile paths) moved from the forensic group.
- **Fixes:** the DBF reader no longer reads past a header shorter than
  32 bytes or underflows on a dBASE 7 header shorter than 68 bytes (found
  by the fuzz smoke job).
- **Developer tools:** `scripts/fixtures/executables.sh` builds the
  executable fixtures with gcc, clang, mingw-w64, osslsigncode, makensis,
  wat2wasm and gdb (in a podman container) and with the macOS toolchain
  and codesign; `craft_executables.py` writes the MS-DOS, NE, LE and .NET
  headers. `exec_oracle.py` compares the reports with readelf,
  llvm-readobj, osslsigncode, wasm-objdump, lipo, otool and codesign.
  `scripts/fixtures/bytecode.sh` builds the bytecode fixtures with javac,
  d8, CPython 3.8 to 3.14, luac 5.1 to 5.4, LuaJIT, erlc, Emacs, mrbc,
  Ruby, ocamlc and the .NET SDK (in podman containers), and
  `bytecode_oracle.py` compares the reports with javap, CPython's
  `marshal` and `dis`, `beam_lib` and dnfile.
  `scripts/fixtures/crypto.sh` makes the crypto fixtures with openssl,
  ssh-keygen, puttygen, gpg, keytool, keepassxc-cli, age, minisign and
  signify (in a podman container), and `crypto_oracle.py` compares the
  reports with openssl, ssh-keygen, puttygen, gpg, keytool and klist.
  `scripts/fixtures/db.sh` makes the database fixtures with sqlite3, GDAL,
  the Python dbf package, Jackcess, DuckDB, LMDB, Berkeley DB, RocksDB,
  LevelDB, Redis, PostgreSQL, MariaDB and H2 (in a podman container), and
  `db_oracle.py` compares the reports with SQLite itself on 100 generated
  databases and system files, with ogrinfo, mdbtools and each engine's
  own tools.
  `scripts/fixtures/forensic.sh` takes MIT-licensed samples (Eric
  Zimmerman's test sets, rust-minidump's dumps) and makes the rest with
  text2pcap, editcap, hivexregedit, pylnk3, ntfs-3g, utmpdump and
  systemd-journal-remote (in podman containers); `forensic_oracle.py`
  compares the reports with python-evtx, regipy, LnkParse3,
  windowsprefetch, minidump, idstools and capinfos.
  `scripts/fixtures/apple.sh` makes the Apple fixtures with plutil,
  genstrings, actool, ditto and Swift on macOS (and openssl and ds_store
  in a podman container); `apple_oracle.py` compares the reports with
  plistlib, plutil, assetutil, `security cms` and ds_store over system
  folders and /Applications. `scripts/fixtures/binser.sh` makes the
  serialisation fixtures with each format's own library or tool
  (msgpack, cbor2, bson, py-ubjson, amazon.ion, bencode.py, nbtlib,
  pickle, fastavro, mktorrent, PHP, OpenJDK, Jackson, protoc, flatc,
  openssl), and `binser_oracle.py` checks generated documents against
  them.

## 0.5.1 — 2026-10-27

Software packages and installers, and disk images: Stage 5 is complete.
What was deliberately set aside is listed in
[`docs/known-gaps.md`](docs/known-gaps.md).

- **Packages:** one set of facts for every package format — ecosystem,
  name, version, release, architecture, summary and description, licence,
  authors or maintainer, homepage, repository, dependencies with their
  constraints, install-time scripts (`install_script` risk) and
  signatures — and the payload listed with the archive inventory (so the
  archive risks apply) and handed on within the limits:
  - Linux: Debian `.deb` / `.udeb` (control file, maintainer scripts,
    conffiles, the DEP-5 `copyright` licence, `debsigs` signatures), RPM
    (lead, signature and main headers: digests, OpenPGP signatures,
    scriptlets, requires / provides / conflicts / obsoletes / recommends,
    the file list from the header, the cpio payload), Arch `.pkg.tar.*`
    and Alpine `.apk` (`.PKGINFO`, install scripts, Alpine signatures),
    Slackware and FreeBSD `pkg`;
  - mobile: Android APK, App Bundle (protocol-buffer manifest), APK sets
    and XAPK (binary XML manifest: package, version code and name, SDK
    levels, permissions and which are dangerous, features, components and
    exported ones, the launcher activity, the label from `resources.arsc`,
    flags; v1 / v2 / v3 / v3.1 signing schemes; DEX files, native ABIs,
    Flutter / React Native / Xamarin / Unity), iOS IPA (`Info.plist`:
    bundle id, versions, minimum OS, devices, URL schemes, privacy usage
    keys; the provisioning profile: team, expiry, entitlements,
    distribution kind; code signature, FairPlay);
  - language ecosystems: npm tarballs and Rust crates (through the
    `code.manifest` mappings), Python wheels, source distributions and
    eggs (core metadata, wheel tags, commands, `.pth` start-up hooks),
    Ruby gems (the YAML specification; native extensions), Java JAR / WAR
    / EAR / AAR (manifest, Maven coordinates, JAR signatures, the Java
    release targeted, servlets, modules), NuGet (`.nuspec`, PowerShell
    install scripts), conda (`.conda` and `.tar.bz2`);
  - Windows: Windows Installer `.msi` / `.msm` / `.msp` (summary
    information, the Property table, file / component / feature counts and
    installed size, custom actions that run code, embedded cabinets handed
    on, Authenticode), MSIX / APPX and bundles (identity, publisher,
    device families, capabilities and the restricted ones);
  - macOS: installer packages `.pkg` / `.mpkg` and plain XAR (table of
    contents, Distribution: product, components, architectures, minimum
    OS, installer JavaScript; PackageInfo: identifier, install location,
    scripts; the gzip or `pbzx` cpio payload), disk images `.dmg` (UDIF
    trailer, partitions, chunk compression, licence agreement, encrypted
    images);
  - others: Helm charts, Docker / OCI image tarballs (tags, platform,
    entry point, environment with secrets redacted, ports, labels, layers;
    `runs_as_root`), VS Code / Visual Studio extensions (`.vsix`), Firefox
    `.xpi` and Chrome `.crx` (CRX2 / CRX3 header, signatures, extension
    id; WebExtension permissions and `broad_extension_permissions`),
    Electron `.asar`;
  - Linux bundles: Snap (`meta/snap.yaml`: apps, plugs and slots, base,
    grade, confinement; install hooks), AppImage (desktop entry, AppStream
    metadata, update information, signature section) and Flatpak
    `.flatpakref` / `.flatpakrepo`. Raw `.dmg` images now report their
    partition table and file systems.
- **Disk images** (feature `forensics`, which now includes `common`):
  every image reports its own facts and then what is on the disk, read
  without mounting it: the partition table (MBR with extended partitions,
  GPT with checksums, Apple Partition Map) and each partition's file
  system (ext2 / 3 / 4, FAT12 / 16 / 32, exFAT, NTFS, HFS / HFS+ / HFSX,
  APFS with its volumes, roles and encryption, btrfs, XFS, ISO 9660, UDF,
  squashfs, swap, LVM2, LUKS, BitLocker: label, UUID, sizes, free space,
  times, features). FAT, ext, ISO 9660, UDF, squashfs, Amiga and C64
  volumes are listed with the archive inventory and their files handed on.
  - raw disks and file-system images (`.img`, `.dd`, ext, FAT floppies,
    exFAT, NTFS, HFS+, APFS, LUKS);
  - optical discs: ISO 9660 (primary volume descriptor, Joliet and Rock
    Ridge names, El Torito boot entries, EFI boot images handed on,
    isohybrid partition tables), UDF (512- and 2048-byte blocks; checked on
    revisions 1.02, 1.50 and 2.01; metadata partitions of 2.50+ are read
    but untested on a real disc; write-once discs with a virtual partition
    are described, not listed), raw 2352-byte CD images (mode 1 and mode 2),
    CloneCD control files;
  - VM disks, read through their block maps: VirtualBox VDI, VMware VMDK
    (sparse, stream-optimised, descriptor files), VHD (fixed, dynamic,
    differencing with parent locators), VHDX, QEMU QCOW / QCOW2 (zlib and
    zstd clusters, snapshots, backing files, encryption) and QED, Apple
    `.sparseimage`; OVF descriptors and OVA appliances (product, vendor,
    guest OS, CPUs, memory, disks, networks; manifest, signature);
  - forensic evidence: EnCase / Expert Witness `.E01` (case metadata,
    acquisition software, dates and device, MD5 / SHA-1; the acquired disk
    read through its chunk tables) and AFF;
  - Android sparse images (expanded through their chunks) and boot images
    (header versions 0–4 and vendor boot: command line, OS version, patch
    level, kernel version; kernel, ramdisk and device tree handed on);
  - firmware: U-Boot legacy images (checksums checked, multi-file) and FIT
    images, Intel HEX, Motorola S-record, UEFI capsules (FMP images,
    signing, firmware versions);
  - home computers: Amiga OFS / FFS volumes (`.adf`, `.hdf`) and
    Commodore 1541 `.d64`.
- **Archives:** squashfs 4.0 (gzip, LZMA, xz and zstd; fragments,
  symbolic links), listed and its files handed on.
- **Risks:** `debuggable` (Android `debuggable`, iOS `get-task-allow`).
- **Fixes:** `code.manifest` no longer reports `build_script` for a
  Cargo manifest with `build = false`.
- **Developer tools:** `scripts/fixtures/packages.sh` makes the package
  fixtures with npm, cargo, setuptools, RubyGems, Helm, the JDK (jar,
  jarsigner), the Android build tools (aapt2, d8, zipalign, apksigner) and
  hdiutil; `craft_packages.py` writes the rest (Debian, RPM, Windows
  Installer, MSIX, NuGet, CRX3, IPA, XAR / `.pkg` …) with real signatures
  from throwaway keys. The tar and cpio readers are shared with the
  package extractors. `whiff-dev catalogue` matches formats by name as
  well as by extension, and long-tail formats already handled keep their
  stage. `scripts/fixtures/disks.sh` makes the disk image fixtures with
  the Linux tools (in a podman container: mkfs, mksquashfs, xorriso,
  mkudffs, cryptsetup, ewfacquire, mkbootimg, mkimage …), hdiutil and the
  macOS newfs tools, qemu-img, amitools and the d64 package;
  `craft_disks.py` writes the rest (AFF, raw CD sectors, CloneCD, a UEFI
  capsule, stand-in kernel and AppImage runtime). `disk_oracle.py`
  compares the reports with 7-Zip, qemu-img, hdiutil, blkid, ewfinfo,
  unsquashfs, mkimage, srec_info and unpack_bootimg.

## 0.5.0 — 2026-10-25

Archives and compressed files (packages and disk images to come).

- **Compressed files:** gzip (name, time, comment, operating system,
  level, extra subfields incl. BGZF and dictzip; several members), raw
  zlib, bzip2 (several streams), xz (check, filters, dictionary; streams,
  blocks and size from the index), `.lzma`, lzip, Zstandard (window,
  content size, dictionary id, checksum, skippable frames, seekable
  format), LZ4 (frame and legacy formats), Brotli, Unix `compress` (`.Z`)
  and the Snappy framing format are decompressed and the stream inside is
  analysed in turn, so `x.tar.gz` lists the tar's entries. The stream
  does not use up a recursion level (up to three nested layers). lzop and
  LZFSE headers are read. Declared and measured sizes, trailing data and
  decompression bombs are reported.
- **Archives:** ZIP (Zip64, extended-timestamp and NTFS times, Unix modes,
  ZipCrypto and WinZip AES, comment, the system that made it, a
  self-extractor or polyglot prefix; stored, deflate, bzip2, LZMA,
  Zstandard and xz entries handed on), tar (v7, ustar, pax with global
  and extended headers, GNU long names and sparse files; checksums
  verified), 7z (plain and packed headers, folders, coders, solid blocks,
  encrypted headers; copy, LZMA, LZMA2, deflate and bzip2 folders, with
  BCJ or delta filters, handed on), RAR 4 and 5 (volume, solid, recovery
  record, lock, encrypted headers, comment; stored entries handed on),
  Microsoft Cabinet (sets of cabinets, folders; uncompressed and MSZIP
  folders handed on), LHA (header levels 0–2), ARJ, cpio (newc, crc, odc,
  binary) and `ar` (GNU and BSD names, symbol tables). Every archive
  reports the same inventory: entry, file, folder and link counts, sizes
  and ratio, methods, encrypted entries, file types, top-level folders,
  the range of modification times and the first 50 entries. ZIP names
  without the UTF-8 flag are read as code page 437.
- **Risks:** `path_traversal`, `absolute_path`, `symlink_escape`,
  `decompression_bomb` and `overlapping_entries` (Fifield's overlapping
  zip bomb), plus `double_extension` for archive entries; `trailing_data`
  now also covers archives and compressed streams.
- **Engine and plugin API:** `plugin::codec` decodes every codec above
  into at most a given number of bytes, charged to the decompression
  budget, with memory bounded by the output (LZMA dictionaries are never
  larger than it); `Context::decompress`, `decompress_mszip`,
  `emit_inner` (the stream inside a compressed file), `emit_child_prefix`
  (the start of a larger entry) and `child_room`. The ZIP reader reads
  extra fields, more methods and entries' first bytes
  (`Zip::read_prefix`). New dependencies, all pure Rust: `ruzstd`,
  `lzma-rust2` and `brotli-decompressor` (132 of 185 for the library).
- **Tests:** `tests/bombs.rs` checks that a 1 GiB zip bomb, a 42.zip-style
  nest of them (256 GiB in all), an overlapping-entry bomb, archives whose
  paths leave the target folder and a deep gzip-in-gzip chain are all
  reported within the limits; the inputs are built in memory, not kept as
  fixtures.
- **Developer tools:** `scripts/fixtures/archives.sh` regenerates the
  archive and compression fixtures with bsdtar, Info-ZIP, 7-Zip, Python's
  zipfile and tarfile, gzip, bzip2, xz, zstd, lz4, brotli, compress and
  `compression_tool`; `craft_archives.py` writes RAR, CAB, LHA, ARJ, lzip,
  Snappy, lzop and BGZF files (checked with `7zz t`).
  `archive_corpus.sh` builds a larger corpus from system folders with
  every method each tool offers, and `archive_oracle.py` compares entry
  counts, paths, types and sizes with 7-Zip's listing and uncompressed
  sizes with the reference decompressors.

## 0.4.0 — 2026-10-22

Audio, video, subtitles, playlists and scores.

- **Audio** (in-house readers, no new dependencies): MP3 / MP2 / MP1
  (frame header, Xing / Info / VBRI and LAME tags, duration from the VBR
  header, the CBR size or a bounded frame walk), AAC (ADTS) and MPEG-4
  audio (M4A, M4B, M4P, M4R: AAC profile, ALAC, Opus, FLAC, AC-3, AMR),
  FLAC (STREAMINFO, cue sheet, seek table, pictures), Ogg Vorbis / Opus /
  Speex / FLAC (headers reassembled across pages, duration from the last
  granule), WAV, Broadcast Wave (`bext`, iXML), RF64 / BW64 and Wave64,
  AIFF / AIFF-C, CAF (packet table, `info`), WMA (ASF header objects, DRM),
  WavPack, Monkey's Audio, Musepack SV7 / SV8, TTA, DSF and DSDIFF, AMR,
  Sun AU and Creative VOC. Streams report codec, profile, sample rate,
  channels and layout, bit depth, bitrate and CBR / VBR. HE-AAC reports
  its output rate and channels from the AudioSpecificConfig (SBR / PS
  signalling included), not the sample entry's. Durations, sample rates
  and channel counts agree with `ffprobe` on every fixture and on 6 615
  audio files found on a Mac (system sounds, ringtones, voice prompts,
  GarageBand and application content). Durations are the presentation
  length: the encoder priming and padding an MP4 edit list or CAF packet
  table marks are left out, where ffprobe keeps them (497 of those files).
- **Video** (in-house readers, no new dependencies): MP4 / M4V / MOV / 3GP
  / F4V / CMAF (fragmented files' durations from `mehd` or the `moof`
  run tables), Matroska / WebM / MKA / MKS (EBML; seek head, chapters,
  tags, attachments; the duration from the last cluster when the header
  has none), AVI and OpenDML, MPEG transport streams (TS, BDAV M2TS:
  PAT / PMT / SDT, stream types and descriptors, scrambling) and program
  streams (MPEG-1, MPEG-2, DVD VOB with private-stream audio and
  subpictures), FLV (AMF0 `onMetaData`, enhanced-RTMP FourCCs), WMV,
  RealMedia, Ogg Theora, and elementary streams (H.264, HEVC, MPEG-1 / 2
  video, AV1 OBU, IVF, YUV4MPEG2). Each stream reports codec and tag,
  profile, level and tier, size, display size, sample and display aspect
  ratios, frame rate and CFR / VFR, frame count, bit depth, chroma
  subsampling, colour primaries / transfer / matrix / range, HDR format
  (HDR10, HLG, Dolby Vision), mastering display and content light level,
  scan type and field order, rotation, stereo mode, bitrate, language,
  title, and default / forced flags, read from the container and the
  codec configuration (H.264 / HEVC parameter sets with VUI, `avcC`,
  `hvcC`, `av1C` and the AV1 sequence header, `vpcC` and VP8 / VP9 key
  frames, MPEG-1 / 2 sequence headers and extensions, MPEG-4 Part 2
  profiles, `colr`, `pasp`, `mdcv`, `clli`, `dvcC`). TS and PS durations
  come from the first and last presentation time stamps. Camera make,
  model and software go to `format.device`, QuickTime / ISO 6709
  locations to `content.location`, the QuickTime creation date to the
  captured date, and MP4 XMP to the XMP decoder. Durations, sizes,
  frame rates and codecs agree with `ffprobe` on 2 052 video files that
  ship with macOS and installed applications (one duration differs: an
  edit list that ends a track after the movie header's length).
- **Subtitles** (in-house readers, no new dependencies): SubRip, WebVTT,
  ASS / SSA, TTML (TTML 1 / 2, DFXP, IMSC, SMPTE-TT, EBU-TT: clock, frame,
  tick and offset times, nested time containers, agents), SAMI (classes
  and their languages), YouTube SBV, srv1 / srv2 / srv3 and json3,
  SubViewer 1 and 2, Spruce STL, MicroDVD, MPL2, LRC (ID tags, offsets,
  word times), Scenarist SCC (a CEA-608 decoder for pop-on, roll-up and
  paint-on captions), EBU STL (GSI titles, language, dates and counts; ISO
  6937 and ISO 8859 text), Blu-ray PGS and the VobSub index. Each reports
  the cue count, the first cue and the end of the last, language, title
  and author, styles and fonts, speakers, the frame rate, the markup used,
  sound-description and music cues, overlapping and out-of-order cues, and
  the format's header fields, and hands the transcript to the text
  analyzers. Codecs, cue counts and end times agree with `ffprobe` on 51
  of 52 files (the fixtures, ffmpeg's own subtitle test samples and the
  Sintel subtitles; the miss is a trimmed VobSub sample whose index points
  past its picture data). Where ffmpeg reads a format differently (it
  drops SubViewer cues whose text starts with `[`, reads LRC millisecond
  fractions and Spruce STL frames as hundredths), whiff follows the format.
- **Playlists** (in-house readers): M3U and extended M3U (IPTV attributes
  and groups), HLS master playlists (variants with bandwidth, resolution,
  codecs, frame rate and video range; renditions; I-frame variants;
  session data) and media playlists (segments and total duration, target
  duration, VOD / live, fMP4 / TS / packed audio, byte ranges, gaps,
  encryption and key formats, program date-times, ad markers,
  low-latency parts), PLS, XSPF, ASX, WPL / ZPL, CUE sheets (catalogue
  number, REM fields, files, tracks with ISRCs and index times, disc
  images), MPEG-DASH (type, duration, periods, adaptation sets,
  representations, segment addressing, DRM systems) and Smooth Streaming
  client manifests. Entries report titles, artists, albums and durations;
  locations only by file name and host, since paths name folders and users
  and query strings can carry access tokens. Remote entries count as
  external references; HLS keys and DRM systems set `security.encrypted`.
- **Subtitle text in video files:** the text of SubRip, ASS / SSA and
  WebVTT tracks in Matroska and WebM (zlib and header-stripping
  compression included), and of 3GPP timed text, QuickTime text and
  WebVTT tracks in MP4 / MOV, is read into cues. Each subtitle stream
  reports its cue count and the end of its last cue, and the text of one
  track (the default one that is not forced) goes to the text analyzers.
  Matroska blocks of other tracks are skipped by their headers; the walk
  is skipped in the `minimal` profile and stops at its block, byte and
  time limits with a warning.
- **Scores** (in-house readers): Standard MIDI files (formats 0, 1 and 2),
  karaoke `.kar` and RIFF MIDI: division, tracks with names and
  instruments, the tempo map and the duration it gives, time and key
  signatures, General MIDI program names, percussion, note counts, GM /
  GM2 / GS / XG, markers (as chapters), cue points, copyright and lyrics.
  Tracker modules (MOD, XM, S3M, IT, MPTM): title, tracker, channels,
  orders, patterns, instrument and sample names, the IT song message, and
  the length of one pass, from a walk of the patterns for the commands
  that change timing. Notation: MusicXML (partwise and timewise) and
  compressed MXL, MEI, MuseScore (`.mscx`, `.mscz`), Guitar Pro 3 to 5,
  ABC (tune books too) and LilyPond: title, composer and other creators,
  rights, software, parts with instruments, staves, measures, notes and
  rests, key, time signature, tempo, repeats, length in quarter notes
  (seconds when a tempo is marked) and lyrics. MIDI durations agree with
  mido on every fixture and on 100 corpus scores rendered by music21; on
  music21's corpus (627 MusicXML / MXL scores, 1 146 ABC files) staves,
  measures and ABC tune counts agree on all, notes on 99.8 % and lengths
  in quarter notes on 97.1 %. `.abc` Alembic, `.mod` DTD and `.gpx` GPS
  files are not mistaken for scores.
- **Tags:** ID3v1 / v1.1 and ID3v2.2–2.4 (unsynchronisation, compressed
  and grouped frames, iTunes' non-syncsafe sizes, CHAP / CTOC chapters),
  Vorbis comments, APEv1 / v2, iTunes `ilst` (with free-form `----` items
  and QuickTime `keys`), RIFF `INFO`, ASF / `WM/` attributes, AIFF text
  chunks, CAF `info` and DSDIFF edited-master data are kept in their own
  names under `metadata.<standard>` and normalised into `format.tags`
  (title, artist, album, track / disc and totals, dates, genre, composer,
  label, ISRC, BPM, key, MusicBrainz ids, ReplayGain…), which fills
  `content`, `rights` and `temporal`. Cover art is described and handed
  on as an embedded file; chapters fill `format.chapters` and the outline;
  lyrics go to the text analyzers. A purchaser's Apple ID or name
  (`apID`, `ownr`) goes through the privacy setting.
- **Containers:** `plugin::mp4` (ISO base media: tracks, sample tables,
  `esds`, `ilst`, chapters, visual sample entries and their configuration
  boxes, protection schemes, movie fragments, subtitle text samples, XMP)
  and `plugin::asf` (ASF
  header objects, extended stream properties, language list) are shared
  by the audio and video extractors; the HEIF extractor uses
  `plugin::mp4`'s box iterator. A WMA file with a video stream is handed
  to the WMV extractor, and an Ogg file with a Theora stream is reported
  as Ogg video.
- **Developer tools:** `scripts/fixtures/scores.sh` regenerates the score
  fixtures with mido, music21, verovio and pyguitarpro;
  `craft_scores.py` writes the tracker modules, RIFF MIDI, ABC, LilyPond
  and MuseScore files; `score_oracle.py` compares whiff with music21 and
  mido. `whiff-dev oracle subtitles` compares subtitle
  codecs, cue counts and the end of the last cue with `ffprobe`'s packets
  (gate: 98 % of cue counts). `scripts/fixtures/subtitles.sh` regenerates
  the subtitle and playlist fixtures with ffmpeg, GStreamer, pysubs2,
  pycaption, the m3u8 library and metaflac; `craft_subtitles.py` writes
  the formats none of them does (SBV, SubViewer, Spruce STL, YouTube timed
  text, EBU STL, PGS, VobSub, hand-written playlists).
  `whiff-dev oracle media` compares durations,
  sample rates and channel counts, and the first video stream's codec,
  size and frame rate, with `ffprobe` (gate: 98 % of durations within
  0.1 s; mono HE-AAC, which ffmpeg decodes to stereo, counts as agreeing).
  `scripts/fixtures/video.sh` regenerates the video fixtures with ffmpeg,
  GStreamer's own muxers, the x264 / x265 encoders, VideoToolbox and
  `avconvert`. `scripts/fixtures/audio.sh` regenerates the audio
  fixtures with ffmpeg, LAME, flac / metaflac, speexenc, mpcenc and Core
  Audio's `afconvert`; `craft_audio.py` writes the iXML chunk and the
  Monkey's Audio, DSF and DSDIFF files no available tool writes.

## 0.3.0 — 2026-10-18

Documents, e-mail, calendars and contacts.

- **PDF** (in-house parser): cross-reference tables and streams, object
  streams, incremental updates, and a repair scan for damaged files; RC4 and
  AES (128 and 256) decryption with the empty user password, so files
  encrypted only to set permissions are read in full. Reports the Info
  dictionary, XMP, page count and sizes, outline (as headings), fonts,
  images, annotations, AcroForm / XFA fields, signatures, PDF/A, /UA and /X
  claims, permissions and per-page text. JavaScript, automatic actions,
  launch actions, form submission, remote go-to actions and executable
  attachments are `security.risks`; embedded files become children. FDF
  field names too.
- **Office Open XML** (Word, Excel, PowerPoint, Visio, with their
  templates, macro-enabled and show variants, and XLSB): core, app and
  custom properties, sensitivity labels, outline, comments, tracked changes,
  fields, hyperlinks, sheets, slides, notes and text. Macros (VBA source
  decompressed and scanned), auto-run procedures, DDE fields, external
  templates and OLE links, Excel 4.0 macro sheets and remote images are
  risks; embeddings become children.
- **OpenDocument** (text, spreadsheet, presentation, drawing, formula,
  database, chart, master document, templates and flat XML): `meta.xml`,
  outline, text, comments, tracked changes, StarBasic macros and the events
  that run them, encryption.
- **Legacy Office and other compound files** (in-house CFB and property-set
  readers): Word 97–2003 text through the piece table and its fields, Excel
  97–2003 sheets and shared strings, PowerPoint 97–2003 slide titles and
  text, Visio, Publisher, Project, Hangul HWP, Thumbs.db, VBA projects and
  encrypted OOXML containers; macros, embedded objects and Equation Editor
  objects are flagged.
- **RTF** (in-house): the `\info` group, fonts, styles and outline, text in
  every code page, comments, fields and links, pictures, tracked changes and
  protection; embedded OLE objects become children, and linked or
  auto-updating objects, DDE fields and remote includes are risks.
- **Ebooks:** EPUB 2 / 3 (OPF metadata, creators and roles, identifiers
  with ISBN checks, series, navigation document or NCX, cover, DRM and font
  obfuscation, reading-order text), Mobipocket / Kindle MOBI, AZW and AZW3
  (EXTH records, PalmDOC-compressed text), PalmDOC, FictionBook (FB2, FBZ)
  and comic book ZIPs with `ComicInfo.xml`.
- **E-mail:** EML, mbox, MHTML and Apple Mail EMLX (via `mail-parser`) and
  Outlook MSG (in-house, including compressed RTF bodies): addresses,
  dates, Received hops, SPF / DKIM / DMARC verdicts, lists, S/MIME and PGP,
  body text and attachments as children. Phishing signals are risks: a
  Reply-To on another domain, a display name naming a different address,
  link text naming another site, failed authentication, risky attachment
  names (executables, double extensions, macro documents) and password
  forms.
- **Calendars and contacts** (in-house RFC 5545 / 6350 parsers): iCalendar
  and vCalendar events, to-dos, recurrence, time zones, organizers and
  attendees, date range and alarms that run a procedure; vCard 2.1 / 3.0 /
  4.0 names, organisations, titles, e-mail domains, phone and address
  counts.
- **PostScript and EPS** (DSC comments, previews, XMP, shown text) and
  **BibTeX** (entries, types, years, DOIs). LaTeX sources now also report
  class options, packages, the abstract, included files, figure / table /
  citation counts and the body text.
- **Privacy:** `--privacy strict` (the default) keeps only the domain of an
  e-mail address and counts phone numbers and street addresses;
  `--privacy off` lists them.
- **Engine:** a container extractor can hand a file to the format it found
  inside (`detected_by: content`), so compound files are routed to Word,
  Excel, Outlook and the rest by their streams.
- **Risk categories and severities:** every `security.risks[]` entry now
  has a `category` (`active_content`, `phishing`, `external_reference`,
  `exploit`, `obfuscation`, `data_exposure`, `supply_chain`,
  `unsafe_operation`, `provenance`) and a `severity` (`info`, `low`,
  `medium`, `high`), both decided by the kind in one vocabulary
  (`src/report/risk.rs`, listed in the generated `docs/risks.md`).
  `security.risk_level` is the highest severity of a file and everything
  embedded in it; `security.embedded_risks` counts embedded files' risks by
  kind, at any depth. The LLM view shows the level and each risk's
  severity. Kinds outside the vocabulary (third-party extractors) are
  `other` / `medium`; the conformance suite fails on any in whiff.
- **Report schema:** new `DateField` values `printed`, `sent` and
  `received`, `DetectedBy::Content`, and the risk fields above (additive;
  still `whiff/1`).
- **Pure-Rust check:** `whiff-dev check-deps` fails on `-sys` crates and
  native build tools in the library's and CLI's dependency graph, and CI
  checks that the published crate holds no development tooling.
- **Developer tools:** `scripts/fixtures/documents.sh` regenerates the
  document fixtures with textutil, Ghostscript, Core Graphics and poppler,
  third-party writers (rust_xlsxwriter, simple_excel_writer, docx-rs and
  ppt-rs in `scripts/fixtures/office_gen`; Apache POI for BIFF8 workbooks,
  PowerPoint 97 slide shows and genuinely encrypted xls, ppt and OOXML),
  plus standard-library generators for the formats no local tool writes.
  Files from these independent writers showed and fixed: a false macro
  risk on every PowerPoint-saved `.ppt` (the VBA-info record is present
  without a project), slides lost after a record whose length overruns its
  container, master-slide placeholders read as slide text, packed string
  vectors in property sets (PowerPoint's `TitlesOfParts`), sheet names read
  from encrypted BIFF records, and encrypted OOXML whose directory is not
  contiguous left as a plain compound file. Excel cell notes and threaded
  comments are now counted, with their authors.
- **Release:** the release workflow now pushes the Homebrew formula and
  Scoop manifest to `baoulo/homebrew-tap` and `baoulo/scoop-bucket`, and
  publishes to crates.io only once that has succeeded.

## 0.2.0 — 2026-10-17

Images and embedded metadata blocks.

- **Image extractors (41 formats):** JPEG (JFIF, EXIF, XMP and extended
  XMP, ICC, MPF, Photoshop IRB, Adobe, quality estimate, Ultra HDR, C2PA),
  PNG / APNG, GIF, WebP, BMP, ICO / CUR, TIFF / BigTIFF, HEIC / HEIF / AVIF,
  JPEG XL, JPEG 2000 (JP2 and codestreams), TGA, PCX, Netpbm, QOI, Radiance
  HDR, OpenEXR, DDS, KTX / KTX2, Photoshop PSD / PSB (layers), GIMP XCF, SVG
  / SVGZ, EMF / WMF, and camera raw: DNG, CR2, CR3, NEF, ARW, ORF, RW2, PEF,
  RAF, SRW. Headers and structure only; pixels are never decoded.
- **Metadata blocks:** EXIF, XMP, IPTC-IIM, ICC profiles and Photoshop
  image resources are decoded wherever they are embedded, into
  `metadata.exif`, `metadata.xmp`, `metadata.iptc`, `metadata.icc` and
  `metadata.photoshop`.
- **Normalisation (MWG):** title, description, creators, copyright,
  keywords, credit, licence, capture / digitisation / modification dates and
  GPS location are reconciled across XMP, IPTC and EXIF with the Metadata
  Working Group's precedence rules (including the IPTC digest check).
- **AI provenance:** Stable Diffusion, ComfyUI and InvokeAI generation
  parameters in PNGs, and the IPTC `DigitalSourceType` for generated media,
  are reported; the prompt becomes the description and `security.risks`
  flags the image as AI-generated. C2PA manifests set `security.signed`.
- **SVG risks:** scripts, event handlers, `foreignObject`, external
  references and entity declarations are flagged.
- **Developer tools:** `whiff-dev oracle images` compares the normalised
  fields with `exiftool -use MWG`; `scripts/fixtures/` regenerates the image
  fixtures and a 200-image oracle corpus.
- MSRV is now Rust 1.89.

Fixes:

- Reports read from stdin no longer carry the source name `-`.
- The LLM view no longer lowercases date values (`T` and `Z` came out as
  `t` and `z`).

## 0.1.0 — 2026-10-16

First release.

- **Report:** one JSON document per file (`whiff/1`) with fixed sections —
  identification, system, temporal, security, rights, physical, integrity,
  content, metadata, format, embedded, diagnostics — and a JSON Schema
  (`whiff schema`).
- **Every file:** detection (registered extractors, then a ~1000-signature
  database), filesystem identity and times, permissions with owner names,
  extended attributes (macOS quarantine, "Where from", Finder tags; Windows
  `Zone.Identifier`), SHA-256 and BLAKE3, entropy, and `wc`-compatible counts
  for text.
- **Extractors (79 formats):** plain text, logs, diffs, Markdown, HTML,
  XML, RSS / Atom / JSON Feed / OPML / sitemaps, JSON / NDJSON / JSON5, YAML,
  TOML, INI / properties / dotenv, CSV / TSV, SQL, 43 programming languages,
  package manifests (npm, Cargo, Python, Go, Maven), Jupyter notebooks,
  Dockerfiles, Makefiles and unknown binary data. About 20 well-known
  configuration schemas are recognised (OpenAPI, Kubernetes, GitHub Actions,
  Docker Compose, HAR, SARIF, …).
- **Content analysis:** language, keywords, keyword frequency, outline,
  excerpt and summary; `--profile llm` prints a compact, token-budgeted view.
- **Privacy:** secrets are counted and redacted; personal data is counted,
  never listed.
- **Safety:** pure Rust with `unsafe` forbidden; read, decompression and time
  budgets; contained panics; nesting limits before recursive parsers; a
  watchdog for extractors that ignore their deadline; fuzzed.
- **Library:** `whiff::Engine` with profiles and limits; a plugin API for
  adding formats in one file, with an automatic conformance suite.
