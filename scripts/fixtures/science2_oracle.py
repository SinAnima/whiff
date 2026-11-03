"""Compare whiff's reports for the second science set (arrays, statistics,
chemistry, instruments, medical) with each format's own library.

    # in `whiff-science2`: build a corpus and the expected facts
    python3 science2_oracle.py expect OUT_DIR
    # in `whiff-science-r`: R's own facts for the .rds / .rda files
    Rscript science_oracle.R OUT_DIR
    # on the host
    python3 science2_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is the test data shipped inside the installed packages (SciPy
MAT files, pyreadstat SAV, the rdata package's RDS / RDA, pydicom, nibabel,
pyEDFlib, scikit-rf, npTDMS, RDKit, eccodes samples) plus generated files
(NPY of every dtype and order, NPZ, SAV re-written as DTA, XPORT and POR,
NIfTI-1 / 2 and Analyze, NRRD, EDF+ / BDF+, Touchstone, TDMS, SDF), copied
into OUT_DIR/corpus. R's own library files are added by the R step.
Nothing here ships with whiff.
"""

import glob
import json
import os
import random
import shutil
import subprocess
import sys

R = random.Random(7)
# Corpus files not compared, and why.
SKIP = {
    "scipy__io__matlab__tests__data__debigged_m4.mat": "a 134217728-row matrix in 2 KB (scipy reads the header only)",
}
SITE = "/usr/local/lib/python3.12/site-packages"
EXTS = (".npy", ".npz", ".mat", ".sav", ".zsav", ".dta", ".xpt", ".por", ".rds", ".rda", ".rdata", ".dcm", ".nii",
        ".hdr", ".nrrd", ".nhdr", ".edf", ".bdf", ".s1p", ".s2p", ".s3p", ".s4p", ".tdms", ".sdf", ".mol", ".grib")


def generate(c):
    import numpy as np

    # NPY: dtypes, orders, versions; NPZ.
    for i, dt in enumerate(["<f4", ">f8", "<i2", "|u1", "|b1", "<c16", "<U7", "|S3", "<M8[s]", "<i8"]):
        a = np.zeros(tuple(R.randint(1, 6) for _ in range(R.randint(0, 3))), dtype=dt)
        if R.random() < 0.4 and a.ndim > 1:
            a = np.asfortranarray(a)
        with open(f"{c}/gen-{i}.npy", "wb") as fh:
            np.lib.format.write_array(fh, a, version=R.choice([(1, 0), (2, 0), (3, 0)]))
    for i in range(4):
        arrs = {f"v{j}": np.arange(R.randint(1, 50)) for j in range(R.randint(1, 6))}
        (np.savez_compressed if i % 2 else np.savez)(f"{c}/gen-{i}.npz", **arrs)
    # Statistics: random frames as SAV / ZSAV, DTA (every version), XPORT
    # (v5 and v8) and POR.
    import pandas as pd
    import pyreadstat

    for i in range(24):
        cols = {}
        for j in range(R.randint(1, 30)):
            n = f"v{j}" if R.random() < 0.7 else f"col_{j}"
            cols[n] = [R.random() for _ in range(5)] if R.random() < 0.6 else [R.choice(["a", "bb", ""]) for _ in range(5)]
        df = pd.DataFrame(cols).iloc[: R.randint(0, 5)]
        labels = [f"label {n}" if R.random() < 0.7 else None for n in df.columns]
        kind = ["sav", "zsav", "dta", "xpt", "por"][i % 5]
        fn, kw = {"sav": (pyreadstat.write_sav, {}), "zsav": (pyreadstat.write_sav, {"compress": True}),
                  "dta": (pyreadstat.write_dta, {"version": R.choice(range(8, 16))}),
                  "xpt": (pyreadstat.write_xport, {"file_format_version": R.choice([5, 8])}),
                  "por": (pyreadstat.write_por, {})}[kind]
        try:
            fn(df, f"{c}/gen-{i}.{kind}", column_labels=labels, **kw)
        except Exception:
            pass
    # NIfTI-1 / 2 and Analyze.
    import nibabel as nib

    for i, dt in enumerate([np.uint8, np.int16, np.int32, np.float32, np.float64, np.int8, np.uint16, np.int64]):
        shape = tuple(R.randint(1, 9) for _ in range(R.randint(2, 5)))
        data = np.zeros(shape, dtype=dt)
        kind = [nib.Nifti1Image, nib.Nifti2Image, nib.AnalyzeImage][i % 3]
        if kind is nib.AnalyzeImage and dt not in (np.uint8, np.int16, np.int32, np.float32, np.float64):
            kind = nib.Nifti1Image
        img = kind(data, np.eye(4)) if kind is nib.AnalyzeImage else kind(data, np.eye(4), dtype=dt)
        nib.save(img, f"{c}/gen-{i}.{'hdr' if kind is nib.AnalyzeImage else 'nii'}")
    # NRRD: encodings and types.
    import nrrd

    for i, (dt, enc) in enumerate([(np.float32, "gzip"), (np.uint8, "raw"), (np.int16, "ascii"), (np.float64, "raw"),
                                   (np.uint16, "gzip"), (np.int32, "bzip2")]):
        shape = tuple(R.randint(1, 8) for _ in range(R.randint(1, 4)))
        nrrd.write(f"{c}/gen-{i}.nrrd", np.zeros(shape, dtype=dt), {"encoding": enc})
    # EDF+ / BDF+.
    import pyedflib

    for i in range(4):
        bdf = i % 2 == 1
        n = R.randint(1, 5)
        p = f"{c}/gen-{i}.{'bdf' if bdf else 'edf'}"
        w = pyedflib.EdfWriter(p, n, file_type=pyedflib.FILETYPE_BDFPLUS if bdf else pyedflib.FILETYPE_EDFPLUS)
        rate = R.choice([10, 50, 100])
        w.setSignalHeaders([{"label": f"ch{j}", "dimension": "uV", "sample_frequency": rate, "physical_max": 100,
                             "physical_min": -100, "digital_max": 32767, "digital_min": -32768} for j in range(n)])
        secs = R.randint(1, 12)
        w.writeSamples([np.zeros(rate * secs) for _ in range(n)])
        w.close()
    # Touchstone.
    import skrf

    for i in range(4):
        ports = R.randint(1, 4)
        f = skrf.Frequency(1, 3, R.randint(2, 30), unit="GHz")
        s = np.zeros((len(f), ports, ports), dtype=complex)
        skrf.Network(frequency=f, s=s).write_touchstone(f"{c}/gen-{i}")
    # TDMS.
    from nptdms import ChannelObject, TdmsWriter

    for i in range(3):
        with TdmsWriter(f"{c}/gen-{i}.tdms") as w:
            for g in range(R.randint(1, 3)):
                w.write_segment([ChannelObject(f"g{g}", f"c{k}", np.arange(10.0)) for k in range(R.randint(1, 4))])
    # SDF.
    from rdkit import Chem

    smiles = ["CCO", "c1ccccc1", "NCC(=O)O", "O=C=O", "CC(C)Cc1ccc(cc1)C(C)C(=O)O", "C1CCCCC1", "N#N"]
    for i in range(3):
        w = Chem.SDWriter(f"{c}/gen-{i}.sdf")
        for s in R.sample(smiles, R.randint(1, len(smiles))):
            w.write(Chem.MolFromSmiles(s))
        w.close()
    # GRIB: the eccodes samples.
    for p in glob.glob("/usr/share/eccodes/samples/GRIB*.tmpl"):
        shutil.copy(p, f"{c}/eccodes-{os.path.basename(p)[:-5]}.grib")


def facts(p):
    low = p.lower()
    ext = os.path.splitext(low)[1]
    if ext == ".npy":
        import numpy as np

        with open(p, "rb") as fh:
            v = np.lib.format.read_magic(fh)
            read = np.lib.format.read_array_header_1_0 if v == (1, 0) else np.lib.format.read_array_header_2_0
            shape, fortran, dt = read(fh)
        f = {"shape": list(shape), "order": "F" if fortran else "C"}
        if dt.fields is None and dt.kind != "O":  # Python 2 headers say `|O8`
            f["descr"] = dt.str
        return f
    if ext == ".npz":
        import numpy as np

        return {"array_names": sorted(n[:-4] if n.endswith(".npy") else n for n in np.load(p).files)}
    if ext == ".mat":
        import scipy.io

        with open(p, "rb") as fh:
            head = fh.read(128)
        if head[124:128] in (b"\x00\x02IM", b"\x02\x00MI") or b"MATLAB 7.3" in head:
            if b"MATLAB 7.3" in head:
                return None  # HDF5: compared in part 3a
        # SciPy squeezes char arrays to a list of strings: those are not compared.
        return {"variable_shapes": {n: "x".join(map(str, s)) for n, s, c in scipy.io.whosmat(p) if c != "char"}}
    if ext in (".sav", ".zsav", ".dta", ".xpt", ".por"):
        import pyreadstat

        with open(p, "rb") as fh:
            if ext == ".sav" and fh.read(4) != b"$FL2":
                return None  # an IDL save file

        fn = {".sav": pyreadstat.read_sav, ".zsav": pyreadstat.read_sav, ".dta": pyreadstat.read_dta,
              ".xpt": pyreadstat.read_xport, ".por": pyreadstat.read_por}[ext]
        _, m = fn(p, metadataonly=True)
        f = {"variable_names": list(m.column_names)}
        if ext in (".sav", ".zsav", ".dta") and m.number_rows not in (None, -1):
            f["rows"] = m.number_rows
        return f
    if ext == ".dcm":
        import pydicom

        with open(p, "rb") as fh:
            if fh.read(132)[128:] != b"DICM":
                return None
        d = pydicom.dcmread(p, stop_before_pixels=True)
        return {"modality": d.get("Modality"), "rows": d.get("Rows"), "columns": d.get("Columns"),
                "sop_class_uid": str(d.SOPClassUID) if "SOPClassUID" in d else None}
    if ext in (".nii", ".hdr"):
        import nibabel as nib

        img = nib.load(p)
        h = img.header
        dt = h.get_data_dtype()
        f = {"shape": "x".join(str(n) for n in h.get_data_shape())}
        if dt.fields is None:
            f["datatype"] = dt.name
        return f
    if ext in (".nrrd", ".nhdr"):
        import nrrd

        h = nrrd.read_header(p)
        return {"type": h.get("type"), "encoding": h.get("encoding"), "sizes": " ".join(str(int(n)) for n in h["sizes"])}
    if ext in (".edf", ".bdf"):
        import pyedflib

        r = pyedflib.EdfReader(p)
        try:
            return {"signals": r.signals_in_file, "records": r.datarecords_in_file}
        finally:
            r.close()
    if ext in (".s1p", ".s2p", ".s3p", ".s4p"):
        import skrf

        n = skrf.Network(p)
        return {"ports": n.nports, "frequency_points": len(n.frequency)}
    if ext == ".tdms":
        from nptdms import TdmsFile

        t = TdmsFile.read_metadata(p)
        return {"groups": [g.name for g in t.groups()], "channel_count": sum(len(g.channels()) for g in t.groups())}
    if ext == ".sdf":
        from rdkit import Chem

        return {"molecules": len(Chem.SDMolSupplier(p, sanitize=False, removeHs=False))}
    if ext == ".mol":
        from rdkit import Chem

        m = Chem.MolFromMolFile(p, sanitize=False, removeHs=False)
        return {"atoms": m.GetNumAtoms(), "bonds": m.GetNumBonds()}
    if ext == ".grib":
        import eccodes

        eds, n = set(), 0
        with open(p, "rb") as fh:
            while (h := eccodes.codes_grib_new_from_file(fh)) is not None:
                n += 1
                eds.add(eccodes.codes_get(h, "edition"))
                eccodes.codes_release(h)
        return {"messages": n, "editions": sorted(eds)}
    return None


def cmd_expect(out):
    c = os.path.join(out, "corpus")
    shutil.rmtree(c, ignore_errors=True)
    os.makedirs(c)
    generate(c)
    for p in glob.glob(f"{SITE}/**/*", recursive=True):
        low = p.lower()
        shipped = "test" in p[len(SITE):] or "/skrf/data/" in p
        if os.path.isfile(p) and low.endswith(EXTS) and shipped and os.path.getsize(p) < 64 << 20:
            shutil.copy(p, os.path.join(c, p[len(SITE) + 1:].replace("/", "__")))
    rows = []
    for name in sorted(os.listdir(c)):
        p = os.path.join(c, name)
        if name.lower().endswith((".rds", ".rda", ".rdata")):
            continue  # science_oracle.R
        try:
            f = facts(p)
        except Exception as e:  # recorded, not compared
            f = {"oracle_error": f"{type(e).__name__}: {e}"[:200]}
        if f is not None:
            rows.append({"path": os.path.relpath(p, out), "facts": f})
    with open(os.path.join(out, "expected.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
    print(f"{len(rows)} files written to {out}/expected.jsonl")


def got(d, want):
    """whiff's values for the oracle's keys."""
    g = {}
    for k in want:
        if k == "array_names":
            g[k] = sorted(d.get("arrays", {}))
        elif k == "variable_shapes":
            g[k] = {n: (v.split() + ["?"])[1] for n, v in d.get("variables", {}).items() if not v.startswith("char ")}
        elif k == "variable_names":
            v = d.get("variables") or (d.get("members") or [{}])[0].get("variables", {})
            g[k] = list(v)
        elif k == "rows" and ("cases" in d or "observations" in d):
            g[k] = d.get("cases", d.get("observations"))
        elif k == "signals":
            plus = "+" in d.get("type", "")  # EDF+ / BDF+: annotations are not signals
            g[k] = d.get("signal_count", 0) - (sum("Annotations" in s for s in d.get("signals", {})) if plus else 0)
        elif k == "shape" and isinstance(want[k], list):
            g[k] = d.get("shape")
        else:
            g[k] = d.get(k)
    return g


def run(whiff, path):
    res = subprocess.run([whiff, "--profile", "standard", path], capture_output=True)
    try:
        r = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None, res.stderr.decode()[:200]
    fmt = r.get("format", {})
    if not fmt:
        return None, r["identification"].get("format")
    return next(iter(fmt.items())), None


def cmd_check(out, whiff):
    rows = [json.loads(l) for l in open(os.path.join(out, "expected.jsonl"))]
    # R's facts: path \t object \t description ("" object: the .rds value).
    rfile = os.path.join(out, "expected-r.tsv")
    robj = {}
    if os.path.exists(rfile):
        for line in open(rfile, encoding="utf-8"):
            path, name, desc = line.rstrip("\n").split("\t")
            robj.setdefault(path, {})[name] = desc
    for path, objs in robj.items():
        rows.append({"path": path, "facts": {"object": objs[""]} if "" in objs else {"objects": objs}})
    totals, fails, errors = {}, {}, 0
    for row in rows:
        want = row["facts"]
        if "oracle_error" in want:
            errors += 1
            continue
        path = os.path.join(out, row["path"])
        if os.path.basename(path) in SKIP:
            continue
        ext = os.path.splitext(path)[1].lower()
        totals[ext] = totals.get(ext, 0) + 1
        res, err = run(whiff, path)
        if res is None:
            fails.setdefault(ext, []).append((path, [("format", "section", err)]))
            continue
        _, d = res
        g = got(d, want)
        bad = [(k, v, g.get(k)) for k, v in want.items() if g.get(k) != v]
        if bad:
            fails.setdefault(ext, []).append((path, bad))
    for ext in sorted(totals):
        n, f = totals[ext], len(fails.get(ext, []))
        print(f"{ext:8} {n - f:5}/{n:<5} agree")
    print(f"oracle could not read {errors} files")
    for ext, items in sorted(fails.items()):
        for path, bad in items[: int(os.environ.get("SHOW", "6"))]:
            print(f"  {path}")
            for k, v, g in bad[:4]:
                print(f"      {k}: oracle {json.dumps(v, default=str)[:220]} whiff {json.dumps(g, default=str)[:220]}")


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        cmd_expect(sys.argv[2])
    else:
        cmd_check(sys.argv[2], sys.argv[3])
