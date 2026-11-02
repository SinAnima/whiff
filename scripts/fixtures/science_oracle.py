"""Compare whiff's science reports with each format's own library.

    # in the `whiff-science` container: build a corpus and the expected facts
    python3 science_oracle.py expect OUT_DIR

    # on the host
    python3 science_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is generated files (HDF5 with both library versions, many
links, nesting, compound and string types; NetCDF classic and 4; AnnData;
Loom; FITS with every tile compression; ASDF; Zarr; BAM, CRAM, VCF, BCF,
FASTA, FASTQ) plus the test data shipped inside the installed packages
(astropy, h5py, netCDF4, scipy, asdf, xarray, pysam …), copied into
OUT_DIR/corpus. Expected facts come from h5py, netCDF4, astropy, asdf,
zarr and pysam. Nothing here ships with whiff.
"""

import glob
import json
import os
import random
import shutil
import subprocess
import sys

R = random.Random(5)
EXTS = (".h5", ".hdf5", ".he5", ".nc", ".nc4", ".h5ad", ".loom", ".fits", ".fit", ".fts", ".fz", ".asdf",
        ".bam", ".cram", ".bcf", ".fa", ".fasta", ".fq", ".fastq")


def h5_type(dt):
    import h5py
    import numpy as np

    if h5py.check_string_dtype(dt) is not None and h5py.check_string_dtype(dt).length is None:
        return "vlen string"
    if dt.kind == "S":
        return f"string[{dt.itemsize}]"
    if dt.kind in "iu":
        return f"{'' if dt.kind == 'i' else 'u'}int{dt.itemsize * 8}"
    if dt.kind == "f":
        return f"float{dt.itemsize * 8}"
    if dt.kind == "b":
        return "enum<int8>"
    return None


def hdf5_facts(p):
    import h5py

    groups, datasets = 1, {}
    with h5py.File(p, "r") as f:
        def visit(name, obj):
            nonlocal groups
            if isinstance(obj, h5py.Group):
                groups += 1
            elif isinstance(obj, h5py.Dataset):
                t = h5_type(obj.dtype)
                shape = "x".join(str(n) for n in obj.shape) if obj.shape else "scalar"
                datasets["/" + name] = [shape.replace("+", ""), t]
        f.visititems(visit)
        root = sorted(f.attrs.keys())
    return {"groups": groups, "datasets": len(datasets), "dataset_shapes": datasets, "root_attribute_keys": root}


def netcdf_facts(p):
    import netCDF4

    with netCDF4.Dataset(p) as d:
        return {"dimensions": {k: len(v) for k, v in d.dimensions.items()},
                "variables": {k: list(v.dimensions) for k, v in d.variables.items()}}


def fits_facts(p):
    from astropy.io import fits

    with fits.open(p, checksum=True, disable_image_compression=True) as h:
        out = []
        for hdu in h:
            hd = hdu.header
            e = {"type": "primary" if "SIMPLE" in hd else {"BINTABLE": "compressed image" if hd.get("ZIMAGE") else "binary table",
                                                             "TABLE": "ascii table", "IMAGE": "image"}.get(hd.get("XTENSION"), "other")}
            if e["type"].endswith("table"):
                e["rows"] = hd.get("NAXIS2", 0)
            # astropy's own verification of CHECKSUM / DATASUM.
            if "CHECKSUM" in hd:
                e["checksum"] = "valid" if getattr(hdu, "_checksum_valid", False) else "invalid"
            if "DATASUM" in hd:
                e["datasum"] = "valid" if getattr(hdu, "_datasum_valid", False) else "invalid"
            out.append(e)
        return {"hdus": len(h), "hdu_types": [x["type"] for x in out],
                "table_rows": [x.get("rows") for x in out if "rows" in x],
                "checksums": [[x.get("checksum"), x.get("datasum")] for x in out]}


def asdf_facts(p):
    import asdf

    with asdf.open(p, lazy_load=True, memmap=False) as af:
        keys = [k for k in af.tree.keys()]
        return {"blocks": len(af._blocks.blocks) if hasattr(af, "_blocks") else None, "tree_keys": sorted(keys)}


def bam_facts(p):
    import pysam

    with pysam.AlignmentFile(p, "rc" if p.endswith(".cram") else "rb", check_sq=False,
                             reference_filename=cram_ref(p) if p.endswith(".cram") else None) as a:
        n = sum(1 for _ in a.fetch(until_eof=True))
        return {"references": a.nreferences, "reference_names": list(a.references)[:100], "records": n}


def cram_ref(p):
    """The generated reference beside a generated CRAM."""
    ref = p[:-5] + ".fa"
    return ref if os.path.exists(ref) else None


def bcf_facts(p):
    import pysam

    with pysam.VariantFile(p) as v:
        return {"samples": len(v.header.samples), "contigs": len(v.header.contigs), "records": sum(1 for _ in v)}


def fastx_facts(p):
    import pysam

    n, total = 0, 0
    with pysam.FastxFile(p) as f:
        for r in f:
            n += 1
            total += len(r.sequence)
    return ({"sequences": n, "total_length": total} if p.endswith((".fa", ".fasta")) else {"reads": n, "bases": total})


# ------------------------------------------------------------ generators
def generate(c):
    import h5py
    import numpy as np

    rng = np.random.default_rng(3)
    for i in range(24):
        p = os.path.join(c, f"g{i}.h5")
        with h5py.File(p, "w", libver=R.choice(["earliest", "latest"])) as f:
            for k in range(R.randint(0, 6)):
                f.attrs[f"a{k}"] = R.choice(["text", 3, 2.5, np.arange(3), np.bytes_("bytes")])
            def fill(g, depth):
                for j in range(R.randint(1, 14)):
                    if depth < 3 and R.random() < 0.25:
                        fill(g.create_group(f"grp{j}"), depth + 1)
                    else:
                        kind = R.choice(["f4", "i8", "u1", "S6", "str", "f8"])
                        shape = tuple(R.randint(1, 30) for _ in range(R.randint(0, 3)))
                        if kind == "str":
                            g.create_dataset(f"d{j}", data=np.array(["a", "bb"], dtype=h5py.string_dtype()))
                        else:
                            kw = {}
                            if shape and R.random() < 0.5:
                                kw = dict(chunks=True, compression=R.choice(["gzip", "lzf"]), shuffle=R.random() < 0.5)
                            g.create_dataset(f"d{j}", data=np.zeros(shape, kind), **kw)
            fill(f, 0)
    import netCDF4

    for i in range(16):
        fmt = R.choice(["NETCDF4", "NETCDF4_CLASSIC", "NETCDF3_CLASSIC", "NETCDF3_64BIT_OFFSET", "NETCDF3_64BIT_DATA"])
        p = os.path.join(c, f"n{i}.nc")
        with netCDF4.Dataset(p, "w", format=fmt) as d:
            dims = []
            for k in range(R.randint(1, 4)):
                name = f"dim{k}"
                d.createDimension(name, None if k == 0 and R.random() < 0.5 else R.randint(1, 20))
                dims.append(name)
            for k in range(R.randint(1, 6)):
                vd = tuple(sorted(R.sample(dims, R.randint(1, len(dims)))))  # unlimited first
                v = d.createVariable(f"v{k}", R.choice(["f4", "f8", "i4", "i2"]), vd)
                v.units = "m"
            d.title = f"corpus {i}"
    from astropy.io import fits

    for i, comp in enumerate(["RICE_1", "GZIP_1", "GZIP_2", "PLIO_1", "HCOMPRESS_1", None, None]):
        hdus = [fits.PrimaryHDU(rng.normal(size=(16, 16)).astype("f4") if comp is None else None)]
        if comp:
            data = (rng.integers(0, 100, (32, 32))).astype("i2") if comp == "PLIO_1" else rng.normal(size=(32, 32)).astype("f4")
            hdus.append(fits.CompImageHDU(data, compression_type=comp))
        hdus.append(fits.BinTableHDU.from_columns([fits.Column("x", "J", array=np.arange(R.randint(1, 50)))]))
        hdus.append(fits.TableHDU.from_columns([fits.Column("y", "I8", array=np.arange(4))]))
        fits.HDUList(hdus).writeto(os.path.join(c, f"f{i}.fits"), checksum=R.random() < 0.7)
    # Genomics: random references, reads and variants through samtools / bcftools.
    for i in range(8):
        refs = {f"chr{j}": "".join(R.choice("ACGT") for _ in range(R.randint(300, 2000))) for j in range(R.randint(1, 4))}
        fa = os.path.join(c, f"r{i}.fa")
        with open(fa, "w") as fh:
            for n, s in refs.items():
                fh.write(f">{n}\n" + "".join(s[k:k + 70] + "\n" for k in range(0, len(s), 70)))
        with open(os.path.join(c, f"r{i}.fq"), "w") as fh:
            for k in range(R.randint(1, 80)):
                s = "".join(R.choice("ACGTN") for _ in range(R.randint(20, 150)))
                fh.write(f"@q{k}\n{s}\n+\n{'I' * len(s)}\n")
        sam = os.path.join(c, f"r{i}.sam.txt")
        with open(sam, "w") as fh:
            fh.write("@HD\tVN:1.6\n" + "".join(f"@SQ\tSN:{n}\tLN:{len(s)}\n" for n, s in refs.items()))
            for k in range(R.randint(0, 120)):
                n = R.choice(list(refs))
                pos = R.randint(1, len(refs[n]) - 40)
                flag = R.choice([0, 16, 4])
                rname, p2 = (n, pos) if flag != 4 else ("*", 0)
                seq = refs[n][pos - 1:pos + 29]
                cig = "30M" if flag != 4 else "*"
                fh.write(f"r{k}\t{flag}\t{rname}\t{p2}\t{60 if flag != 4 else 0}\t{cig}\t*\t0\t0\t{seq}\t{'I' * 30}\n")
        subprocess.run(["samtools", "sort", "--no-PG", "-o", os.path.join(c, f"r{i}.bam"), sam], check=True)
        subprocess.run(["samtools", "view", "--no-PG", "-C", "-T", fa, "-o", os.path.join(c, f"r{i}.cram"),
                        os.path.join(c, f"r{i}.bam")], check=True)
        vcf = os.path.join(c, f"r{i}.vcf.txt")
        with open(vcf, "w") as fh:
            fh.write("##fileformat=VCFv4.2\n" + "".join(f"##contig=<ID={n},length={len(s)}>\n" for n, s in refs.items()))
            fh.write('##FORMAT=<ID=GT,Number=1,Type=String,Description="Genotype">\n')
            samples = [f"s{k}" for k in range(R.randint(0, 5))]
            fh.write("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO" + ("\tFORMAT\t" + "\t".join(samples) if samples else "") + "\n")
            n = list(refs)[0]
            for pos in sorted(R.sample(range(1, len(refs[n])), R.randint(0, 30))):
                gt = ("\tGT" + "".join("\t0/1" for _ in samples)) if samples else ""
                fh.write(f"{n}\t{pos}\t.\t{refs[n][pos - 1]}\t{'A' if refs[n][pos - 1] != 'A' else 'C'}\t30\tPASS\t.{gt}\n")
        subprocess.run(["bcftools", "view", "--no-version", "-O", "b", "-o", os.path.join(c, f"r{i}.bcf"), vcf], check=True)
        for f in (sam, vcf, fa + ".fai"):
            if os.path.exists(f):
                os.remove(f)
    os.environ["CRAM_REF"] = ""

    import asdf

    for i in range(6):
        tree = {f"k{j}": rng.normal(size=(R.randint(1, 8),)) for j in range(R.randint(1, 5))}
        tree["meta"] = {"i": i}
        asdf.AsdfFile(tree).write_to(os.path.join(c, f"a{i}.asdf"), all_array_compression=R.choice([None, "zlib", "bzp2"]))


def cmd_expect(out):
    c = os.path.join(out, "corpus")
    shutil.rmtree(c, ignore_errors=True)
    os.makedirs(c)
    generate(c)
    # Test data shipped with the installed packages.
    site = "/usr/local/lib/python3.12/site-packages"
    for p in glob.glob(f"{site}/**/*", recursive=True):
        low = p.lower()
        if os.path.isfile(p) and low.endswith(EXTS) and "/tests/" in p.replace("/test/", "/tests/") and os.path.getsize(p) < 64 << 20:
            dst = os.path.join(c, p[len(site) + 1:].replace("/", "__"))
            shutil.copy(p, dst)
    rows = []
    for name in sorted(os.listdir(c)):
        p = os.path.join(c, name)
        low = name.lower()
        try:
            if low.endswith((".h5", ".hdf5", ".he5", ".h5ad", ".loom")):
                facts = hdf5_facts(p)
            elif low.endswith((".nc", ".nc4")):
                facts = netcdf_facts(p)
                with open(p, "rb") as fh:
                    if fh.read(4) == b"\x89HDF":
                        facts.update({k: v for k, v in hdf5_facts(p).items() if k in ("groups", "datasets")})
            elif low.endswith((".fits", ".fit", ".fts", ".fz")):
                facts = fits_facts(p)
            elif low.endswith(".asdf"):
                facts = asdf_facts(p)
            elif low.endswith((".bam", ".cram")):
                facts = bam_facts(p)
            elif low.endswith(".bcf"):
                facts = bcf_facts(p)
            elif low.endswith((".fa", ".fasta", ".fq", ".fastq")):
                facts = fastx_facts(p)
            else:
                continue
        except Exception as e:  # recorded, not compared
            facts = {"oracle_error": f"{type(e).__name__}: {e}"[:200]}
        rows.append({"path": os.path.relpath(p, out), "facts": facts})
    with open(os.path.join(out, "expected.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"{len(rows)} files written to {out}/expected.jsonl")


def got_facts(fmt, d, want):
    """whiff's values for the oracle's keys."""
    g = {}
    for k in want:
        if k == "dataset_shapes":
            g[k] = {x["path"]: [x["shape"].replace("+", ""), x["type"] if x["type"] in
                                 {v[1] for v in want[k].values()} else None] for x in d.get("dataset_list", [])}
            # Only compare types the oracle names.
            g[k] = {p: [s, t if want[k].get(p, [None, None])[1] is not None else None] for p, (s, t) in g[k].items()}
            # whiff lists the first 200 datasets: compare those.
            want[k] = {p: want[k].get(p) for p in g[k]}
        elif k == "root_attribute_keys":
            g[k] = sorted(d.get("root_attributes", {}).keys())
        elif k == "variables":
            g[k] = {n: v.get("dimensions") for n, v in d.get("variables", {}).items()}
        elif k == "hdu_types":
            g[k] = [h.get("type") for h in d.get("hdu_list", [])]
        elif k == "checksums":
            g[k] = [[h.get("checksum"), h.get("datasum")] for h in d.get("hdu_list", [])]
        elif k == "table_rows":
            g[k] = [h.get("rows") for h in d.get("hdu_list", []) if "rows" in h]
        elif k == "tree_keys":
            g[k] = sorted(x for x in d.get("tree_keys", []) if x not in ("asdf_library", "history"))
        else:
            g[k] = d.get(k)
    return g


def cmd_check(out, whiff):
    rows = [json.loads(l) for l in open(os.path.join(out, "expected.jsonl"))]
    totals, fails, errors = {}, {}, 0
    for row in rows:
        want = row["facts"]
        if "oracle_error" in want:
            errors += 1
            continue
        path = os.path.join(out, row["path"])
        ext = os.path.splitext(path)[1].lower()
        totals[ext] = totals.get(ext, 0) + 1
        res = subprocess.run([whiff, "--profile", "standard", path], capture_output=True)
        try:
            r = json.loads(res.stdout)
        except json.JSONDecodeError:
            fails.setdefault(ext, []).append((path, [("report", "present", res.stderr.decode()[:200])]))
            continue
        fmt = r.get("format", {})
        if not fmt:
            fails.setdefault(ext, []).append((path, [("format", "section", r["identification"].get("format"))]))
            continue
        fid, d = next(iter(fmt.items()))
        if "tree_keys" in want:
            want = dict(want, tree_keys=sorted(x for x in want["tree_keys"] if x not in ("asdf_library", "history")))
            want.pop("blocks", None)
        g = got_facts(fid, d, want)
        bad = [(k, v, g.get(k)) for k, v in want.items() if g.get(k) != v]
        if bad:
            fails.setdefault(ext, []).append((path, bad))
    for ext in sorted(totals):
        n, f = totals[ext], len(fails.get(ext, []))
        print(f"{ext:8} {n - f:5}/{n:<5} agree")
    print(f"oracle could not read {errors} files")
    for ext, items in sorted(fails.items()):
        for path, bad in items[:5]:
            print(f"  {path}")
            for k, v, g in bad[:4]:
                print(f"      {k}: oracle {json.dumps(v)[:200]} whiff {json.dumps(g)[:200]}")


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        cmd_expect(sys.argv[2])
    else:
        cmd_check(sys.argv[2], sys.argv[3])
