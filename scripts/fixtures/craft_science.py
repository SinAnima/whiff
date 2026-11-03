"""Science fixtures for whiff (HDF5 and its layouts, NetCDF, FITS, ASDF,
Zarr, genomics), written by each format's own library.

Run by scripts/fixtures/science.sh inside the `whiff-science` container:

    python3 craft_science.py OUT_DIR

Fictitious data for Saltmere Harbour (tide gauges, a survey telescope on
the harbour wall, a made-up kelp genome); CC0-1.0.
"""

import os
import shutil
import subprocess
import sys

import numpy as np

OUT = sys.argv[1]
RNG = np.random.default_rng(42)


def out(*p):
    path = os.path.join(OUT, *p)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def hdf5():
    import h5py

    for libver, name in [("earliest", "tides-v0.h5"), ("latest", "tides-v3.h5")]:
        with h5py.File(out("hdf5", name), "w", libver=libver) as f:
            f.attrs["title"] = "Saltmere tide gauges"
            f.attrs["institution"] = "Saltmere Harbour Office"
            f.attrs["version"] = 3
            g = f.create_group("gauges")
            for i in range(12):  # more than 8 links: dense storage with libver latest
                d = g.create_dataset(f"G{i:02d}", data=RNG.normal(2.5, 1.2, (24, 60)).astype("f4"),
                                     chunks=(6, 60), compression="gzip", shuffle=True)
                d.attrs["units"] = "m"
            f.create_dataset("stations", data=np.array([b"Pier", b"Mole", b"Gate"]))
            f.create_dataset("calibration", data=np.arange(6, dtype="i8").reshape(2, 3))
            f.create_group("empty")


def netcdf():
    import netCDF4

    for fmt, name, folder in [("NETCDF4", "tides.nc", "netcdf4"), ("NETCDF4_CLASSIC", "tides-classic-model.nc", "netcdf4"),
                              ("NETCDF3_CLASSIC", "tides-cdf1.nc", "netcdf3"),
                              ("NETCDF3_64BIT_OFFSET", "tides-cdf2.nc", "netcdf3"),
                              ("NETCDF3_64BIT_DATA", "tides-cdf5.nc", "netcdf3")]:
        ds = netCDF4.Dataset(out(folder, name), "w", format=fmt)
        ds.title = "Saltmere tide heights"
        ds.institution = "Saltmere Harbour Office"
        ds.Conventions = "CF-1.8"
        ds.history = "2025-09-01 written for whiff's tests"
        ds.createDimension("time", None)
        ds.createDimension("station", 3)
        t = ds.createVariable("time", "f8", ("time",))
        t.units = "hours since 2025-09-01 00:00:00"
        t.standard_name = "time"
        h = ds.createVariable("height", "f4", ("time", "station"), zlib=fmt.startswith("NETCDF4"), fill_value=-999.0)
        h.units = "m"
        h.standard_name = "sea_surface_height"
        h.long_name = "tide height above chart datum"
        lat = ds.createVariable("lat", "f4", ("station",))
        lat.units = "degrees_north"
        lat[:] = [50.712, 50.713, 50.714]
        t[:] = np.arange(48)
        h[:, :] = RNG.normal(2.5, 1.0, (48, 3))
        ds.close()


def anndata_loom():
    import anndata
    import loompy
    import pandas as pd
    import scipy.sparse as sp

    X = sp.random(40, 25, density=0.2, format="csr", random_state=1, dtype=np.float32)
    obs = pd.DataFrame({"cell_type": pd.Categorical(["frond", "stipe", "holdfast", "frond"] * 10),
                        "n_counts": np.arange(40)}, index=[f"cell{i}" for i in range(40)])
    var = pd.DataFrame({"gene_symbol": [f"KLP{i}" for i in range(25)]}, index=[f"gene{i}" for i in range(25)])
    a = anndata.AnnData(X=X, obs=obs, var=var)
    a.layers["raw"] = X.copy()
    a.obsm["X_pca"] = RNG.normal(size=(40, 5)).astype("f4")
    a.uns["study"] = "Saltmere kelp atlas"
    a.write_h5ad(out("h5ad", "kelp-atlas.h5ad"), compression="gzip")
    loompy.create(out("loom", "kelp-atlas.loom"), RNG.poisson(1.0, (25, 40)).astype("f4"),
                  {"Gene": np.array([f"KLP{i}" for i in range(25)])},
                  {"CellID": np.array([f"cell{i}" for i in range(40)]), "Tissue": np.array(["frond"] * 40)},
                  file_attrs={"title": "Saltmere kelp atlas"})


def mat73():
    """MATLAB 7.3: an HDF5 file with a 512-byte user block holding the MAT
    header, as MATLAB and hdf5storage write it."""
    import h5py

    p = out("mat73", "tides-v73.mat")
    with h5py.File(p, "w", userblock_size=512, libver="earliest") as f:
        d = f.create_dataset("height", data=RNG.normal(2.5, 1.0, (3, 48)))
        d.attrs["MATLAB_class"] = np.bytes_("double")
        s = f.create_dataset("station", data=np.array([[ord(c)] for c in "Pier"], dtype="u2"))
        s.attrs["MATLAB_class"] = np.bytes_("char")
    head = b"MATLAB 7.3 MAT-file, Platform: GLNXA64, Created on: Mon Sep  1 06:00:00 2025 HDF5 schema 1.00 ."
    head = head.ljust(116, b" ") + b"\0" * 8 + b"\x00\x02" + b"IM"
    with open(p, "r+b") as fh:
        fh.write(head.ljust(512, b"\0"))


def fits():
    from astropy.io import fits as pf

    hdr = pf.Header()
    hdr["TELESCOP"] = "Saltmere Harbour Wall Survey"
    hdr["INSTRUME"] = "SHW-CAM1"
    hdr["OBJECT"] = "M31"
    hdr["OBSERVER"] = "Harbour Astronomy Club"
    hdr["DATE-OBS"] = "2025-09-01T22:14:05"
    hdr["EXPTIME"] = 30.0
    hdr["FILTER"] = "V"
    for k, v in {"CTYPE1": "RA---TAN", "CTYPE2": "DEC--TAN", "CRVAL1": 10.6847, "CRVAL2": 41.2690,
                 "CRPIX1": 32.0, "CRPIX2": 32.0, "CDELT1": -0.0003, "CDELT2": 0.0003, "RADESYS": "ICRS"}.items():
        hdr[k] = v
    img = pf.PrimaryHDU(RNG.normal(1000, 30, (64, 64)).astype("f4"), header=hdr)
    cols = pf.ColDefs([pf.Column("star", "10A", array=np.array(["alpha", "beta", "gamma"])),
                       pf.Column("ra", "D", array=[10.68, 10.70, 10.71], unit="deg"),
                       pf.Column("mag", "E", array=[3.4, 5.1, 6.0])])
    tab = pf.BinTableHDU.from_columns(cols, name="CATALOG")
    pf.HDUList([img, tab]).writeto(out("fits", "m31-survey.fits"), overwrite=True, checksum=True)
    comp = pf.CompImageHDU(RNG.normal(1000, 30, (64, 64)).astype("f4"), header=hdr, compression_type="RICE_1",
                           quantize_level=16.0)
    pf.HDUList([pf.PrimaryHDU(), comp]).writeto(out("fits", "m31-rice.fits.fz"), overwrite=True, checksum=True)


def asdf_files():
    import asdf

    tree = {"meta": {"telescope": "Saltmere Harbour Wall Survey", "target": "M31", "exposure_s": 30.0},
            "image": RNG.normal(1000, 30, (32, 32)).astype("f4"),
            "flags": np.zeros(32, "u1")}
    af = asdf.AsdfFile(tree)
    af.write_to(out("asdf", "m31-survey.asdf"))
    af.write_to(out("asdf", "m31-survey-zlib.asdf"), all_array_compression="zlib")


def zarr_files():
    import zarr

    for fmt in (2, 3):
        p = os.path.join(OUT, "_scratch", f"tides-v{fmt}.zarr")
        shutil.rmtree(p, ignore_errors=True)
        root = zarr.open_group(p, mode="w", zarr_format=fmt)
        root.attrs["title"] = "Saltmere tide heights"
        a = root.create_array("height", shape=(48, 3), chunks=(24, 3), dtype="f4")
        a[:] = RNG.normal(2.5, 1.0, (48, 3))
        a.attrs["units"] = "m"
        if fmt == 2:
            for f in (".zgroup", ".zattrs"):
                shutil.copy(os.path.join(p, f), out("zarr", f"tides-v2-group{f}"))
            shutil.copy(os.path.join(p, "height", ".zarray"), out("zarr", "height.zarray"))
        else:
            shutil.copy(os.path.join(p, "zarr.json"), out("zarr", "group-zarr.json"))
            shutil.copy(os.path.join(p, "height", "zarr.json"), out("zarr", "height-zarr.json"))


def genomics():
    rng = np.random.default_rng(7)
    seqs = {f"kelp_chr{i}": "".join(rng.choice(list("ACGT"), 600 + 200 * i)) for i in (1, 2)}
    fa = out("fasta", "saltmere-kelp.fa")
    with open(fa, "w") as fh:
        for n, s in seqs.items():
            fh.write(f">{n} Saltmere kelp (fictitious) chromosome {n[-1]}\n")
            fh.writelines(s[i:i + 60] + "\n" for i in range(0, len(s), 60))
    with open(out("fastq", "reads.fastq"), "w") as fh:
        for k in range(30):
            chrom = "kelp_chr1"
            pos = int(rng.integers(0, 500))
            s = seqs[chrom][pos:pos + 50]
            fh.write(f"@read{k} pos={pos}\n{s}\n+\n{''.join(chr(33 + int(q)) for q in rng.integers(20, 40, 50))}\n")
    sam = os.path.join(OUT, "_scratch", "reads.sam")
    os.makedirs(os.path.dirname(sam), exist_ok=True)
    with open(sam, "w") as fh:
        fh.write("@HD\tVN:1.6\tSO:coordinate\n")
        for n, s in seqs.items():
            # UR names the reference (samtools would record its full path).
            fh.write(f"@SQ\tSN:{n}\tLN:{len(s)}\tUR:saltmere-kelp.fa\n")
        fh.write("@RG\tID:run1\tSM:kelp-A\tPL:ILLUMINA\n@PG\tID:whiff-fixture\tPN:craft_science.py\tVN:1\n")
        reads = sorted((int(rng.integers(0, 500)), k) for k in range(30))
        for pos, k in reads:
            s = seqs["kelp_chr1"][pos:pos + 50]
            fh.write(f"read{k}\t0\tkelp_chr1\t{pos + 1}\t60\t50M\t*\t0\t0\t{s}\t{'I' * 50}\tRG:Z:run1\n")
    shutil.copy(sam, out("sam", "reads.sam"))
    subprocess.run(["samtools", "view", "--no-PG", "-b", "-o", out("bam", "reads.bam"), sam], check=True)
    # From the reference's folder, so UR: names the file, not the work path.
    # The CRAM file ID is the output name, so write it by its bare name.
    subprocess.run(["samtools", "view", "--no-PG", "-C", "-T", os.path.basename(fa), "-o", "reads.cram",
                    os.path.abspath(sam)], check=True, cwd=os.path.dirname(fa))
    shutil.move(os.path.join(os.path.dirname(fa), "reads.cram"), out("cram", "reads.cram"))
    # samtools records the reference's absolute path in UR:; drop it (M5 identifies the reference).
    cram = os.path.abspath(out("cram", "reads.cram"))
    hdr = subprocess.run(["samtools", "view", "--no-PG", "-H", cram], check=True, capture_output=True, text=True).stdout
    hdr_path = os.path.join(OUT, "_scratch", "cram-header.sam")
    with open(hdr_path, "w") as fh:
        fh.write("\n".join("\t".join(f for f in l.split("\t") if not f.startswith("UR:")) for l in hdr.splitlines()) + "\n")
    subprocess.run(["samtools", "reheader", "--no-PG", "-i", hdr_path, cram], check=True)
    os.remove(fa + ".fai")  # samtools indexes the reference beside it
    vcf = out("vcf_variants", "variants.vcf")
    with open(vcf, "w") as fh:
        fh.write("##fileformat=VCFv4.3\n##source=craft_science.py\n##reference=saltmere-kelp.fa\n")
        for n, s in seqs.items():
            fh.write(f"##contig=<ID={n},length={len(s)}>\n")
        fh.write('##INFO=<ID=DP,Number=1,Type=Integer,Description="Read depth">\n')
        fh.write('##FORMAT=<ID=GT,Number=1,Type=String,Description="Genotype">\n')
        fh.write("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tkelp-A\tkelp-B\n")
        for pos in (11, 120, 333, 480):
            ref = seqs["kelp_chr1"][pos - 1]
            alt = "A" if ref != "A" else "C"
            fh.write(f"kelp_chr1\t{pos}\t.\t{ref}\t{alt}\t50\tPASS\tDP=30\tGT\t0/1\t1/1\n")
    subprocess.run(["bcftools", "view", "--no-version", "-O", "b", "-o", out("bcf", "variants.bcf"), vcf], check=True)
    with open(out("bed", "genes.bed"), "w") as fh:
        fh.write('track name=kelp_genes description="Saltmere kelp genes"\n')
        for i, (a, b) in enumerate([(10, 200), (250, 420), (500, 590)]):
            fh.write(f"kelp_chr1\t{a}\t{b}\tKLP{i}\t0\t+\n")
    with open(out("gff", "genes.gff3"), "w") as fh:
        fh.write("##gff-version 3\n##sequence-region kelp_chr1 1 600\n")
        for i, (a, b) in enumerate([(11, 200), (251, 420)]):
            fh.write(f"kelp_chr1\tcraft\tgene\t{a}\t{b}\t.\t+\t.\tID=gene{i};Name=KLP{i}\n")
            fh.write(f"kelp_chr1\tcraft\tmRNA\t{a}\t{b}\t.\t+\t.\tID=mrna{i};Parent=gene{i}\n")
            fh.write(f"kelp_chr1\tcraft\texon\t{a}\t{b}\t.\t+\t.\tParent=mrna{i}\n")


if __name__ == "__main__":
    steps = {"hdf5": hdf5, "netcdf": netcdf, "anndata": anndata_loom, "mat73": mat73, "fits": fits,
             "asdf": asdf_files, "zarr": zarr_files, "genomics": genomics}
    for name in sys.argv[2:] or steps:
        steps[name]()
    shutil.rmtree(os.path.join(OUT, "_scratch"), ignore_errors=True)
