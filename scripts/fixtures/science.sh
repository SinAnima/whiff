#!/usr/bin/env bash
# Regenerate the science fixtures under tests/fixtures/<format>/.
#
# Written in a container run with podman (image `whiff-science`, built from
# the Containerfile below) by each format's own library or tool, for a
# fictitious harbour (Saltmere Harbour: tide gauges, a survey telescope on
# the harbour wall, a made-up kelp genome), CC0-1.0: h5py (HDF5 with
# libver earliest and latest, a MATLAB 7.3 file with its user block),
# netCDF4 (NetCDF-4, the classic model, CDF-1 / 2 / 5), anndata (h5ad),
# loompy (Loom), astropy (FITS with checksums, a RICE tile-compressed
# image), asdf (plain and zlib blocks), zarr (v2 and v3 metadata), samtools
# (BAM, CRAM against the FASTA) and bcftools (BCF); FASTA, FASTQ, SAM, VCF,
# BED and GFF3 are written by craft_science.py.
#
#     scripts/fixtures/science.sh            (everything)
#     scripts/fixtures/science.sh more       (craft_science2.py and craft_science.R only)
#
# The second set (craft_science2.py in `whiff-science2`, craft_science.R in
# `whiff-science-r`) adds NumPy, SciPy MAT v4 / v5, eccodes GRIB 1 / 2,
# pyreadstat (SPSS, Stata, SAS XPORT), uproot (ROOT), gemmi (mmCIF), RDKit
# (MOL, SDF), pyEDFlib (EDF+, BDF+), npTDMS, pyvcd, sigrok-cli (demo
# capture), scikit-rf (Touchstone), tifffile (OME-TIFF), pydicom, nibabel
# (NIfTI-1 / 2, Analyze), pynrrd, fhir.resources (a validated bundle), and
# R saveRDS / save / haven::write_sas; the plain-text formats (PDB, MOL2,
# XYZ, mzML, mzXML, BrainVision, Gaussian, ORCA, SPICE, LTspice, IBIS,
# Liberty, LEF, DEF, ENVI, MetaImage, HL7) are written by craft_science2.py.
#
#     FROM localhost/whiff-science:latest            (`podman build -t whiff-science2`)
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sigrok-cli
#     RUN pip install --no-cache-dir rdkit==2026.9.1 pynrrd==1.1.3 nptdms==1.13.0 pyvcd==0.5.1 \
#         tifffile==2026.10.15 scikit-rf==2.2.0
#
#     FROM localhost/whiff-columnar-r:latest         (`podman build -t whiff-science-r`)
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zlib1g-dev pkg-config
#     RUN Rscript -e 'install.packages("haven")'     (haven 2.5.4)
#
# Containerfile (`podman build -t whiff-science`):
#
#     FROM docker.io/library/python:3.12-slim-bookworm
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         hdf5-tools netcdf-bin samtools bcftools tabix dcmtk libeccodes-tools ca-certificates
#     RUN pip install --no-cache-dir numpy==2.5.4 pandas==3.1.0 scipy==1.18.1 h5py==3.16.0 netCDF4==1.7.5.1.post1 \
#         anndata==0.13.4 loompy==3.0.8 astropy==8.0.2 asdf==6.0.0 zarr==3.4.2 xarray==2026.9.0 pysam==0.24.1 \
#         nibabel==5.4.2 pydicom==3.0.2 eccodes==2.50.0 pyreadstat==1.3.7 uproot==5.7.7 pyEDFlib==0.1.42 \
#         pyteomics==5.0.2 gemmi==0.7.5 hl7==0.4.5 fhir.resources==8.3.0 rdata==1.1.0

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/science-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

if [ "${1:-}" != "more" ]; then
    podman run --rm -v "$root:/whiff" -w /whiff whiff-science python3 scripts/fixtures/craft_science.py "$w" "$@"
fi
if [ $# -eq 0 ] || [ "$1" = "more" ]; then
    podman run --rm -v "$root:/whiff" -w /whiff whiff-science2 python3 scripts/fixtures/craft_science2.py "$w"
    podman run --rm -v "$root:/whiff" -w /whiff whiff-science-r Rscript scripts/fixtures/craft_science.R "$w"
fi

for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour). Regenerate with \`scripts/fixtures/science.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
[ -d "$fx/hdf5" ] && source_md hdf5 "HDF5" "h5py 3.16.0 (libver earliest: superblock 0, symbol tables; libver latest: superblock 3, dense links)"
[ -d "$fx/netcdf4" ] && source_md netcdf4 "NetCDF-4" "netCDF4 1.7.5 (NETCDF4 and NETCDF4_CLASSIC)"
[ -d "$fx/netcdf3" ] && source_md netcdf3 "NetCDF (3 / 4)" "netCDF4 1.7.5 (NETCDF3_CLASSIC, 64BIT_OFFSET, 64BIT_DATA)"
[ -d "$fx/h5ad" ] && source_md h5ad "AnnData (h5ad)" "anndata 0.13.4 (CSR X, layers, obsm, uns)"
[ -d "$fx/loom" ] && source_md loom "Loom" "loompy 3.0.8"
[ -d "$fx/mat73" ] && source_md mat73 "MATLAB MAT" "h5py 3.16.0 with a 512-byte user block holding the MAT header, as MATLAB and hdf5storage write it"
[ -d "$fx/fits" ] && source_md fits "FITS" "astropy 8.0.2 (checksums; RICE_1 tile compression)"
[ -d "$fx/asdf" ] && source_md asdf "ASDF (Advanced Scientific Data Format)" "asdf 6.0.0 (plain and zlib blocks)"
[ -d "$fx/zarr" ] && source_md zarr "Zarr" "zarr 3.4.2 (v2 .zarray / .zgroup / .zattrs, v3 zarr.json)"
[ -d "$fx/fasta" ] && source_md fasta "FASTA sequences" "craft_science.py (random sequences)"
[ -d "$fx/fastq" ] && source_md fastq "FASTQ reads" "craft_science.py"
[ -d "$fx/sam" ] && source_md sam "SAM alignments" "craft_science.py"
[ -d "$fx/bam" ] && source_md bam "BAM alignments" "samtools 1.16.1 view -b from the SAM fixture"
[ -d "$fx/cram" ] && source_md cram "CRAM alignments" "samtools 1.16.1 view -C against the FASTA fixture"
[ -d "$fx/vcf_variants" ] && source_md vcf_variants "VCF variants" "craft_science.py"
[ -d "$fx/bcf" ] && source_md bcf "BCF variants" "bcftools 1.16 view -O b from the VCF fixture"
[ -d "$fx/bed" ] && source_md bed "BED intervals" "craft_science.py"
[ -d "$fx/gff" ] && source_md gff "GFF / GTF features" "craft_science.py"
[ -d "$fx/npy" ] && source_md npy "NumPy NPY / NPZ" "NumPy 2.5.4 np.save"
[ -d "$fx/npz" ] && source_md npz "NumPy NPZ archive" "NumPy 2.5.4 np.savez_compressed"
[ -d "$fx/mat" ] && source_md mat "MATLAB MAT v5" "SciPy 1.18.1 savemat (plain and compressed)"
[ -d "$fx/mat_v4" ] && source_md mat_v4 "MATLAB MAT v4" "SciPy 1.18.1 savemat format 4"
[ -d "$fx/grib" ] && source_md grib "GRIB 1/2" "eccodes 2.50 grib_set from the GRIB1 / GRIB2 samples"
[ -d "$fx/sav" ] && source_md sav "SPSS data" "pyreadstat 1.3.7 write_sav (sav and zsav)"
[ -d "$fx/por" ] && source_md por "SPSS portable" "pyreadstat 1.3.7 write_por"
[ -d "$fx/dta" ] && source_md dta "Stata data" "pyreadstat 1.3.7 write_dta (format 119)"
[ -d "$fx/xpt" ] && source_md xpt "SAS dataset / transport" "pyreadstat 1.3.7 write_xport (XPORT v8)"
[ -d "$fx/sas7bdat" ] && source_md sas7bdat "SAS dataset" "R 4.4.2 haven 2.5.4 write_sas"
[ -d "$fx/rds" ] && source_md rds "R data" "R 4.4.2 saveRDS (gzip, xz, ascii)"
[ -d "$fx/rdata" ] && source_md rdata "R workspace" "R 4.4.2 save"
[ -d "$fx/root" ] && source_md root "ROOT (CERN)" "uproot 5.7.7 (an RNTuple and a histogram)"
[ -d "$fx/pdb" ] && source_md pdb "PDB structure" "craft_science2.py (a made-up peptide)"
[ -d "$fx/mmcif" ] && source_md mmcif "mmCIF structure" "gemmi 0.7.5 from the PDB fixture"
[ -d "$fx/mol" ] && source_md mol "MDL molfile" "RDKit 2026.09.1"
[ -d "$fx/sdf" ] && source_md sdf "SDF structures" "RDKit 2026.09.1 SDWriter"
[ -d "$fx/mol2" ] && source_md mol2 "Tripos MOL2" "craft_science2.py"
[ -d "$fx/xyz" ] && source_md xyz "XYZ coordinates" "craft_science2.py"
[ -d "$fx/mzml" ] && source_md mzml "mzML mass spectrometry" "craft_science2.py"
[ -d "$fx/mzxml" ] && source_md mzxml "mzXML mass spectrometry" "craft_science2.py"
[ -d "$fx/edf" ] && source_md edf "EDF / EDF+ recording" "pyEDFlib 0.1.42 (EDF+)"
[ -d "$fx/bdf_eeg" ] && source_md bdf_eeg "BioSemi BDF" "pyEDFlib 0.1.42 (BDF+)"
[ -d "$fx/vhdr" ] && source_md vhdr "BrainVision header" "craft_science2.py"
[ -d "$fx/tdms" ] && source_md tdms "NI TDMS" "npTDMS 1.13.0"
[ -d "$fx/vcd" ] && source_md vcd "VCD waveform" "pyvcd 0.5.1"
[ -d "$fx/sigrok" ] && source_md sigrok "Sigrok session" "sigrok-cli 0.7.2 demo device"
[ -d "$fx/gaussian" ] && source_md gaussian "Gaussian / ORCA / CP2K outputs" "craft_science2.py (a made-up log)"
[ -d "$fx/orca" ] && source_md orca "ORCA output" "craft_science2.py (a made-up output)"
[ -d "$fx/spice" ] && source_md spice "SPICE netlist" "craft_science2.py"
[ -d "$fx/touchstone" ] && source_md touchstone "Touchstone network data" "scikit-rf 2.2.0 write_touchstone"
[ -d "$fx/ltspice" ] && source_md ltspice "LTspice schematic" "craft_science2.py"
[ -d "$fx/ibis" ] && source_md ibis "IBIS model" "craft_science2.py"
[ -d "$fx/liberty" ] && source_md liberty "Liberty cell library" "craft_science2.py"
[ -d "$fx/lef" ] && source_md lef "LEF library" "craft_science2.py"
[ -d "$fx/def" ] && source_md def "DEF design" "craft_science2.py"
[ -d "$fx/envi" ] && source_md envi "ENVI / ERDAS / PCIDSK rasters" "craft_science2.py"
[ -d "$fx/ome_tiff" ] && source_md ome_tiff "OME-TIFF microscopy image" "tifffile 2026.10.15 (OME-XML)"
[ -d "$fx/dicom" ] && source_md dicom "DICOM" "pydicom 3.0.2 (a made-up water phantom; fictitious identifiers)"
[ -d "$fx/nifti" ] && source_md nifti "NIfTI-1 / NIfTI-2" "nibabel 5.4.2"
[ -d "$fx/analyze" ] && source_md analyze "Analyze 7.5" "nibabel 5.4.2 (header only)"
[ -d "$fx/nrrd" ] && source_md nrrd "NRRD volume" "pynrrd 1.1.3 (gzip)"
[ -d "$fx/metaimage" ] && source_md metaimage "MetaImage" "craft_science2.py"
[ -d "$fx/hl7" ] && source_md hl7 "HL7 v2 message" "craft_science2.py (fictitious identifiers)"
[ -d "$fx/fhir" ] && source_md fhir "FHIR resource" "fhir.resources 8.3.0 (validated bundle, fictitious patient)"
echo "fixtures written; scratch files in $work"
