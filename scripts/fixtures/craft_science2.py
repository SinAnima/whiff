"""More science and medical fixtures for whiff, written by each format's own
library (or, for plain-text formats, by this script).

Run by scripts/fixtures/science.sh inside the `whiff-science2` container:

    python3 craft_science2.py OUT_DIR

Fictitious data for Saltmere Harbour (tide gauges, the harbour clinic's
made-up phantom scans, a buoy's electronics); no real person appears;
CC0-1.0.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import zipfile

import numpy as np

OUT = sys.argv[1]
RNG = np.random.default_rng(9)


def out(*p):
    path = os.path.join(OUT, *p)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def text(path, body):
    with open(out(*path), "w", newline="\n") as fh:
        fh.write(body)


def arrays():
    np.save(out("npy", "tides.npy"), RNG.normal(2.5, 1.0, (48, 3)).astype("<f4"))
    np.save(out("npy", "stations.npy"), np.array(["Pier", "Mole", "Gate"]))
    np.savez_compressed(out("npz", "tides.npz"), height=RNG.normal(size=(48, 3)), station=np.arange(3, dtype="i2"))
    import scipy.io

    data = {"height": RNG.normal(2.5, 1.0, (3, 48)), "station": "Pier", "count": np.int32(48),
            "meta": {"units": "m", "gauge": 7}}
    scipy.io.savemat(out("mat", "tides-v5.mat"), data, do_compression=False)
    scipy.io.savemat(out("mat", "tides-v5-compressed.mat"), data, do_compression=True)
    scipy.io.savemat(out("mat_v4", "tides-v4.mat"), {"height": RNG.normal(size=(3, 4))}, format="4")


def grib():
    for ed, tmpl in [(1, "GRIB1"), (2, "GRIB2")]:
        p = out("grib", f"sea-level.grib{ed}")
        subprocess.run(["grib_set", "-s", "centre=98,date=20250901,time=600,shortName=2t", "-d", "280",
                        f"/usr/share/eccodes/samples/{tmpl}.tmpl", p], check=True)


def stats():
    import pandas as pd
    import pyreadstat

    df = pd.DataFrame({"gauge": ["G7", "G8", "G9"], "height_m": [2.41, 3.05, 1.98], "ok": [1, 1, 0]})
    labels = ["Gauge identifier", "Tide height (m)", "Reading accepted"]
    pyreadstat.write_sav(df, out("sav", "tides.sav"), column_labels=labels, file_label="Saltmere tide readings")
    pyreadstat.write_sav(df, out("sav", "tides.zsav"), column_labels=labels, compress=True)
    pyreadstat.write_por(df, out("por", "tides.por"), column_labels=labels, file_label="Saltmere tide readings")
    pyreadstat.write_dta(df, out("dta", "tides.dta"), column_labels=labels, file_label="Saltmere tide readings", version=15)
    pyreadstat.write_xport(df, out("xpt", "tides.xpt"), column_labels=labels, file_label="Saltmere tides", table_name="TIDES")


def root_file():
    import uproot

    with uproot.recreate(out("root", "tides.root")) as f:
        f["readings"] = {"height": RNG.normal(size=50).astype("f4"), "gauge": np.arange(50, dtype="i4")}
        f["hist"] = np.histogram(RNG.normal(size=200), bins=10)


def chemistry():
    import gemmi

    pdb = """HEADER    STRUCTURAL PROTEIN                      01-SEP-25   9XYZ
TITLE     A MADE-UP KELP PEPTIDE FOR WHIFF'S TESTS
COMPND    MOL_ID: 1; MOLECULE: TIDE PEPTIDE
SOURCE    MOL_ID: 1; ORGANISM_SCIENTIFIC: SALTMERE KELP
EXPDTA    THEORETICAL MODEL
AUTHOR    SALTMERE HARBOUR LAB
CRYST1   10.000   10.000   10.000  90.00  90.00  90.00 P 1           1
ATOM      1  N   GLY A   1       0.000   0.000   0.000  1.00  0.00           N
ATOM      2  CA  GLY A   1       1.458   0.000   0.000  1.00  0.00           C
ATOM      3  C   GLY A   1       2.009   1.420   0.000  1.00  0.00           C
ATOM      4  O   GLY A   1       1.251   2.390   0.000  1.00  0.00           O
ATOM      5  N   ALA A   2       3.332   1.536   0.000  1.00  0.00           N
ATOM      6  CA  ALA A   2       3.970   2.845   0.000  1.00  0.00           C
HETATM    7  O   HOH A 101       5.000   5.000   5.000  1.00  0.00           O
END
"""
    text(["pdb", "tide-peptide.pdb"], pdb)
    st = gemmi.read_pdb_string(pdb)
    st.setup_entities()
    st.make_mmcif_document().write_file(out("mmcif", "tide-peptide.cif"))
    from rdkit import Chem
    from rdkit.Chem import AllChem

    m = Chem.AddHs(Chem.MolFromSmiles("OC(=O)CCN"))  # beta-alanine
    AllChem.Compute2DCoords(m)
    m.SetProp("_Name", "beta-alanine")
    Chem.MolToMolFile(m, out("mol", "beta-alanine.mol"))
    w = Chem.SDWriter(out("sdf", "harbour-compounds.sdf"))
    for name, smi in [("glycine", "NCC(=O)O"), ("taurine", "NCCS(=O)(=O)O"), ("urea", "NC(N)=O")]:
        x = Chem.MolFromSmiles(smi)
        AllChem.Compute2DCoords(x)
        x.SetProp("_Name", name)
        x.SetProp("source", "Saltmere Harbour Lab")
        w.write(x)
    w.close()
    text(["mol2", "urea.mol2"], """@<TRIPOS>MOLECULE
urea
 4 3 1 0 0
SMALL
NO_CHARGES

@<TRIPOS>ATOM
      1 C1          0.0000    0.0000    0.0000 C.2     1  URE1        0.0000
      2 O1          0.0000    1.2200    0.0000 O.2     1  URE1        0.0000
      3 N1          1.1500   -0.6700    0.0000 N.am    1  URE1        0.0000
      4 N2         -1.1500   -0.6700    0.0000 N.am    1  URE1        0.0000
@<TRIPOS>BOND
     1     1     2    2
     2     1     3   am
     3     1     4   am
""")
    text(["xyz", "water.xyz"], "3\nwater, Saltmere Harbour Lab\nO 0.000 0.000 0.117\nH 0.000 0.757 -0.469\nH 0.000 -0.757 -0.469\n")


def spectra():
    scans = "".join(
        f'<spectrum index="{i}" id="scan={i + 1}" defaultArrayLength="4"><cvParam cvRef="MS" accession="MS:1000511" name="ms level" value="{1 + i % 2}"/>'
        f'<cvParam cvRef="MS" accession="MS:1000016" name="scan start time" value="{0.5 * i}" unitName="minute"/></spectrum>'
        for i in range(6))
    text(["mzml", "kelp-extract.mzML"], f"""<?xml version="1.0" encoding="utf-8"?>
<mzML xmlns="http://psi.hupo.org/ms/mzml" version="1.1.0" id="kelp_extract">
<cvList count="1"><cv id="MS" fullName="Proteomics Standards Initiative Mass Spectrometry Ontology" version="4.1.0"/></cvList>
<fileDescription><fileContent><cvParam cvRef="MS" accession="MS:1000579" name="MS1 spectrum"/></fileContent></fileDescription>
<softwareList count="1"><software id="craft" version="1.0"><cvParam cvRef="MS" accession="MS:1000799" name="custom unreleased software tool" value="craft_science2"/></software></softwareList>
<instrumentConfigurationList count="1"><instrumentConfiguration id="IC1"><cvParam cvRef="MS" accession="MS:1000449" name="LTQ Orbitrap"/></instrumentConfiguration></instrumentConfigurationList>
<run id="kelp_run" defaultInstrumentConfigurationRef="IC1" startTimeStamp="2025-09-01T06:00:00Z">
<spectrumList count="6">{scans}</spectrumList></run></mzML>
""")
    text(["mzxml", "kelp-extract.mzXML"], """<?xml version="1.0" encoding="ISO-8859-1"?>
<mzXML xmlns="http://sashimi.sourceforge.net/schema_revision/mzXML_3.2">
<msRun scanCount="2" startTime="PT0S" endTime="PT60S">
<msInstrument><msManufacturer category="msManufacturer" value="Thermo Scientific"/><msModel category="msModel" value="LTQ Orbitrap"/></msInstrument>
<scan num="1" msLevel="1" peaksCount="0" retentionTime="PT0S"></scan>
<scan num="2" msLevel="2" peaksCount="0" retentionTime="PT30S"></scan>
</msRun></mzXML>
""")


def signals():
    import pyedflib

    for ext, ft in [("edf", pyedflib.FILETYPE_EDFPLUS), ("bdf", pyedflib.FILETYPE_BDFPLUS)]:
        folder = "edf" if ext == "edf" else "bdf_eeg"
        w = pyedflib.EdfWriter(out(folder, f"buoy-sensors.{ext}"), 2, file_type=ft)
        w.setHeader({"technician": "", "recording_additional": "Saltmere buoy B7", "patientname": "",
                     "patientcode": "", "equipment": "buoy logger", "admincode": "", "sex": "",
                     "startdate": __import__("datetime").datetime(2025, 9, 1, 6, 0, 0), "birthdate": "",
                     "patient_additional": ""})
        for i, label in enumerate(["tilt", "pressure"]):
            w.setSignalHeader(i, {"label": label, "dimension": "deg" if i == 0 else "hPa", "sample_frequency": 10,
                                  "physical_max": 100, "physical_min": -100, "digital_max": 32767 if ext == "edf" else 8388607,
                                  "digital_min": -32768 if ext == "edf" else -8388608, "prefilter": "", "transducer": "buoy"})
        w.writeSamples([RNG.normal(size=100), RNG.normal(size=100)])
        w.close()
    text(["vhdr", "buoy.vhdr"], """Brain Vision Data Exchange Header File Version 1.0
; Saltmere buoy sensors, written for whiff's tests

[Common Infos]
Codepage=UTF-8
DataFile=buoy.eeg
MarkerFile=buoy.vmrk
DataFormat=BINARY
DataOrientation=MULTIPLEXED
NumberOfChannels=2
SamplingInterval=1000

[Binary Infos]
BinaryFormat=IEEE_FLOAT_32

[Channel Infos]
Ch1=tilt,,0.1,deg
Ch2=pressure,,0.1,hPa
""")
    from nptdms import ChannelObject, GroupObject, RootObject, TdmsWriter

    with TdmsWriter(out("tdms", "buoy.tdms")) as w:
        w.write_segment([RootObject(properties={"name": "Saltmere buoy B7", "author": "Harbour Office"}),
                         GroupObject("sensors", properties={"site": "B7"}),
                         ChannelObject("sensors", "tilt", RNG.normal(size=50), properties={"unit_string": "deg"}),
                         ChannelObject("sensors", "pressure", RNG.normal(size=50), properties={"unit_string": "hPa"})])
    from vcd import VCDWriter

    with open(out("vcd", "buoy-logic.vcd"), "w") as fh:
        with VCDWriter(fh, timescale="1 ns", date="2025-09-01", version="pyvcd") as w:
            clk = w.register_var("logger", "clk", "wire", size=1)
            data = w.register_var("logger", "data", "wire", size=8)
            for t in range(10):
                w.change(clk, t * 10, t % 2)
                w.change(data, t * 10, t * 3)
    p = out("sigrok", "buoy-demo.sr")
    subprocess.run(["sigrok-cli", "-d", "demo", "--channels", "D0,D1,D2,D3", "--samples", "64", "-o", p], check=True)


def eda_text():
    text(["gaussian", "water-opt.log"], """ Entering Gaussian System, Link 0=g16
 Initial command:
 ******************************************
 Gaussian 16:  ES64L-G16RevC.01  3-Jul-2019
                 1-Sep-2025
 ******************************************
 #p opt b3lyp/6-31g(d)
 -----------------------
 Water optimisation (made up)
 -----------------------
 Symbolic Z-matrix:
 Charge =  0 Multiplicity = 1
 O                     0.        0.        0.117
 H                     0.        0.757    -0.469
 H                     0.       -0.757    -0.469
 SCF Done:  E(RB3LYP) =  -76.4089534     A.U. after    9 cycles
 Optimization completed.
 Normal termination of Gaussian 16 at Mon Sep  1 06:12:00 2025.
""")
    text(["orca", "water-opt.out"], """
                                 *****************
                                 * O   R   C   A *
                                 *****************

                       Program Version 6.0.1 -  RELEASE  -

The coordinates will be read from file: water.xyz
|  1> ! B3LYP def2-SVP Opt
|  2> * xyz 0 1
|  3>  O 0.000 0.000 0.117
|  4>  H 0.000 0.757 -0.469
|  5>  H 0.000 -0.757 -0.469
|  6> *
FINAL SINGLE POINT ENERGY       -76.320451270000
                    *** OPTIMIZATION RUN DONE ***
                             ****ORCA TERMINATED NORMALLY****
TOTAL RUN TIME: 0 days 0 hours 0 minutes 12 seconds 0 msec
""")
    text(["spice", "buoy-filter.cir"], """* Saltmere buoy sensor filter (made up)
.title Buoy sensor RC filter
V1 in 0 SIN(0 1 1k)
R1 in out 1k
C1 out 0 100n
X1 out amp_out OPAMP
.subckt OPAMP in out
E1 out 0 in 0 100k
.ends
.include models.lib
.tran 10u 5m
.ac dec 10 1 100k
.end
""")
    import skrf

    f = skrf.Frequency(1, 3, 5, "GHz")
    s = np.zeros((5, 2, 2), complex)
    s[:, 0, 1] = s[:, 1, 0] = 0.9
    nw = skrf.Network(frequency=f, s=s, name="buoy-antenna")
    nw.write_touchstone(out("touchstone", "buoy-antenna"))
    text(["ltspice", "buoy-filter.asc"], """Version 4
SHEET 1 880 680
WIRE 128 96 32 96
SYMBOL res 112 80 R0
SYMATTR InstName R1
SYMATTR Value 1k
SYMBOL cap 208 112 R0
SYMATTR InstName C1
SYMATTR Value 100n
SYMBOL voltage 32 96 R0
SYMATTR InstName V1
TEXT 0 300 Left 2 !.tran 5m
""")
    text(["ibis", "buoy-io.ibs"], """[IBIS Ver]   7.1
[File Name]  buoy-io.ibs
[File Rev]   1.0
[Date]       September 1, 2025
[Source]     Saltmere Harbour electronics bench (made up)
[Component]  BUOY-IO
[Manufacturer] Saltmere Harbour
[Pin]  signal_name  model_name
1      DATA         io_model
2      CLK          in_model
[Model]  io_model
Model_type  I/O
[Model]  in_model
Model_type  Input
[End]
""")
    text(["liberty", "buoy-cells.lib"], """library (buoy_cells) {
  technology (cmos) ;
  delay_model : table_lookup ;
  time_unit : "1ns" ;
  voltage_unit : "1V" ;
  cell (INVX1) { area : 1.0 ; pin (A) { direction : input ; } pin (Y) { direction : output ; function : "!A" ; } }
  cell (NAND2X1) { area : 1.5 ; pin (A) { direction : input ; } pin (B) { direction : input ; } pin (Y) { direction : output ; function : "!(A&B)" ; } }
}
""")
    text(["lef", "buoy.lef"], """VERSION 5.8 ;
BUSBITCHARS "[]" ;
UNITS
  DATABASE MICRONS 1000 ;
END UNITS
LAYER metal1
  TYPE ROUTING ;
END metal1
MACRO INVX1
  CLASS CORE ;
  SIZE 1.2 BY 2.4 ;
END INVX1
MACRO NAND2X1
  CLASS CORE ;
  SIZE 1.8 BY 2.4 ;
END NAND2X1
END LIBRARY
""")
    text(["def", "buoy-top.def"], """VERSION 5.8 ;
DESIGN buoy_top ;
UNITS DISTANCE MICRONS 1000 ;
DIEAREA ( 0 0 ) ( 20000 20000 ) ;
COMPONENTS 2 ;
- u1 INVX1 + PLACED ( 1000 1000 ) N ;
- u2 NAND2X1 + PLACED ( 3000 1000 ) N ;
END COMPONENTS
NETS 1 ;
- n1 ( u1 Y ) ( u2 A ) ;
END NETS
END DESIGN
""")
    text(["envi", "harbour-scan.hdr"], """ENVI
description = {Saltmere harbour multispectral scan (made up)}
samples = 64
lines   = 32
bands   = 4
header offset = 0
file type = ENVI Standard
data type = 4
interleave = bsq
byte order = 0
wavelength units = Nanometers
band names = { blue, green, red, nir }
wavelength = { 480, 560, 660, 840 }
map info = { UTM, 1.000, 1.000, 600000.000, 5620000.000, 2.0, 2.0, 30, North, WGS-84, units=Meters }
""")


def microscopy():
    import tifffile

    tifffile.imwrite(out("ome_tiff", "kelp-cells.ome.tif"), RNG.integers(0, 4096, (2, 3, 32, 32), dtype="u2"),
                     ome=True, photometric="minisblack",
                     metadata={"axes": "ZCYX", "Channel": {"Name": ["DAPI", "GFP", "RFP"]},
                               "PhysicalSizeX": 0.65, "PhysicalSizeY": 0.65, "PhysicalSizeZ": 2.0})


def medical():
    import pydicom
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    meta.MediaStorageSOPInstanceUID = "1.2.826.0.1.3680043.8.498.1"
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.ImplementationClassUID = "1.2.826.0.1.3680043.8.498.0"
    ds = FileDataset(out("dicom", "phantom-ct.dcm"), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = "1.2.826.0.1.3680043.8.498.2"
    ds.SeriesInstanceUID = "1.2.826.0.1.3680043.8.498.3"
    ds.Modality = "CT"
    ds.PatientName = "Phantom^Water"
    ds.PatientID = "PHANTOM-0001"
    ds.PatientBirthDate = "20000101"
    ds.PatientSex = "O"
    ds.InstitutionName = "Saltmere Harbour Clinic"
    ds.Manufacturer = "Saltmere Imaging"
    ds.ManufacturerModelName = "Tide CT 1"
    ds.StudyDate = ds.SeriesDate = "20250901"
    ds.StudyTime = "061200"
    ds.StudyDescription = "Water phantom calibration"
    ds.SeriesDescription = "Axial 5mm"
    ds.BodyPartExamined = "PHANTOM"
    ds.SliceThickness = "5"
    ds.PixelSpacing = [0.5, 0.5]
    ds.Rows = ds.Columns = 16
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 1
    ds.PixelData = RNG.integers(-1000, 1000, (16, 16), dtype="i2").tobytes()
    ds.save_as(out("dicom", "phantom-ct.dcm"), enforce_file_format=True)
    import nibabel as nib

    img = nib.Nifti1Image(RNG.normal(size=(8, 8, 4)).astype("f4"), np.diag([2.0, 2.0, 3.0, 1.0]))
    img.header["descrip"] = b"Saltmere phantom (made up)"
    img.header.set_xyzt_units("mm", "sec")
    nib.save(img, out("nifti", "phantom.nii"))
    nib.save(nib.Nifti2Image(img.get_fdata().astype("f4"), img.affine), out("nifti", "phantom-n2.nii"))
    nib.save(nib.AnalyzeImage(img.get_fdata().astype("i2"), np.eye(4)), out("analyze", "phantom.hdr"))
    os.remove(out("analyze", "phantom.img"))
    import nrrd

    nrrd.write(out("nrrd", "phantom.nrrd"), RNG.normal(size=(8, 8, 4)).astype("f4"),
               {"space": "left-posterior-superior", "space directions": np.eye(3) * 2.0, "kinds": ["domain"] * 3,
                "encoding": "gzip"})
    text(["metaimage", "phantom.mhd"], """ObjectType = Image
NDims = 3
BinaryData = True
BinaryDataByteOrderMSB = False
CompressedData = False
TransformMatrix = 1 0 0 0 1 0 0 0 1
Offset = 0 0 0
ElementSpacing = 2 2 3
DimSize = 8 8 4
ElementType = MET_FLOAT
ElementDataFile = phantom.raw
""")
    text(["hl7", "admission.hl7"], "\r".join([
        "MSH|^~\\&|TIDEADT|SALTMERE CLINIC|HARBOURLAB|SALTMERE|20250901061200||ADT^A01|MSG00001|P|2.5.1",
        "EVN|A01|20250901061200",
        "PID|1||PHANTOM-0001^^^SALTMERE||Phantom^Water||20000101|O",
        "PV1|1|O|CLINIC^1^1",
        "OBX|1|NM|TIDE^Tide height^L||2.41|m",
    ]) + "\r")
    from fhir.resources.bundle import Bundle

    bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
        {"resource": {"resourceType": "Patient", "id": "phantom", "name": [{"family": "Phantom", "given": ["Water"]}],
                      "gender": "other", "birthDate": "2000-01-01"}},
        {"resource": {"resourceType": "Observation", "id": "tide1", "status": "final",
                      "code": {"text": "Tide height"}, "subject": {"reference": "Patient/phantom"},
                      "valueQuantity": {"value": 2.41, "unit": "m"}}}]}
    Bundle.model_validate(bundle)
    text(["fhir", "phantom-bundle.fhir.json"], json.dumps(bundle, indent=2) + "\n")


STEPS = {"arrays": arrays, "grib": grib, "stats": stats, "root": root_file, "chemistry": chemistry,
         "spectra": spectra, "signals": signals, "eda": eda_text, "microscopy": microscopy, "medical": medical}

if __name__ == "__main__":
    for name in sys.argv[2:] or STEPS:
        STEPS[name]()
