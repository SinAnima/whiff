#!/usr/bin/env python3
"""Stage 8 long tail, batch 5e part 2: science and medical fixtures for the
fictitious Saltmere Harbour, CC0-1.0, written from each format's published
layout (HDF4 comes from GDAL, see science5e.sh). Run in `whiff-legacy`.

    craft_science5e.py OUT_DIR
"""

import struct
import sys
from pathlib import Path

OUT = Path(sys.argv[1])


def out(fmt, name, data):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


def crc_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def scp_ecg() -> bytes:
    """EN 1064: sections 0 (pointers), 1 (header), 3 (leads), 6 (rhythm)."""
    def section(sid, body, reserved=b"\0" * 6):
        head = struct.pack("<HIBB", sid, 16 + len(body), 20, 20) + reserved
        sec = head + body
        return struct.pack("<H", crc_ccitt(sec)) + sec

    def tag(t, v):
        return struct.pack("<BH", t, len(v)) + v
    device = struct.pack("<HHHBB", 1, 2, 7, 0, 255) + b"SALT1\0" + bytes([20, 0, 0, 0, 0, 0]) + bytes(14) + bytes(1)
    device += b"\0" + b"SN-0001\0" + b"harbour-ecg 1.0\0" + b"craft 1.0\0" + b"Saltmere Instruments\0"
    s1 = (tag(0, b"Gull\0") + tag(1, b"Ben\0") + tag(2, b"SALT-0001\0") + tag(5, struct.pack("<HBB", 1960, 3, 12)) + tag(8, b"\x01")
          + tag(14, device) + tag(16, b"Saltmere Harbour Clinic\0") + tag(20, b"Dr Ana Lighthouse\0")
          + tag(25, struct.pack("<HBB", 2025, 9, 1)) + tag(26, bytes([12, 0, 0])) + tag(27, struct.pack("<H", 5)) + tag(28, struct.pack("<H", 150))
          + tag(255, b""))
    samples = 500  # one second at 500 Hz
    leads = [1, 2, 61, 62, 63, 64, 3, 4, 5, 6, 7, 8]
    s3 = bytes([len(leads), 0x04]) + b"".join(struct.pack("<IIB", 1, samples, l) for l in leads)
    data = b"".join(struct.pack("<h", (i % 50) - 25) for i in range(samples))
    s6 = struct.pack("<HHBB", 5000, 2000, 0, 0) + struct.pack("<H", len(data)) * len(leads) + data * len(leads)
    bodies = {1: s1, 3: s3, 6: s6}
    # Section 0 needs the offsets, so lay the others out first.
    pointer_count = 12  # sections 0 – 11
    s0_len = 16 + 2 + pointer_count * 10
    pos = 6 + s0_len + 1
    sections, ptrs = b"", b""
    for sid in range(pointer_count):
        if sid == 0:
            ptrs += struct.pack("<HII", 0, s0_len, 7)
        elif sid in bodies:
            sec = section(sid, bodies[sid])
            ptrs += struct.pack("<HII", sid, len(sec), pos)
            sections += sec
            pos += len(sec)
        else:
            ptrs += struct.pack("<HII", sid, 0, 0)
    s0 = section(0, ptrs + b"\0\0", reserved=b"SCPECG")
    body = s0 + sections
    total = 6 + len(body)
    return struct.pack("<HI", crc_ccitt(struct.pack("<I", total) + body), total) + body


def main():
    out("scp_ecg", "harbour-clinic.scp", scp_ecg())
    digits = " ".join(str((i % 50) - 25) for i in range(500))
    lead = lambda code: f'''<component><sequence><code code="{code}" codeSystem="2.16.840.1.113883.6.24"/><value xsi:type="SLIST_PQ"><origin value="0" unit="uV"/><scale value="5" unit="uV"/><digits>{digits}</digits></value></sequence></component>'''
    out("aecg", "harbour-clinic.aecg.xml", f'''<?xml version="1.0" encoding="UTF-8"?>
<AnnotatedECG xmlns="urn:hl7-org:v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <id root="00000000-0000-0000-0000-00000000ec60"/>
  <code code="93000" codeSystem="2.16.840.1.113883.6.12"/>
  <effectiveTime><low value="20250901120000"/><high value="20250901120001"/></effectiveTime>
  <componentOf><timepointEvent><componentOf><subjectAssignment><subject><trialSubject><id extension="SALT-0001"/>
    <subjectDemographicPerson><name><given>Ben</given><family>Gull</family></name><administrativeGenderCode code="M"/><birthTime value="19600312"/></subjectDemographicPerson>
  </trialSubject></subject></subjectAssignment></componentOf></timepointEvent></componentOf>
  <component><series>
    <code code="RHYTHM" codeSystem="2.16.840.1.113883.5.4"/>
    <effectiveTime><low value="20250901120000"/><high value="20250901120001"/></effectiveTime>
    <author><seriesAuthor><manufacturedSeriesDevice><manufacturerModelName>Harbour ECG 1</manufacturerModelName><softwareName>harbour-ecg 1.0</softwareName></manufacturedSeriesDevice>
      <manufacturerOrganization><name>Saltmere Instruments</name></manufacturerOrganization></seriesAuthor></author>
    <component><sequenceSet>
      <component><sequence><code code="TIME_ABSOLUTE" codeSystem="2.16.840.1.113883.5.4"/><value xsi:type="GLIST_TS"><head value="20250901120000.000"/><increment value="0.002" unit="s"/></value></sequence></component>
      {lead("MDC_ECG_LEAD_I")}{lead("MDC_ECG_LEAD_II")}{lead("MDC_ECG_LEAD_V1")}
    </sequenceSet></component>
    <subjectOf><annotationSet><component><annotation><code code="MDC_ECG_INTERPRETATION"/><value xsi:type="ST">Normal sinus rhythm</value></annotation></component></annotationSet></subjectOf>
  </series></component>
</AnnotatedECG>
''')
    out("maple_mw", "tide-model.mw", '''<?xml version="1.0" encoding="UTF-8"?>
<Worksheet><Version major="2023" minor="0"/><View-Properties presentation="true"/>
<Styles><Font name="Text" family="Times New Roman" size="12"/></Styles>
<Group view="presentation"><Input><Text-field style="Title" layout="Heading 1">Saltmere tide model</Text-field></Input></Group>
<Group view="presentation"><Input><Text-field style="Text">High water follows a sine of period 12.42 hours.</Text-field></Input></Group>
<Group view="presentation"><Input><Equation executable="true" style="2D Input">tide := t -&gt; 2.1*sin(2*Pi*t/12.42)</Equation></Input>
<Output><Equation style="2D Output">tide := t -&gt; 2.1 sin(0.5059 t)</Equation></Output></Group>
<Group view="presentation"><Input><Equation executable="true" style="2D Input">plot(tide(t), t = 0 .. 24)</Equation></Input><Output><Plot height="300" width="500"/></Output></Group>
</Worksheet>
''')
    out("mathcad", "mooring-loads.xmcd", '''<?xml version="1.0" encoding="utf-8"?>
<worksheet version="3.0.3" xmlns="http://schemas.mathsoft.com/worksheet30" xmlns:ml="http://schemas.mathsoft.com/math30">
  <pointReleaseData/>
  <metadata>
    <generator>Mathcad (TM) 15</generator>
    <userData><title>Mooring loads</title><description>Line tension for the Saltmere moorings</description><author>Ana Lighthouse</author><company>Saltmere Harbour</company></userData>
  </metadata>
  <settings/>
  <regions>
    <region region-id="1" left="24" top="12"><text><p>Mooring line tension</p></text></region>
    <region region-id="2" left="24" top="48"><math><ml:define><ml:id>F</ml:id><ml:real>1200</ml:real></ml:define></math></region>
    <region region-id="3" left="24" top="84"><math><ml:eval><ml:id>F</ml:id></ml:eval></math></region>
  </regions>
</worksheet>
''')
    out("mrsid", "saltmere-ortho.sid", b"msid" + bytes([4]) + bytes(59))


main()
