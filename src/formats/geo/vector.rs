//! Binary vector stores:
//! * `FlatGeobuf`: name, title, description, geometry type and dimensions,
//!   features, the spatial index, columns, the CRS and the envelope;
//! * S-57 electronic navigational charts (ISO 8211): the data set name,
//!   edition, update, issue date, standard edition, producing agency,
//!   compilation scale, feature records by object class, vector records
//!   and bounds from the coordinates.
//!
//! Specifications: `FlatGeobuf` 3 (`header.fbs`); IHO S-57 edition 3.1
//! (part 3, data structure; appendix A, object classes) on ISO/IEC 8211.

use std::collections::BTreeMap;

use super::{Bounds, Crs, hist, report_bounds, report_native};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, flatbuf::FlatBuf,
    truncate_chars,
};

/// Extractor for binary vector stores.
pub struct Vector;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.vector",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "flatgeobuf",
            name: "FlatGeobuf",
            family: "geo",
            mimes: &["application/vnd.flatgeobuf"],
            extensions: &["fgb"],
            magic: &[Magic::at(0, b"fgb\x03fgb")],
            parent: None,
        },
        FormatSpec {
            id: "s57",
            name: "S-57 / S-101 nautical charts",
            family: "geo",
            mimes: &[],
            extensions: &["000", "s57"],
            magic: &[],
            parent: None,
        },
    ],
};

fn fgb_geometry(t: u8) -> &'static str {
    match t {
        0 => "Unknown",
        1 => "Point",
        2 => "LineString",
        3 => "Polygon",
        4 => "MultiPoint",
        5 => "MultiLineString",
        6 => "MultiPolygon",
        7 => "GeometryCollection",
        8 => "CircularString",
        9 => "CompoundCurve",
        10 => "CurvePolygon",
        11 => "MultiCurve",
        12 => "MultiSurface",
        13 => "Curve",
        14 => "Surface",
        15 => "PolyhedralSurface",
        16 => "TIN",
        17 => "Triangle",
        _ => "unknown",
    }
}

fn fgb_column(t: u8) -> &'static str {
    match t {
        0 => "byte",
        1 => "ubyte",
        2 => "bool",
        3 => "short",
        4 => "ushort",
        5 => "int",
        6 => "uint",
        7 => "long",
        8 => "ulong",
        9 => "float",
        10 => "double",
        11 => "string",
        12 => "json",
        13 => "datetime",
        14 => "binary",
        _ => "unknown",
    }
}

fn flatgeobuf(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("FlatGeobuf header");
    let h = src.read_vec(0, 12).map_err(|_| bad())?;
    cx.format_set("version", format!("{}.0.{}", h[3], h[7]));
    let size = usize::try_from(u32::from_le_bytes([h[8], h[9], h[10], h[11]])).map_err(|_| bad())?;
    if size > 16 << 20 {
        return Err(bad());
    }
    let buf = src.read_vec(12, size).map_err(|_| bad())?;
    let f = FlatBuf(&buf);
    let t = f.root().ok_or_else(bad)?;
    if let Some(n) = f.string(t, 0) {
        cx.format_set("name", truncate_chars(&n, 200));
    }
    if let Some(n) = f.string(t, 11) {
        cx.format_set("title", truncate_chars(&n, 200));
        cx.content().source("fgb.title").title(truncate_chars(&n, 200));
    }
    if let Some(d) = f.string(t, 12) {
        cx.content().source("fgb.description").description(truncate_chars(&d, 500));
    }
    cx.format_set("geometry_type", fgb_geometry(f.u8_field(t, 2).unwrap_or(0)));
    let dims: String =
        [(3, "Z"), (4, "M"), (5, "T"), (6, "TM")].iter().filter(|(n, _)| f.bool(t, *n)).map(|(_, d)| *d).collect();
    if !dims.is_empty() {
        cx.format_set("dimensions", dims.clone());
    }
    cx.format_set("features", f.u64_field(t, 8).unwrap_or(0));
    let node = f.u16_field(t, 9).unwrap_or(16);
    cx.format_set("index_node_size", node);
    let mut columns = Vec::new();
    for c in f.tables(t, 7).into_iter().take(1000) {
        let name = f.string(c, 0).unwrap_or_default();
        columns.push(format!("{} ({})", truncate_chars(&name, 60), fgb_column(f.u8_field(c, 1).unwrap_or(255))));
    }
    cx.format_set("columns", columns);
    let crs = f.table(t, 10).and_then(|c| {
        let code = f.u32_field(c, 1).filter(|&c| c != 0);
        let org = f.string(c, 0).unwrap_or_else(|| "EPSG".into());
        let wkt = f.string(c, 4).and_then(|w| Crs::from_wkt(&w));
        let name = f.string(c, 2);
        match (wkt, code) {
            (Some(mut w), c) => {
                if w.epsg.is_none() && org.eq_ignore_ascii_case("EPSG") {
                    w.epsg = c;
                }
                Some(w)
            }
            (None, Some(c)) if org.eq_ignore_ascii_case("EPSG") => {
                let mut x = Crs::epsg(c);
                x.name = name;
                Some(x)
            }
            _ => name.map(|n| Crs { name: Some(n), epsg: None, geographic: false }),
        }
    });
    let mut b = Bounds::default();
    if let Some((_, n)) = f.vector(t, 1).filter(|(_, n)| *n >= 4) {
        let d = |i| f.element(t, 1, i, 8).and_then(|s| s.try_into().ok()).map_or(f64::NAN, f64::from_le_bytes);
        b.add(d(0), d(1));
        b.add(d(2), d(3));
        if n >= 6 && dims.contains('Z') {
            b.add_z(d(4));
            b.add_z(d(5));
        }
    }
    if crs.is_some() {
        report_bounds(cx, &b, crs.as_ref(), "fgb.envelope");
    } else {
        report_native(cx, &b);
    }
    Ok(())
}

/// The fields of an ISO 8211 record: (tag, data).
type Fields<'a> = Vec<(String, &'a [u8])>;

/// An ISO 8211 record: its fields and its length.
fn iso8211_record(b: &[u8], at: usize) -> Option<(Fields<'_>, usize)> {
    let leader = b.get(at..at + 24)?;
    let digits = |s: &[u8]| std::str::from_utf8(s).ok()?.trim().parse::<usize>().ok();
    let len = digits(&leader[0..5])?;
    let base = digits(&leader[12..17])?;
    let size_len = usize::from(leader[20].checked_sub(b'0')?);
    let size_pos = usize::from(leader[21].checked_sub(b'0')?);
    let size_tag = usize::from(leader[23].checked_sub(b'0')?);
    let entry = size_tag + size_len + size_pos;
    if len < 24 || base < 24 || entry == 0 || entry > 20 {
        return None;
    }
    let rec = b.get(at..at + len)?;
    let mut fields = Vec::new();
    let mut i = 24;
    while i + entry <= base && rec.get(i) != Some(&0x1e) {
        let e = &rec[i..i + entry];
        let tag = String::from_utf8_lossy(&e[..size_tag]).into_owned();
        let flen = digits(&e[size_tag..size_tag + size_len])?;
        let fpos = digits(&e[size_tag + size_len..])?;
        let data = rec.get(base + fpos..base + fpos + flen)?;
        fields.push((tag, data));
        i += entry;
    }
    Some((fields, len))
}

/// Text up to the unit terminator.
fn unit(b: &[u8], at: &mut usize) -> String {
    let s = &b[(*at).min(b.len())..];
    let end = s.iter().position(|&c| c == 0x1f || c == 0x1e).unwrap_or(s.len());
    *at += end + 1;
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

/// S-57 object class codes and acronyms (IHO S-57 appendix A, as listed in
/// GDAL's `s57objectclasses.csv`).
const S57_CLASSES: [(u16, &str); 286] = [
    (0, ""),
    (0, ""),
    (1, "ADMARE"),
    (2, "AIRARE"),
    (3, "ACHBRT"),
    (4, "ACHARE"),
    (5, "BCNCAR"),
    (6, "BCNISD"),
    (7, "BCNLAT"),
    (8, "BCNSAW"),
    (9, "BCNSPP"),
    (10, "BERTHS"),
    (11, "BRIDGE"),
    (12, "BUISGL"),
    (13, "BUAARE"),
    (14, "BOYCAR"),
    (15, "BOYINB"),
    (16, "BOYISD"),
    (17, "BOYLAT"),
    (18, "BOYSAW"),
    (19, "BOYSPP"),
    (20, "CBLARE"),
    (21, "CBLOHD"),
    (22, "CBLSUB"),
    (23, "CANALS"),
    (24, "CANBNK"),
    (25, "CTSARE"),
    (26, "CAUSWY"),
    (27, "CTNARE"),
    (28, "CHKPNT"),
    (29, "CGUSTA"),
    (30, "COALNE"),
    (31, "CONZNE"),
    (32, "COSARE"),
    (33, "CTRPNT"),
    (34, "CONVYR"),
    (35, "CRANES"),
    (36, "CURENT"),
    (37, "CUSZNE"),
    (38, "DAMCON"),
    (39, "DAYMAR"),
    (40, "DWRTCL"),
    (41, "DWRTPT"),
    (42, "DEPARE"),
    (43, "DEPCNT"),
    (44, "DISMAR"),
    (45, "DOCARE"),
    (46, "DRGARE"),
    (47, "DRYDOC"),
    (48, "DMPGRD"),
    (49, "DYKCON"),
    (50, "EXEZNE"),
    (51, "FAIRWY"),
    (52, "FNCLNE"),
    (53, "FERYRT"),
    (54, "FSHZNE"),
    (55, "FSHFAC"),
    (56, "FSHGRD"),
    (57, "FLODOC"),
    (58, "FOGSIG"),
    (59, "FORSTC"),
    (60, "FRPARE"),
    (61, "GATCON"),
    (62, "GRIDRN"),
    (63, "HRBARE"),
    (64, "HRBFAC"),
    (65, "HULKES"),
    (66, "ICEARE"),
    (67, "ICNARE"),
    (68, "ISTZNE"),
    (69, "LAKARE"),
    (70, "LAKSHR"),
    (71, "LNDARE"),
    (72, "LNDELV"),
    (73, "LNDRGN"),
    (74, "LNDMRK"),
    (75, "LIGHTS"),
    (76, "LITFLT"),
    (77, "LITVES"),
    (78, "LOCMAG"),
    (79, "LOKBSN"),
    (80, "LOGPON"),
    (81, "MAGVAR"),
    (82, "MARCUL"),
    (83, "MIPARE"),
    (84, "MORFAC"),
    (85, "NAVLNE"),
    (86, "OBSTRN"),
    (87, "OFSPLF"),
    (88, "OSPARE"),
    (89, "OILBAR"),
    (90, "PILPNT"),
    (91, "PILBOP"),
    (92, "PIPARE"),
    (93, "PIPOHD"),
    (94, "PIPSOL"),
    (95, "PONTON"),
    (96, "PRCARE"),
    (97, "PRDARE"),
    (98, "PYLONS"),
    (99, "RADLNE"),
    (100, "RADRNG"),
    (101, "RADRFL"),
    (102, "RADSTA"),
    (103, "RTPBCN"),
    (104, "RDOCAL"),
    (105, "RDOSTA"),
    (106, "RAILWY"),
    (107, "RAPIDS"),
    (108, "RCRTCL"),
    (109, "RECTRC"),
    (110, "RCTLPT"),
    (111, "RSCSTA"),
    (112, "RESARE"),
    (113, "RETRFL"),
    (114, "RIVERS"),
    (115, "RIVBNK"),
    (116, "ROADWY"),
    (117, "RUNWAY"),
    (118, "SNDWAV"),
    (119, "SEAARE"),
    (120, "SPLARE"),
    (121, "SBDARE"),
    (122, "SLCONS"),
    (123, "SISTAT"),
    (124, "SISTAW"),
    (125, "SILTNK"),
    (126, "SLOTOP"),
    (127, "SLOGRD"),
    (128, "SMCFAC"),
    (129, "SOUNDG"),
    (130, "SPRING"),
    (131, "SQUARE"),
    (132, "STSLNE"),
    (133, "SUBTLN"),
    (134, "SWPARE"),
    (135, "TESARE"),
    (136, "TS_PRH"),
    (137, "TS_PNH"),
    (138, "TS_PAD"),
    (139, "TS_TIS"),
    (140, "T_HMON"),
    (141, "T_NHMN"),
    (142, "T_TIMS"),
    (143, "TIDEWY"),
    (144, "TOPMAR"),
    (145, "TSELNE"),
    (146, "TSSBND"),
    (147, "TSSCRS"),
    (148, "TSSLPT"),
    (149, "TSSRON"),
    (150, "TSEZNE"),
    (151, "TUNNEL"),
    (152, "TWRTPT"),
    (153, "UWTROC"),
    (154, "UNSARE"),
    (155, "VEGATN"),
    (156, "WATTUR"),
    (157, "WATFAL"),
    (158, "WEDKLP"),
    (159, "WRECKS"),
    (160, "TS_FEB"),
    (161, "ARCSLN"),
    (162, "ASLXIS"),
    (163, "NEWOBJ"),
    (300, "M_ACCY"),
    (301, "M_CSCL"),
    (302, "M_COVR"),
    (303, "M_HDAT"),
    (304, "M_HOPA"),
    (305, "M_NPUB"),
    (306, "M_NSYS"),
    (307, "M_PROD"),
    (308, "M_QUAL"),
    (309, "M_SDAT"),
    (310, "M_SREL"),
    (311, "M_UNIT"),
    (312, "M_VDAT"),
    (400, "C_AGGR"),
    (401, "C_ASSO"),
    (402, "C_STAC"),
    (500, "$AREAS"),
    (501, "$LINES"),
    (502, "$CSYMB"),
    (503, "$COMPS"),
    (504, "$TEXTS"),
    (17000, "achbrt"),
    (17001, "achare"),
    (17002, "canbnk"),
    (17003, "depare"),
    (17004, "dismar"),
    (17005, "resare"),
    (17006, "rivbnk"),
    (17007, "sistat"),
    (17008, "sistaw"),
    (17009, "topmar"),
    (17010, "berths"),
    (17011, "bridge"),
    (17012, "cblohd"),
    (17013, "feryrt"),
    (17014, "hrbare"),
    (17015, "hrbfac"),
    (17016, "lokbsn"),
    (17017, "rdocal"),
    (17018, "m_nsys"),
    (17050, "notmrk"),
    (17051, "wtwaxs"),
    (17052, "wtwprf"),
    (17053, "brgare"),
    (17054, "bunsta"),
    (17055, "comare"),
    (17056, "hrbbsn"),
    (17057, "lokare"),
    (17058, "lkbspt"),
    (17059, "prtare"),
    (17060, "bcnwtw"),
    (17061, "boywtw"),
    (17062, "refdmp"),
    (17063, "rtplpt"),
    (17064, "termnl"),
    (17065, "trnbsn"),
    (20484, "atsctl"),
    (20485, "airres + catasr"),
    (20486, "imgare"),
    (20487, "bchext"),
    (20488, "bchprf"),
    (20489, "bchare"),
    (20490, "bedare"),
    (20491, "botmft + catbot"),
    (20492, "centre"),
    (20494, "histob"),
    (20495, "ctlasp + catcas"),
    (20496, "divloc"),
    (20497, "watloc"),
    (20498, "drpzne"),
    (20499, "envare"),
    (20500, "fshare"),
    (20501, "iscour"),
    (20502, "lngare"),
    (20503, "lndplc"),
    (20504, "lndpnt"),
    (20505, "lndste"),
    (20506, "lndstp"),
    (20507, "lndzne"),
    (20508, "marman + catmma"),
    (20509, "msiare"),
    (20510, "mcmare"),
    (20511, "mexasp + catmea"),
    (20513, "patare + catpat"),
    (20514, "qroute"),
    (20515, "rdoare"),
    (20516, "regasp"),
    (20517, "sedlay"),
    (20518, "seiare"),
    (20519, "senanm"),
    (20520, "shlloc"),
    (20521, "seddep"),
    (20522, "trfare"),
    (20523, "twlscr"),
    (20524, "turnpt"),
    (20525, "viewpt"),
    (20526, "btdare"),
    (20527, "bprare"),
    (20528, "lsrare"),
    (20529, "pfdare"),
    (20530, "resloc"),
    (20531, "rkdare"),
    (20532, "navaid + CATROS"),
    (20533, "intwtr"),
    (20534, "seaice"),
    (20535, "iceadv"),
    (20536, "brgare"),
    (20537, "lndice"),
    (20538, "icelin"),
    (20539, "icerte"),
    (20540, "icepol"),
    (20541, "icelea"),
    (20542, "icebrg"),
    (20543, "icemov"),
    (20544, "tfcrte"),
    (20717, "u_defd"),
    (20718, "smalbo"),
    (21484, "m_conf + catcnf"),
    (21485, "m_clas"),
    (21486, "m_vers"),
    (21487, "m_line"),
];

fn object_class(code: u16) -> String {
    S57_CLASSES
        .binary_search_by_key(&code, |(c, _)| *c)
        .map_or_else(|_| format!("class {code}"), |i| S57_CLASSES[i].1.to_string())
}

#[allow(clippy::too_many_lines)] // DSID, DSPM, then the feature and vector records
fn s57(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let (_, ddr_len) = iso8211_record(b, 0).ok_or_else(|| ExtractError::malformed("ISO 8211 DDR"))?;
    let mut at = ddr_len;
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    let (mut features, mut vectors, mut records) = (0u64, 0u64, 0u64);
    let mut comf = 10_000_000.0f64;
    let mut coords: Vec<(i32, i32)> = Vec::new();
    while at < b.len() && records < 10_000_000 {
        records += 1;
        if records % 65_536 == 0 {
            cx.checkpoint()?;
        }
        let Some((fields, len)) = iso8211_record(b, at) else { break };
        at += len;
        for (tag, d) in &fields {
            match tag.as_str() {
                "DSID" => {
                    // RCNM, RCID (4), EXPP, INTU, then the text subfields.
                    let mut i = 7;
                    let name = unit(d, &mut i);
                    let edition = unit(d, &mut i);
                    let update = unit(d, &mut i);
                    let upd_date = d.get(i..i + 8).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
                    let issue =
                        d.get(i + 8..i + 16).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
                    let edition_std =
                        d.get(i + 16..i + 20).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
                    i += 21;
                    let _psdn = unit(d, &mut i);
                    let _pred = unit(d, &mut i);
                    let agency = d.get(i + 2..i + 4).map(|s| u16::from_le_bytes([s[0], s[1]]));
                    cx.format_set("dataset_name", truncate_chars(&name, 60));
                    cx.content().source("s57.DSID.DSNM").title(truncate_chars(&name, 60));
                    cx.format_set("edition", truncate_chars(&edition, 10));
                    cx.format_set("update", truncate_chars(&update, 10));
                    for (key, v) in [("update_date", upd_date), ("issue_date", issue)] {
                        if v.len() == 8 && v.bytes().all(|c| c.is_ascii_digit()) {
                            cx.format_set(key, format!("{}-{}-{}", &v[..4], &v[4..6], &v[6..]));
                        }
                    }
                    cx.format_set("s57_edition", truncate_chars(&edition_std, 10));
                    if let Some(a) = agency {
                        cx.format_set("producing_agency", a);
                    }
                }
                "DSPM" => {
                    let u32_at = |i: usize| d.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
                    if let Some(scale) = u32_at(8) {
                        cx.format_set("compilation_scale", format!("1:{scale}"));
                    }
                    if let Some(c) = u32_at(16).filter(|&c| c > 0) {
                        comf = f64::from(c);
                    }
                    cx.format_set("horizontal_datum", d.get(5).copied().unwrap_or(0));
                }
                "FRID" => {
                    features += 1;
                    if let Some(s) = d.get(7..9) {
                        let code = u16::from_le_bytes([s[0], s[1]]);
                        if classes.len() < 500 || classes.contains_key(&object_class(code)) {
                            *classes.entry(object_class(code)).or_default() += 1;
                        }
                    }
                }
                "VRID" => vectors += 1,
                // Coordinates: (YCOO, XCOO[, VE3D]) as signed 32-bit integers.
                "SG2D" | "SG3D" => {
                    let step = if tag == "SG2D" { 8 } else { 12 };
                    for c in d.chunks_exact(step).take(1_000_000) {
                        if coords.len() < 50_000_000 {
                            coords.push((
                                i32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                                i32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let mut bounds = Bounds::default();
    for (y, x) in coords {
        bounds.add(f64::from(x) / comf, f64::from(y) / comf);
    }
    cx.format_set("records", records);
    cx.format_set("feature_records", features);
    cx.format_set("vector_records", vectors);
    let mut top: Vec<(String, u64)> = classes.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    cx.format_set("object_classes", hist(top.into_iter().take(40).collect()));
    report_bounds(cx, &bounds, Some(&Crs::epsg(4326)), "s57.SG2D");
    Ok(())
}

impl Extractor for Vector {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // An ISO 8211 DDR leader whose first data record holds a DSID.
        let iso = h.len() > 24 && h[..5].iter().all(u8::is_ascii_digit) && h[6] == b'L' && h[5] == b'3';
        let s57 = iso && h.windows(4).any(|w| w == b"DSID") && h.windows(4).any(|w| w == b"FRID" || w == b"VRID");
        s57.then_some(Sniff { format: "s57", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "flatgeobuf" {
            return flatgeobuf(cx, src);
        }
        let (b, _) = cx.read_bytes(src)?;
        s57(cx, &b)
    }
}

crate::register_extractor!(Vector);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8211_leader() {
        // One field "0001" of 3 bytes: leader, directory, terminator, data.
        let dir = b"00010030000\x1e";
        let base = 24 + dir.len();
        let len = base + 3;
        let mut r = format!("{len:05}3LE1 06{base:05}   3404").into_bytes();
        r.extend(dir);
        r.extend(b"ab\x1e");
        let (fields, n) = iso8211_record(&r, 0).unwrap();
        assert_eq!((fields[0].0.as_str(), fields[0].1, n), ("0001", &b"ab\x1e"[..], len));
        let mut i = 0;
        assert_eq!(unit(b"US5\x1f1\x1f", &mut i), "US5");
        assert_eq!(unit(b"US5\x1f1\x1f", &mut i), "1");
    }

    crate::fixture_tests!("flatgeobuf", "s57");
}
