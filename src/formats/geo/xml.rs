//! XML-based geodata:
//! * KML (and KMZ archives): document name and description, placemarks,
//!   folders, geometry types, network links, time span, bounds;
//! * GPX 1.0 / 1.1: creator, metadata, waypoints, routes, tracks with
//!   their fixes, distance, elevation range and time span;
//! * GML 2 / 3 and `CityGML`: the root, CRS, feature members, geometry types,
//!   city object types, declared envelope and bounds;
//! * Garmin TCX: activities, sports, laps, distance, time, track points;
//! * OpenStreetMap XML: generator, bounds, nodes, ways, relations, the
//!   edit time span and tag keys; OSM change files: create / modify /
//!   delete counts;
//! * OGC SLD: named layers, styles, rules, symbolizers;
//! * Geocaching LOC and `GeoRSS` feeds: waypoints and items with their
//!   positions;
//! * QGIS projects (`.qgs`, `.qgz`): title, CRS, layers by type and
//!   provider.
//!
//! Specifications: OGC KML 2.3; GPX 1.1 schema; OGC GML 3.2.1 and `CityGML`
//! 2.0 / 3.0; Garmin `TrainingCenterDatabase` v2; OSM XML and osmChange
//! (OSM wiki); OGC SLD 1.1; `GeoRSS` Simple and GML; QGIS project file
//! (`.qgs`).

use std::collections::{BTreeMap, BTreeSet};

use super::{Bounds, Crs, Ev, Track, attr, hist, num, report_bounds, walk_xml, xml_root};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip,
    parse_date, truncate_chars, zip_names,
};

/// Extractor for XML-based geodata.
pub struct GeoXml;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.xml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "kml",
            name: "KML / KMZ",
            family: "geo",
            mimes: &["application/vnd.google-earth.kml+xml"],
            extensions: &["kml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "kmz",
            name: "KMZ archive",
            family: "geo",
            mimes: &["application/vnd.google-earth.kmz"],
            extensions: &["kmz"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "gpx",
            name: "GPX",
            family: "geo",
            mimes: &["application/gpx+xml"],
            extensions: &["gpx"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "gml",
            name: "GML / CityGML",
            family: "geo",
            mimes: &["application/gml+xml"],
            extensions: &["gml", "citygml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "tcx",
            name: "Garmin TCX",
            family: "geo",
            mimes: &[],
            extensions: &["tcx"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "osm_xml",
            name: "OpenStreetMap PBF / XML",
            family: "geo",
            mimes: &["application/x-osm+xml"],
            extensions: &["osm"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "osc",
            name: "OSM change / diff",
            family: "geo",
            mimes: &[],
            extensions: &["osc"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "sld",
            name: "OGC SLD style",
            family: "geo",
            mimes: &[],
            extensions: &["sld"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "loc",
            name: "Geocaching LOC / GeoRSS",
            family: "geo",
            mimes: &[],
            extensions: &["loc"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "georss",
            name: "GeoRSS feed",
            family: "geo",
            mimes: &[],
            extensions: &["georss"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "qgis",
            name: "QGIS / ArcGIS project",
            family: "geo",
            mimes: &[],
            extensions: &["qgs"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "qgz",
            name: "QGIS project archive",
            family: "geo",
            mimes: &[],
            extensions: &["qgz"],
            magic: &[],
            parent: Some("zip"),
        },
    ],
};

const MAX_EVENTS: usize = 50_000_000;

/// Whitespace-separated `x,y[,z]` tuples (KML, GML 2 `coordinates`).
fn tuples(text: &str, b: &mut Bounds) {
    for t in text.split_whitespace().take(10_000_000) {
        let mut it = t.split(',').map(|v| v.parse::<f64>().ok());
        if let (Some(Some(x)), Some(Some(y))) = (it.next(), it.next()) {
            b.add(x, y);
            if let Some(Some(z)) = it.next() {
                b.add_z(z);
            }
        }
    }
}

/// A space-separated coordinate list (GML 3 `pos` / `posList`), `dim`
/// values per point, swapped for latitude-first CRSs.
fn pos_list(text: &str, dim: usize, swap: bool, b: &mut Bounds) {
    let vals: Vec<f64> = text.split_whitespace().take(30_000_000).filter_map(|v| v.parse().ok()).collect();
    for p in vals.chunks_exact(dim.max(2)) {
        if swap {
            b.add(p[1], p[0]);
        } else {
            b.add(p[0], p[1]);
        }
        if dim > 2 {
            b.add_z(p[2]);
        }
    }
}

/// Element-path state shared by the walkers: the current element stack.
#[derive(Default)]
struct Path(Vec<String>);

impl Path {
    fn top(&self) -> &str {
        self.0.last().map_or("", String::as_str)
    }
    fn parent(&self) -> &str {
        self.0.len().checked_sub(2).and_then(|i| self.0.get(i)).map_or("", String::as_str)
    }
    fn within(&self, name: &str) -> bool {
        self.0.iter().any(|n| n == name)
    }
}

fn kml(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let (mut placemarks, mut folders, mut links, mut styles) = (0u64, 0u64, 0u64, 0u64);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Bounds::default();
    let (mut name, mut desc, mut author) = (None, None, None);
    let mut times: Vec<String> = Vec::new();
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, _) => {
            match n {
                "Placemark" => placemarks += 1,
                "Folder" => folders += 1,
                "NetworkLink" => links += 1,
                "Style" | "StyleMap" => styles += 1,
                "Point" | "LineString" | "LinearRing" | "Polygon" | "MultiGeometry" | "Model" | "Track"
                | "MultiTrack" | "GroundOverlay" | "PhotoOverlay" | "ScreenOverlay"
                    if (n != "LinearRing" || !p.within("Polygon")) =>
                {
                    *types.entry(n.into()).or_default() += 1;
                }
                _ => {}
            }
            p.0.push(n.into());
        }
        Ev::End(_) => {
            p.0.pop();
        }
        Ev::Text(t) => match (p.top(), p.parent()) {
            ("coordinates", _) => tuples(t, &mut b),
            ("coord", _) => {
                // gx:Track: "lon lat alt".
                let v: Vec<f64> = t.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                if v.len() >= 2 {
                    b.add(v[0], v[1]);
                }
            }
            ("name", "Document" | "kml") if name.is_none() => name = Some(truncate_chars(t, 200)),
            ("description", "Document") if desc.is_none() => desc = Some(truncate_chars(t, 500)),
            ("name", "author") if author.is_none() => author = Some(truncate_chars(t, 100)),
            ("when" | "begin" | "end", _) if times.len() < 1_000_000 => times.push(t.to_string()),
            _ => {}
        },
    })?;
    if let Some(n) = &name {
        cx.format_set("name", n.clone());
        cx.content().source("kml.Document.name").title(n.clone());
    }
    if let Some(d) = desc {
        cx.content().source("kml.Document.description").description(d);
    }
    if let Some(a) = author {
        cx.content().source("kml.author").author(a);
    }
    cx.format_set("placemarks", placemarks);
    cx.format_set("folders", folders);
    cx.format_set("styles", styles);
    if links > 0 {
        cx.format_set("network_links", links);
    }
    cx.format_set("geometry_types", hist(types));
    time_span(cx, &mut times, "kml.when");
    report_bounds(cx, &b, None, "kml.coordinates");
    Ok(())
}

/// The earliest and latest of ISO 8601 times.
fn time_span(cx: &mut Context<'_>, times: &mut [String], source: &str) {
    times.sort();
    if let (Some(a), Some(z)) = (times.first(), times.last()) {
        cx.format_set("time_start", a.clone());
        cx.format_set("time_end", z.clone());
        if let Some((t, tz)) = parse_date(a) {
            cx.temporal().source(source.to_string()).content_date(DateField::Captured, t, tz);
        }
    }
}

#[allow(clippy::too_many_lines)] // the walk, then the report
fn gpx(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let (mut wpts, mut rtes, mut trks, mut segs) = (0u64, 0u64, 0u64, 0u64);
    let mut track = Track::default();
    let mut other = Bounds::default();
    let mut pending: Option<(f64, f64)> = None;
    let (mut ele, mut time) = (None::<f64>, None::<String>);
    let mut meta: BTreeMap<&str, String> = BTreeMap::new();
    let mut root = BTreeMap::new();
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            match n {
                "gpx" => {
                    for k in ["version", "creator"] {
                        if let Some(v) = attr(a, k) {
                            root.insert(k, truncate_chars(v, 100));
                        }
                    }
                }
                "wpt" => wpts += 1,
                "rte" => rtes += 1,
                "trk" => trks += 1,
                "trkseg" => {
                    segs += 1;
                    track.break_segment();
                }
                _ => {}
            }
            if matches!(n, "wpt" | "rtept" | "trkpt") {
                let f = |k| attr(a, k).and_then(|v| v.trim().parse::<f64>().ok());
                pending = f("lat").zip(f("lon"));
                (ele, time) = (None, None);
            }
            if n == "bounds" {
                let f = |k| attr(a, k).and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(f64::NAN);
                meta.insert(
                    "declared_bounds",
                    format!("{} {} {} {}", f("minlon"), f("minlat"), f("maxlon"), f("maxlat")),
                );
            }
            p.0.push(n.into());
        }
        Ev::End(n) => {
            if let Some((lat, lon)) = pending.filter(|_| matches!(n, "wpt" | "rtept" | "trkpt")) {
                if n == "trkpt" {
                    track.fix(lat, lon, ele, time.as_deref());
                } else {
                    other.add(lon, lat);
                }
                pending = None;
            }
            p.0.pop();
        }
        Ev::Text(t) => match (p.top(), p.parent()) {
            ("ele", _) => ele = t.parse().ok(),
            ("time", "trkpt" | "wpt" | "rtept") => time = Some(t.to_string()),
            ("name", "metadata") => {
                meta.entry("name").or_insert_with(|| truncate_chars(t, 200));
            }
            ("name", "trk") => {
                meta.entry("first_track").or_insert_with(|| truncate_chars(t, 200));
            }
            ("desc", "metadata") => {
                meta.entry("desc").or_insert_with(|| truncate_chars(t, 500));
            }
            ("name", "author") => {
                meta.entry("author").or_insert_with(|| truncate_chars(t, 100));
            }
            ("time", "metadata") => {
                meta.entry("time").or_insert_with(|| truncate_chars(t, 40));
            }
            _ => {}
        },
    })?;
    for (k, v) in root {
        cx.format_set(if k == "version" { "gpx_version" } else { k }, v);
    }
    if let Some(n) = meta.get("name").or_else(|| meta.get("first_track")) {
        cx.format_set("name", n.clone());
        cx.content().source("gpx.name").title(n.clone());
    }
    if let Some(d) = meta.get("desc") {
        cx.content().source("gpx.metadata.desc").description(d.clone());
    }
    if let Some(a) = meta.get("author") {
        cx.content().source("gpx.metadata.author").author(a.clone());
    }
    if let Some(t) = meta.get("time") {
        cx.format_set("time", t.clone());
        if let Some((d, tz)) = parse_date(t) {
            cx.temporal().source("gpx.metadata.time").content_date(DateField::Created, d, tz);
        }
    }
    cx.format_set("waypoints", wpts);
    cx.format_set("routes", rtes);
    cx.format_set("tracks", trks);
    cx.format_set("track_segments", segs);
    if let Some(s) = &track.first_time
        && let Some((d, tz)) = parse_date(s)
    {
        cx.temporal().source("gpx.trkpt.time").content_date(DateField::Captured, d, tz);
    }
    let mut all = track.bounds;
    all.merge(&other);
    let t = Track { bounds: all, ..track };
    t.report(cx, "gpx");
    Ok(())
}

fn gml(cx: &mut Context<'_>, text: &str, root_tag: &str) -> Result<(), ExtractError> {
    let city = root_tag.contains("citygml");
    if city {
        let v = root_tag.split("opengis.net/citygml/").nth(1).and_then(|r| r.split(['/', '"']).next()).unwrap_or("");
        cx.format_set("citygml_version", truncate_chars(v, 10));
    }
    let mut p = Path::default();
    let mut members = 0u64;
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut objects: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Bounds::default();
    let mut envelope = Bounds::default();
    let mut crs: Option<Crs> = None;
    // URN and URL references follow the EPSG axis order: latitude first
    // for geographic CRSs; `EPSG:n` and CRS84 are longitude first.
    let mut lat_first = false;
    let mut dim = 2usize;
    let mut root = None;
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            if root.is_none() {
                root = Some(n.to_string());
            }
            if let Some(s) = attr(a, "srsName").filter(|_| crs.is_none()) {
                crs = Crs::from_ref(s);
                let long_form = s.starts_with("urn:") || s.contains("/def/crs/");
                lat_first = long_form && !s.contains("CRS84") && crs.as_ref().is_some_and(|c| c.geographic);
            }
            if let Some(d) = attr(a, "srsDimension").and_then(|d| d.parse().ok()) {
                dim = d;
            }
            match n {
                "featureMember" | "featureMembers" | "member" | "cityObjectMember" => members += 1,
                "Point"
                | "LineString"
                | "Polygon"
                | "MultiPoint"
                | "MultiLineString"
                | "MultiPolygon"
                | "MultiCurve"
                | "MultiSurface"
                | "Surface"
                | "Solid"
                | "CompositeSurface"
                | "TriangulatedSurface"
                | "Curve"
                | "MultiGeometry" => {
                    // Count outer geometries only.
                    let nested = p.0.iter().any(|e| {
                        matches!(
                            e.as_str(),
                            "MultiPolygon"
                                | "MultiSurface"
                                | "Solid"
                                | "CompositeSurface"
                                | "MultiCurve"
                                | "MultiGeometry"
                                | "MultiPoint"
                                | "MultiLineString"
                        )
                    });
                    if !nested {
                        *types.entry(n.into()).or_default() += 1;
                    }
                }
                _ => {}
            }
            if city && matches!(p.top(), "cityObjectMember") {
                *objects.entry(n.into()).or_default() += 1;
            }
            p.0.push(n.into());
        }
        Ev::End(_) => {
            p.0.pop();
        }
        Ev::Text(t) => {
            let swap = lat_first;
            let in_env = p.within("Envelope") || p.within("boundedBy") && !p.within("featureMember");
            let target = if in_env && p.0.len() <= 4 { &mut envelope } else { &mut b };
            match p.top() {
                "coordinates" => tuples(t, target),
                "pos" | "posList" | "lowerCorner" | "upperCorner" => pos_list(t, dim, swap, target),
                _ => {}
            }
        }
    })?;
    if let Some(r) = root {
        cx.format_set("root", r);
    }
    cx.format_set("feature_members", members);
    cx.format_set("geometry_types", hist(types));
    if city {
        cx.format_set("city_objects", hist(objects));
    }
    if !envelope.is_empty() {
        cx.format_set("declared_envelope", envelope.json());
    }
    if b.is_empty() {
        b = envelope;
    }
    report_bounds(cx, &b, crs.as_ref(), "gml.pos");
    Ok(())
}

fn tcx(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let mut sports: BTreeMap<String, u64> = BTreeMap::new();
    let (mut activities, mut laps) = (0u64, 0u64);
    let (mut lap_time, mut lap_dist) = (0.0f64, 0.0f64);
    let mut track = Track::default();
    let (mut lat, mut lon, mut alt, mut time) = (None::<f64>, None::<f64>, None::<f64>, None::<String>);
    let mut creator = None;
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            match n {
                "Activity" => {
                    activities += 1;
                    if let Some(s) = attr(a, "Sport") {
                        *sports.entry(truncate_chars(s, 30)).or_default() += 1;
                    }
                }
                "Lap" => laps += 1,
                "Trackpoint" => (lat, lon, alt, time) = (None, None, None, None),
                "Track" => track.break_segment(),
                _ => {}
            }
            p.0.push(n.into());
        }
        Ev::End(n) => {
            if n == "Trackpoint"
                && let (Some(la), Some(lo)) = (lat, lon)
            {
                track.fix(la, lo, alt, time.as_deref());
            }
            p.0.pop();
        }
        Ev::Text(t) => match (p.top(), p.parent()) {
            ("LatitudeDegrees", _) => lat = t.parse().ok(),
            ("LongitudeDegrees", _) => lon = t.parse().ok(),
            ("AltitudeMeters", "Trackpoint") => alt = t.parse().ok(),
            ("Time", "Trackpoint") => time = Some(t.to_string()),
            ("TotalTimeSeconds", "Lap") => lap_time += t.parse::<f64>().unwrap_or(0.0),
            ("DistanceMeters", "Lap") => lap_dist += t.parse::<f64>().unwrap_or(0.0),
            ("Name", "Creator") if creator.is_none() => creator = Some(truncate_chars(t, 100)),
            _ => {}
        },
    })?;
    cx.format_set("activities", activities);
    cx.format_set("sports", hist(sports));
    cx.format_set("laps", laps);
    if laps > 0 {
        cx.format_set("lap_time_s", num(lap_time, 1));
        cx.format_set("lap_distance_km", num(lap_dist / 1000.0, 3));
    }
    if let Some(c) = creator {
        cx.format_set("device", c);
    }
    if let Some(s) = &track.first_time
        && let Some((d, tz)) = parse_date(s)
    {
        cx.temporal().source("tcx.Trackpoint.Time").content_date(DateField::Captured, d, tz);
    }
    track.report(cx, "tcx");
    Ok(())
}

fn osm(cx: &mut Context<'_>, text: &str, change: bool) -> Result<(), ExtractError> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    if !change {
        for k in ["nodes", "ways", "relations"] {
            counts.insert(k.into(), 0);
        }
    }
    let mut keys: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Bounds::default();
    let mut times: Vec<String> = Vec::new();
    let mut action = String::new();
    let mut root: BTreeMap<&str, String> = BTreeMap::new();
    let mut users = BTreeSet::new();
    walk_xml(text, cx, MAX_EVENTS, |_, ev| {
        let Ev::Start(n, a) = ev else {
            if let Ev::End(n @ ("create" | "modify" | "delete")) = ev {
                let _ = n;
                action.clear();
            }
            return;
        };
        match n {
            "osm" | "osmChange" => {
                for k in ["version", "generator"] {
                    if let Some(v) = attr(a, k) {
                        root.insert(k, truncate_chars(v, 100));
                    }
                }
            }
            "create" | "modify" | "delete" => action = n.to_string(),
            "bounds" => {
                let f = |k| attr(a, k).and_then(|v| v.parse::<f64>().ok()).unwrap_or(f64::NAN);
                root.insert(
                    "declared_bounds",
                    format!("{} {} {} {}", f("minlon"), f("minlat"), f("maxlon"), f("maxlat")),
                );
            }
            "node" | "way" | "relation" => {
                let key = if change {
                    format!("{}_{n}s", if action.is_empty() { "other" } else { &action })
                } else {
                    format!("{n}s")
                };
                *counts.entry(key).or_default() += 1;
                if n == "node"
                    && let (Some(la), Some(lo)) =
                        (attr(a, "lat").and_then(|v| v.parse().ok()), attr(a, "lon").and_then(|v| v.parse().ok()))
                {
                    b.add(lo, la);
                }
                if let Some(t) = attr(a, "timestamp")
                    && times.len() < 2
                {
                    // Keep the earliest and latest only.
                    times.push(t.to_string());
                } else if let Some(t) = attr(a, "timestamp") {
                    times.sort();
                    if t < times[0].as_str() {
                        times[0] = t.to_string();
                    } else if t > times[1].as_str() {
                        times[1] = t.to_string();
                    }
                }
                if let Some(u) = attr(a, "uid")
                    && users.len() < 1_000_000
                {
                    users.insert(u.to_string());
                }
            }
            "tag" => {
                if let Some(k) = attr(a, "k")
                    && (keys.len() < 2000 || keys.contains_key(k))
                {
                    *keys.entry(truncate_chars(k, 60)).or_default() += 1;
                }
            }
            _ => {}
        }
    })?;
    for (k, v) in root {
        cx.format_set(k, v);
    }
    cx.format_set(if change { "changes" } else { "elements" }, hist(counts));
    if !users.is_empty() {
        cx.format_set("contributors", users.len());
    }
    let mut top: Vec<(String, u64)> = keys.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    cx.format_set("top_tag_keys", hist(top.into_iter().take(20).collect()));
    time_span(cx, &mut times, "osm.timestamp");
    report_bounds(cx, &b, None, "osm.node");
    Ok(())
}

fn sld(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let (mut layers, mut styles) = (Vec::new(), Vec::new());
    let mut rules = 0u64;
    let mut symbolizers: BTreeMap<String, u64> = BTreeMap::new();
    let mut version = None;
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            if n == "StyledLayerDescriptor" {
                version = attr(a, "version").map(|v| truncate_chars(v, 10));
            }
            if n == "Rule" {
                rules += 1;
            }
            if n.ends_with("Symbolizer") {
                *symbolizers.entry(n.trim_end_matches("Symbolizer").into()).or_default() += 1;
            }
            p.0.push(n.into());
        }
        Ev::End(_) => {
            p.0.pop();
        }
        Ev::Text(t) => match (p.top(), p.parent()) {
            ("Name", "NamedLayer" | "UserLayer") if layers.len() < 200 => layers.push(truncate_chars(t, 100)),
            ("Name" | "Title", "UserStyle") if styles.len() < 200 => styles.push(truncate_chars(t, 100)),
            _ => {}
        },
    })?;
    if let Some(v) = version {
        cx.format_set("sld_version", v);
    }
    if let Some(t) = layers.first().or(styles.first()) {
        cx.content().source("sld.Name").title(t.clone());
    }
    cx.format_set("layers", layers);
    cx.format_set("styles", styles);
    cx.format_set("rules", rules);
    cx.format_set("symbolizers", hist(symbolizers));
    Ok(())
}

fn loc(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let mut b = Bounds::default();
    let (mut waypoints, mut names) = (0u64, Vec::new());
    let mut src = None;
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            match n {
                "loc" => src = attr(a, "src").map(|s| truncate_chars(s, 60)),
                "waypoint" => waypoints += 1,
                "coord" => {
                    let f = |k| attr(a, k).and_then(|v| v.trim().parse::<f64>().ok());
                    if let (Some(la), Some(lo)) = (f("lat"), f("lon")) {
                        b.add(lo, la);
                    }
                }
                "name" => {
                    if let Some(id) = attr(a, "id")
                        && names.len() < 100
                    {
                        names.push(truncate_chars(id, 40));
                    }
                }
                _ => {}
            }
            p.0.push(n.into());
        }
        Ev::End(_) => {
            p.0.pop();
        }
        Ev::Text(_) => {}
    })?;
    if let Some(s) = src {
        cx.format_set("source", s);
    }
    cx.format_set("waypoints", waypoints);
    cx.format_set("waypoint_ids", names);
    report_bounds(cx, &b, None, "loc.coord");
    Ok(())
}

fn georss(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let mut b = Bounds::default();
    let (mut items, mut located) = (0u64, 0u64);
    let mut title = None;
    let (mut lat, mut lon) = (None::<f64>, None::<f64>);
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, _) => {
            if matches!(n, "item" | "entry") {
                items += 1;
            }
            p.0.push(n.into());
        }
        Ev::End(n) => {
            if matches!(n, "item" | "entry") {
                (lat, lon) = (None, None);
            }
            p.0.pop();
        }
        Ev::Text(t) => {
            let before = b.points;
            match p.top() {
                // GeoRSS Simple and GML give "lat lon"; W3C geo gives lat / long.
                "point" | "pos" | "line" | "polygon" | "posList" | "box" => pos_list(t, 2, true, &mut b),
                "lat" => lat = t.parse().ok(),
                "long" | "lon" => lon = t.parse().ok(),
                "title" if title.is_none() && matches!(p.parent(), "channel" | "feed") => {
                    title = Some(truncate_chars(t, 200));
                }
                _ => {}
            }
            if let (Some(la), Some(lo)) = (lat, lon) {
                b.add(lo, la);
                (lat, lon) = (None, None);
            }
            if b.points > before && (p.within("item") || p.within("entry")) {
                located += 1;
            }
        }
    })?;
    if let Some(t) = title {
        cx.format_set("title", t.clone());
        cx.content().source("georss.title").title(t);
    }
    cx.format_set("items", items);
    cx.format_set("located_items", located);
    report_bounds(cx, &b, None, "georss");
    Ok(())
}

fn qgis(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut p = Path::default();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut providers: BTreeMap<String, u64> = BTreeMap::new();
    let mut layers = Vec::new();
    let mut root: BTreeMap<&str, String> = BTreeMap::new();
    let mut crs = None;
    walk_xml(text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(n, a) => {
            if n == "qgis" {
                for k in ["version", "projectname"] {
                    if let Some(v) = attr(a, k).filter(|v| !v.is_empty()) {
                        root.insert(k, truncate_chars(v, 100));
                    }
                }
            }
            if n == "maplayer"
                && let Some(t) = attr(a, "type")
            {
                *types.entry(truncate_chars(t, 20)).or_default() += 1;
            }
            p.0.push(n.into());
        }
        Ev::End(_) => {
            p.0.pop();
        }
        Ev::Text(t) => match (p.top(), p.parent()) {
            ("title", "qgis") => {
                root.insert("title", truncate_chars(t, 200));
            }
            ("authid", "spatialrefsys") if crs.is_none() && p.within("projectCrs") => crs = Crs::from_ref(t),
            ("layername", "maplayer") if layers.len() < 500 => layers.push(truncate_chars(t, 100)),
            ("provider", "maplayer") => *providers.entry(truncate_chars(t, 30)).or_default() += 1,
            _ => {}
        },
    })?;
    if let Some(t) = root.get("title").or_else(|| root.get("projectname")) {
        cx.content().source("qgis.title").title(t.clone());
    }
    for (k, v) in root {
        cx.format_set(if k == "version" { "qgis_version" } else { k }, v);
    }
    if let Some(c) = crs {
        cx.format_set("crs", c.json());
    }
    cx.format_set("layer_count", layers.len());
    cx.format_set("layer_types", hist(types));
    cx.format_set("providers", hist(providers));
    cx.format_set("layers", layers);
    Ok(())
}

/// The documents of a ZIP: every `.kml` of a KMZ (`doc.kml` first; it
/// often links the others), the first `.qgs` of a QGZ.
fn zipped(src: &mut dyn Source, cx: &mut Context<'_>, ext: &str) -> Result<String, ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let mut docs: Vec<String> =
        zip.entries.iter().map(|e| e.name.clone()).filter(|n| n.to_ascii_lowercase().ends_with(ext)).collect();
    docs.sort_by_key(|n| !n.eq_ignore_ascii_case("doc.kml"));
    if ext == ".qgs" {
        docs.truncate(1);
    }
    let main = docs.first().cloned().ok_or_else(|| ExtractError::malformed(format!("no {ext} entry")))?;
    cx.format_set("document", truncate_chars(&main, 200));
    cx.format_set("entries", zip.entries.len());
    if docs.len() > 1 {
        cx.format_set("documents", docs.len());
    }
    // Concatenated: the walker reads one root after another.
    let mut text = String::new();
    let mut left = cx.parse_limit();
    for d in docs.iter().take(100) {
        let t = zip.read_text(src, d, cx, left).ok_or_else(|| ExtractError::malformed("entry"))??;
        left = left.saturating_sub(t.len());
        text.push_str(&t);
        text.push('\n');
        if left == 0 {
            break;
        }
    }
    Ok(text)
}

impl Extractor for GeoXml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if h.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 200);
            let any = |suffix: &str| names.iter().any(|n| n.to_ascii_lowercase().ends_with(suffix));
            return match probe.extension {
                Some("kmz") if any(".kml") => sure("kmz"),
                _ if names.iter().any(|n| n.eq_ignore_ascii_case("doc.kml")) => sure("kmz"),
                Some("qgz") if any(".qgs") => sure("qgz"),
                _ => None,
            };
        }
        let (root, tag) = xml_root(h)?;
        let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
        match root.as_str() {
            "kml" => sure("kml"),
            "gpx" => sure("gpx"),
            "TrainingCenterDatabase" => sure("tcx"),
            "osm" if tag.contains("version") || has(b"<node") || has(b"<bounds") => sure("osm_xml"),
            "osmChange" => sure("osc"),
            "StyledLayerDescriptor" => sure("sld"),
            "loc" if has(b"<waypoint") => sure("loc"),
            "qgis" => sure("qgis"),
            "rss" | "feed" | "RDF" if has(b"georss") || has(b"w3.org/2003/01/geo") => sure("georss"),
            _ if tag.contains("opengis.net/gml") || tag.contains("opengis.net/citygml") => sure("gml"),
            _ if probe.extension == Some("gml") => Some(Sniff { format: "gml", confidence: 0.9 }),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "kmz" => {
                let text = zipped(src, cx, ".kml")?;
                return kml(cx, &text);
            }
            "qgz" => {
                let text = zipped(src, cx, ".qgs")?;
                return qgis(cx, &text);
            }
            _ => {}
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "kml" => kml(cx, &text),
            "gpx" => gpx(cx, &text),
            "gml" => {
                let tag = xml_root(text.as_bytes()).map(|(_, t)| t).unwrap_or_default();
                gml(cx, &text, &tag)
            }
            "tcx" => tcx(cx, &text),
            "osm_xml" => osm(cx, &text, false),
            "osc" => osm(cx, &text, true),
            "sld" => sld(cx, &text),
            "loc" => loc(cx, &text),
            "georss" => georss(cx, &text),
            _ => qgis(cx, &text),
        }
    }
}

crate::register_extractor!(GeoXml);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinate_text() {
        let mut b = Bounds::default();
        tuples("1,2,3 -4,5\n6,-7,0", &mut b);
        assert_eq!((b.min, b.max, b.points), ([-4.0, -7.0, 0.0], [6.0, 5.0, 3.0], 3));
        let mut s = Bounds::default();
        pos_list("50 10 51 11", 2, true, &mut s);
        assert_eq!((s.min[0], s.min[1], s.max[0], s.max[1]), (10.0, 50.0, 11.0, 51.0));
    }

    crate::fixture_tests!("kml", "kmz", "gpx", "gml", "tcx", "osm_xml", "osc", "sld", "loc", "georss", "qgis", "qgz");
}
