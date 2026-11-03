//! Font sources:
//! * FontForge `.sfd`: names, weight, version, copyright, italic angle,
//!   units per em, embedding, vendor, dates, glyph count, OpenType
//!   features, bitmap strikes;
//! * Glyphs `.glyphs` (2 and 3): family, version, designer, manufacturer,
//!   copyright, licence, date, units per em, masters, instances, axes,
//!   glyph count, features;
//! * UFO `fontinfo.plist`: the font info (names, version, designer,
//!   licence, embedding, dates, metrics);
//! * Metafont `.mf`: identifier, coding scheme, design size, character
//!   count and the files it inputs.
//!
//! Specifications: FontForge "Spline Font Database" file format; Glyphs
//! file format specification (glyphsapp/GlyphsSDK); Unified Font Object 3
//! (`fontinfo.plist`); Knuth, "The METAFONTbook".

use plist::Value as Plist;

use super::embedding;
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    identify_license, parse_date, proplist, truncate_chars,
};

/// Extractor for font sources.
pub struct FontSource;

static META: ExtractorMeta = ExtractorMeta {
    id: "font.source",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "sfd",
            name: "FontForge source",
            family: "font",
            mimes: &[],
            extensions: &["sfd"],
            magic: &[Magic::at(0, b"SplineFontDB:")],
            parent: None,
        },
        FormatSpec {
            id: "glyphs",
            name: "Glyphs source",
            family: "font",
            mimes: &[],
            extensions: &["glyphs"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ufo_fontinfo",
            name: "UFO font info",
            family: "font",
            mimes: &[],
            extensions: &["ufo"],
            magic: &[],
            parent: Some("plist"),
        },
        FormatSpec {
            id: "metafont",
            name: "Metafont source",
            family: "font",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Names listed (instances, masters, inputs).
const MAX_NAMES: usize = 100;

fn has(h: &[u8], needle: &[u8]) -> bool {
    h.windows(needle.len()).any(|w| w == needle)
}

/// Unix seconds as RFC 3339.
fn secs(cx: &mut Context<'_>, key: &str, field: DateField, v: &str) {
    if let Some(t) = v.trim().parse::<i64>().ok().and_then(super::unix_time) {
        cx.format_set(key, t.clone());
        cx.temporal().source(format!("source.{key}")).content_date(field, t, true);
    }
}

fn licence(cx: &mut Context<'_>, text: Option<&str>, url: Option<&str>) {
    if let Some(l) = text {
        cx.format_set("license", truncate_chars(l, 2000));
    }
    if let Some(u) = url {
        cx.format_set("license_url", truncate_chars(u, 500));
    }
    let short = text.map(|l| identify_license(l).map_or_else(|| truncate_chars(l, 200), str::to_string));
    cx.rights().source("source.license").license(short.as_deref(), url);
}

fn sfd(cx: &mut Context<'_>, text: &str) {
    let mut features = std::collections::BTreeSet::new();
    let mut strikes = 0u64;
    let (mut ascent, mut descent) = (None, None);
    for line in text.lines().take(500_000) {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key {
            "SplineFontDB" => cx.format_set("sfd_version", value),
            "FontName" => cx.format_set("postscript_name", truncate_chars(value, 200)),
            "FullName" => {
                cx.format_set("full_name", truncate_chars(value, 200));
                cx.content().source("sfd.FullName").title(truncate_chars(value, 200));
            }
            "FamilyName" => cx.format_set("family", truncate_chars(value, 200)),
            "Weight" => cx.format_set("weight", truncate_chars(value, 100)),
            "Version" => cx.format_set("version", truncate_chars(value, 100)),
            "Copyright" => {
                cx.format_set("copyright", truncate_chars(value, 1000));
                cx.rights().source("sfd.Copyright").copyright(truncate_chars(value, 1000));
            }
            "ItalicAngle" => {
                if let Some(a) = value.parse::<f64>().ok().filter(|a| *a != 0.0) {
                    cx.format_set("italic_angle", a);
                }
            }
            "Ascent" => ascent = value.parse::<u32>().ok(),
            "Descent" => descent = value.parse::<u32>().ok(),
            "FSType" => {
                if let Ok(fs) = value.parse::<u16>() {
                    cx.format_set("fs_type", fs);
                    cx.format_set("embedding", embedding(fs));
                    cx.rights().source("sfd.FSType").embedding(embedding(fs));
                }
            }
            "OS2Vendor" => cx.format_set("vendor_id", value.trim_matches('\'').trim()),
            "CreationTime" => secs(cx, "created", DateField::Created, value),
            "ModificationTime" => secs(cx, "modified", DateField::Modified, value),
            "Encoding" => cx.format_set("encoding", truncate_chars(value, 100)),
            "Lookup" => {
                let mut rest = value;
                while let Some(i) = rest.find("['") {
                    rest = &rest[i + 2..];
                    if let Some(j) = rest.find('\'')
                        && j <= 4
                    {
                        features.insert(rest[..j].to_string());
                    }
                }
            }
            "BitmapFont" => strikes += 1,
            "BeginChars" => {
                if let Some(n) = value.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()) {
                    cx.format_set("glyph_count", n);
                }
            }
            _ => {}
        }
    }
    if let (Some(a), Some(d)) = (ascent, descent) {
        cx.format_set("units_per_em", a + d);
    }
    if !features.is_empty() {
        cx.format_set("features", features.into_iter().collect::<Vec<_>>());
    }
    if strikes > 0 {
        cx.format_set("bitmap_strikes", strikes);
    }
}

fn get<'p>(p: &'p Plist, key: &str) -> Option<&'p Plist> {
    p.as_dictionary()?.get(key)
}

fn get_str<'p>(p: &'p Plist, key: &str) -> Option<&'p str> {
    get(p, key)?.as_string().filter(|s| !s.is_empty())
}

fn get_int(p: &Plist, key: &str) -> Option<i64> {
    let v = get(p, key)?;
    v.as_signed_integer().or_else(|| v.as_string()?.parse().ok())
}

/// A Glyphs custom parameter (`customParameters = ({name; value;})`).
fn parameter<'p>(p: &'p Plist, name: &str) -> Option<&'p Plist> {
    get(p, "customParameters")?
        .as_array()?
        .iter()
        .find(|c| get_str(c, "name") == Some(name))
        .and_then(|c| get(c, "value"))
}

/// A Glyphs 3 property (`properties = ({key; value;} or {key; values;})`).
fn property(p: &Plist, key: &str) -> Option<String> {
    let entry = get(p, "properties")?.as_array()?.iter().find(|e| get_str(e, "key") == Some(key))?;
    if let Some(v) = get_str(entry, "value") {
        return Some(v.to_string());
    }
    let values = get(entry, "values")?.as_array()?;
    let pick =
        values.iter().find(|v| matches!(get_str(v, "language"), Some("dflt" | "ENG"))).or_else(|| values.first())?;
    get_str(pick, "value").map(str::to_string)
}

/// fsType from the bit numbers Glyphs and UFO store.
fn fs_bits(p: Option<&Plist>) -> Option<u16> {
    let bits = p?.as_array()?;
    Some(
        bits.iter()
            .filter_map(|b| b.as_signed_integer().or_else(|| b.as_string()?.parse().ok()))
            .filter(|b| (0..16).contains(b))
            .fold(0u16, |a, b| a | 1 << b),
    )
}

fn names(p: Option<&Plist>, key: &str) -> Vec<String> {
    let items = p.and_then(Plist::as_array).map(Vec::as_slice).unwrap_or_default();
    items.iter().filter_map(|i| get_str(i, key)).take(MAX_NAMES).map(|s| truncate_chars(s, 100)).collect()
}

fn glyphs(cx: &mut Context<'_>, p: &Plist) {
    let format = get_int(p, ".formatVersion").unwrap_or(2);
    cx.format_set("glyphs_format", format);
    if let Some(v) = get_str(p, ".appVersion") {
        cx.format_set("app_version", v);
    }
    let family = get_str(p, "familyName").map(str::to_string);
    if let Some(f) = &family {
        cx.format_set("family", truncate_chars(f, 200));
        cx.content().source("glyphs.familyName").title(truncate_chars(f, 200));
    }
    if let (Some(a), Some(b)) = (get_int(p, "versionMajor"), get_int(p, "versionMinor")) {
        cx.format_set("version", format!("{a}.{b:03}"));
    }
    if let Some(u) = get_int(p, "unitsPerEm") {
        cx.format_set("units_per_em", u);
    }
    let text = |k2: &str, k3: &str| get_str(p, k2).map(str::to_string).or_else(|| property(p, k3));
    if let Some(c) = text("copyright", "copyrights") {
        cx.format_set("copyright", truncate_chars(&c, 1000));
        cx.rights().source("glyphs.copyright").copyright(truncate_chars(&c, 1000));
    }
    if let Some(d) = text("designer", "designers") {
        cx.format_set("designer", truncate_chars(&d, 200));
        cx.content().source("glyphs.designer").author(truncate_chars(&d, 200));
    }
    if let Some(m) = text("manufacturer", "manufacturers") {
        cx.format_set("manufacturer", truncate_chars(&m, 200));
    }
    if let Some(u) = text("designerURL", "designerURL") {
        cx.format_set("designer_url", truncate_chars(&u, 500));
    }
    let lic =
        parameter(p, "license").and_then(Plist::as_string).map(str::to_string).or_else(|| property(p, "licenses"));
    let url =
        parameter(p, "licenseURL").and_then(Plist::as_string).map(str::to_string).or_else(|| property(p, "licenseURL"));
    licence(cx, lic.as_deref(), url.as_deref());
    if let Some(v) = parameter(p, "vendorID").and_then(Plist::as_string) {
        cx.format_set("vendor_id", v);
    }
    if let Some(fs) = fs_bits(parameter(p, "fsType")) {
        cx.format_set("fs_type", fs);
        cx.rights().source("glyphs.fsType").embedding(embedding(fs));
        cx.format_set("embedding", embedding(fs));
    }
    if let Some(d) = get_str(p, "date") {
        cx.format_set("date", d);
        // "2025-09-01 06:12:00 +0000"
        let iso = d.replacen(' ', "T", 1).replacen(" +0000", "Z", 1).replacen(' ', "", 1);
        if let Some((t, tz)) = parse_date(&iso) {
            cx.temporal().source("glyphs.date").content_date(DateField::Created, t, tz);
        }
    }
    let masters = get(p, "fontMaster").and_then(Plist::as_array);
    cx.format_set("masters", masters.map_or(0, Vec::len));
    let master_names = names(get(p, "fontMaster"), "name");
    if !master_names.is_empty() {
        cx.format_set("master_names", master_names);
    }
    if let Some(i) = get(p, "instances").and_then(Plist::as_array) {
        cx.format_set("instance_count", i.len());
        let n = names(get(p, "instances"), "name");
        if !n.is_empty() {
            cx.format_set("instances", n);
        }
    }
    let axes = names(get(p, "axes"), "tag");
    if !axes.is_empty() {
        cx.format_set("axes", axes);
    }
    if let Some(g) = get(p, "glyphs").and_then(Plist::as_array) {
        cx.format_set("glyph_count", g.len());
    }
    let mut features = names(get(p, "features"), "tag");
    if features.is_empty() {
        features = names(get(p, "features"), "name");
    }
    if !features.is_empty() {
        cx.format_set("features", features);
    }
}

fn ufo(cx: &mut Context<'_>, p: &Plist) {
    for (key, out) in [
        ("familyName", "family"),
        ("styleName", "subfamily"),
        ("styleMapFamilyName", "style_map_family"),
        ("postscriptFontName", "postscript_name"),
        ("postscriptFullName", "full_name"),
        ("openTypeNameDesigner", "designer"),
        ("openTypeNameManufacturer", "manufacturer"),
        ("openTypeNameDesignerURL", "designer_url"),
        ("openTypeNameManufacturerURL", "manufacturer_url"),
        ("openTypeOS2VendorID", "vendor_id"),
        ("trademark", "trademark"),
        ("note", "note"),
    ] {
        if let Some(v) = get_str(p, key) {
            cx.format_set(out, truncate_chars(v, 500));
        }
    }
    let family = get_str(p, "familyName");
    let title = get_str(p, "postscriptFullName")
        .map(str::to_string)
        .or_else(|| family.map(|f| get_str(p, "styleName").map_or_else(|| f.to_string(), |s| format!("{f} {s}"))));
    if let Some(t) = title {
        cx.content().source("ufo.familyName").title(truncate_chars(&t, 200));
    }
    if let Some(d) = get_str(p, "openTypeNameDesigner") {
        cx.content().source("ufo.openTypeNameDesigner").author(truncate_chars(d, 200));
    }
    if let Some(d) = get_str(p, "openTypeNameDescription") {
        cx.content().source("ufo.openTypeNameDescription").description(truncate_chars(d, 1000));
    }
    if let (Some(a), Some(b)) = (get_int(p, "versionMajor"), get_int(p, "versionMinor")) {
        cx.format_set("version", format!("{a}.{b:03}"));
    }
    if let Some(c) = get_str(p, "copyright") {
        cx.format_set("copyright", truncate_chars(c, 1000));
        cx.rights().source("ufo.copyright").copyright(truncate_chars(c, 1000));
    }
    licence(cx, get_str(p, "openTypeNameLicense"), get_str(p, "openTypeNameLicenseURL"));
    if let Some(fs) = fs_bits(get(p, "openTypeOS2Type")) {
        cx.format_set("fs_type", fs);
        cx.format_set("embedding", embedding(fs));
        cx.rights().source("ufo.openTypeOS2Type").embedding(embedding(fs));
    }
    if let Some(d) = get_str(p, "openTypeHeadCreated") {
        cx.format_set("created", d);
        // "YYYY/MM/DD HH:MM:SS", UTC by the specification.
        let iso = d.replacen('/', "-", 2).replacen(' ', "T", 1) + "Z";
        if let Some((t, tz)) = parse_date(&iso) {
            cx.temporal().source("ufo.openTypeHeadCreated").content_date(DateField::Created, t, tz);
        }
    }
    for (key, out) in [
        ("unitsPerEm", "units_per_em"),
        ("ascender", "ascender"),
        ("descender", "descender"),
        ("capHeight", "cap_height"),
        ("xHeight", "x_height"),
        ("openTypeOS2WeightClass", "weight_class"),
        ("openTypeOS2WidthClass", "width_class"),
    ] {
        if let Some(v) = get_int(p, key) {
            cx.format_set(out, v);
        }
    }
    if let Some(a) = get(p, "italicAngle")
        .and_then(|v| v.as_real().or_else(|| v.as_signed_integer().and_then(|i| i32::try_from(i).ok()).map(f64::from)))
    {
        cx.format_set("italic_angle", a);
    }
}

fn metafont(cx: &mut Context<'_>, text: &str) {
    let mut inputs = Vec::new();
    let mut chars = 0u64;
    let assigned = |key: &str| {
        let i = text.find(key)? + key.len();
        let rest = text[i..].trim_start().strip_prefix(":=")?.trim_start();
        let v = rest.split(';').next()?.trim().trim_matches('"');
        (!v.is_empty()).then(|| truncate_chars(v, 200))
    };
    for (key, out) in
        [("font_identifier", "identifier"), ("font_coding_scheme", "coding_scheme"), ("designsize", "design_size")]
    {
        if let Some(v) = assigned(key) {
            cx.format_set(out, v);
        }
    }
    for line in text.lines().take(200_000) {
        let l = line.split('%').next().unwrap_or("").trim();
        chars += u64::try_from(l.matches("beginchar").count()).unwrap_or(0);
        if let Some(name) = l.strip_prefix("input ") {
            let name = name.trim_end_matches(';').trim();
            if !name.is_empty() && inputs.len() < MAX_NAMES {
                inputs.push(truncate_chars(name, 200));
            }
        }
    }
    cx.format_set("characters", chars);
    if !inputs.is_empty() {
        cx.format_set("inputs", inputs);
    }
    if let Some(c) = text.lines().take(20).find_map(|l| l.trim_start_matches('%').trim().strip_prefix("Copyright")) {
        cx.rights().source("metafont.comment").copyright(truncate_chars(&format!("Copyright{c}"), 500));
    }
}

impl Extractor for FontSource {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let base = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        if base == Some("fontinfo.plist") && has(h, b"<plist") && (has(h, b"familyName") || has(h, b"unitsPerEm")) {
            return Some(Sniff { format: "ufo_fontinfo", confidence: 0.98 });
        }
        if probe.extension == Some("glyphs")
            && h.trim_ascii_start().starts_with(b"{")
            && (has(h, b".appVersion") || has(h, b"familyName"))
        {
            return Some(Sniff { format: "glyphs", confidence: 0.98 });
        }
        let mf = probe.extension == Some("mf")
            && (has(h, b"beginchar") || has(h, b"mode_setup") || has(h, b"font_identifier"));
        mf.then_some(Sniff { format: "metafont", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            "sfd" => {
                let text = cx.read_text(src)?.text;
                sfd(cx, &text);
            }
            "metafont" => {
                let text = cx.read_text(src)?.text;
                metafont(cx, &text);
            }
            id => {
                let (b, _) = cx.read_bytes(src)?;
                let (p, _) = proplist::parse(&b).ok_or_else(|| ExtractError::malformed("property list"))?;
                if id == "glyphs" {
                    glyphs(cx, &p);
                } else {
                    ufo(cx, &p);
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(FontSource);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_type_bits() {
        let bits = Plist::Array(vec![Plist::Integer(1.into()), Plist::Integer(8.into())]);
        assert_eq!(fs_bits(Some(&bits)), Some(0x0102));
        assert_eq!(fs_bits(Some(&Plist::Array(vec![]))), Some(0));
    }

    crate::fixture_tests!("sfd", "glyphs", "ufo_fontinfo", "metafont");
}
