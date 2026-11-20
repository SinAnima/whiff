//! Xcode projects (`project.pbxproj`, an old-style plist) and workspaces
//! (`contents.xcworkspacedata`):
//! * projects: object and archive versions, compatibility, the last
//!   upgrade check, targets (name, product type, product name), build
//!   configurations, deployment targets, SDKs, Swift versions, bundle
//!   identifiers, development teams, Swift package dependencies, script
//!   build phases, and a histogram of object kinds and file types;
//! * workspaces: the referenced projects and groups.
//!
//! Specifications: Monobjc / "Xcode project file format" notes (the
//! `objects` graph keyed by `isa`); `xcodeproj` (CocoaPods) object model.

use std::collections::{BTreeMap, BTreeSet};

use plist::Value as Plist;
use serde_json::{Map, Value, json};

use super::get_str;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, proplist, truncate_chars,
    user_path,
};

/// Extractor for Xcode projects and workspaces.
pub struct Xcode;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.xcode",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pbxproj",
            name: "Xcode project / workspace",
            family: "apple",
            mimes: &[],
            extensions: &["pbxproj"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "xcworkspace",
            name: "Xcode workspace",
            family: "apple",
            mimes: &[],
            extensions: &["xcworkspacedata"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Items kept per list.
const MAX_LIST: usize = 50;

/// Build settings collected across configurations: setting → output key.
const SETTINGS: [(&str, &str); 10] = [
    ("IPHONEOS_DEPLOYMENT_TARGET", "ios_deployment_targets"),
    ("MACOSX_DEPLOYMENT_TARGET", "macos_deployment_targets"),
    ("TVOS_DEPLOYMENT_TARGET", "tvos_deployment_targets"),
    ("WATCHOS_DEPLOYMENT_TARGET", "watchos_deployment_targets"),
    ("XROS_DEPLOYMENT_TARGET", "visionos_deployment_targets"),
    ("SDKROOT", "sdks"),
    ("SWIFT_VERSION", "swift_versions"),
    ("PRODUCT_BUNDLE_IDENTIFIER", "bundle_identifiers"),
    ("DEVELOPMENT_TEAM", "development_teams"),
    ("CODE_SIGN_STYLE", "code_sign_styles"),
];

fn count_top(m: BTreeMap<String, u64>, top: usize) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(top).map(|(k, n)| (k, n.into())).collect::<Map<_, _>>())
}

impl Extractor for Xcode {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"// !$*UTF8*$!") {
            return Some(Sniff { format: "pbxproj", confidence: 0.97 });
        }
        let ws = probe.extension == Some("xcworkspacedata") && h.windows(10).any(|w| w == b"<Workspace");
        ws.then_some(Sniff { format: "xcworkspace", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        if cx.format_id() == "xcworkspace" {
            workspace(&String::from_utf8_lossy(&data), cx);
            return Ok(());
        }
        if cut {
            return Err(ExtractError::malformed("project larger than the parse limit"));
        }
        let (p, _) = proplist::parse(&data).ok_or_else(|| ExtractError::malformed("project plist"))?;
        project(&p, cx);
        Ok(())
    }
}

crate::register_extractor!(Xcode);

#[allow(clippy::too_many_lines)] // one pass over the object graph
fn project(p: &Plist, cx: &mut Context<'_>) {
    // The ASCII reader gives bare numbers as integers.
    for (key, out) in [("archiveVersion", "archive_version"), ("objectVersion", "object_version")] {
        let v = p.as_dictionary().and_then(|d| d.get(key));
        if let Some(v) =
            v.and_then(|v| v.as_string().map(str::to_string).or_else(|| v.as_signed_integer().map(|n| n.to_string())))
        {
            cx.format_set(out, v);
        }
    }
    let objects = p.as_dictionary().and_then(|d| d.get("objects")).and_then(Plist::as_dictionary);
    let Some(objects) = objects else { return };
    cx.format_set("objects", objects.len());
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut file_types: BTreeMap<String, u64> = BTreeMap::new();
    let mut targets = Vec::new();
    let mut configs: BTreeSet<String> = BTreeSet::new();
    let mut settings: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut packages = Vec::new();
    let mut scripts = 0u64;
    for o in objects.values() {
        let kind = get_str(o, "isa").unwrap_or("");
        *kinds.entry(kind.to_string()).or_default() += 1;
        match kind {
            "PBXFileReference" => {
                if let Some(t) = get_str(o, "lastKnownFileType").or_else(|| get_str(o, "explicitFileType")) {
                    *file_types.entry(t.to_string()).or_default() += 1;
                }
            }
            "PBXNativeTarget" | "PBXAggregateTarget" | "PBXLegacyTarget" => {
                let mut t = Map::new();
                if let Some(n) = get_str(o, "name") {
                    t.insert("name".into(), truncate_chars(n, 200).into());
                }
                if let Some(pt) = get_str(o, "productType") {
                    let short = pt.strip_prefix("com.apple.product-type.").unwrap_or(pt);
                    t.insert("product_type".into(), short.into());
                }
                if let Some(n) = get_str(o, "productName") {
                    t.insert("product_name".into(), truncate_chars(n, 200).into());
                }
                targets.push(Value::Object(t));
            }
            "XCBuildConfiguration" => {
                if let Some(n) = get_str(o, "name") {
                    configs.insert(n.to_string());
                }
                if let Some(bs) = o.as_dictionary().and_then(|d| d.get("buildSettings")) {
                    for (key, _) in SETTINGS {
                        let v = bs.as_dictionary().and_then(|d| d.get(key));
                        if let Some(s) = v.and_then(Plist::as_string).filter(|s| !s.is_empty()) {
                            settings.entry(key).or_default().insert(s.to_string());
                        }
                    }
                }
            }
            "XCRemoteSwiftPackageReference" => {
                let mut m = Map::new();
                if let Some(u) = get_str(o, "repositoryURL") {
                    m.insert("url".into(), truncate_chars(&cx.redact_secrets(u), 300).into());
                }
                let req = o.as_dictionary().and_then(|d| d.get("requirement"));
                if let Some(r) = req {
                    for k in ["kind", "minimumVersion", "version", "branch", "revision"] {
                        if let Some(v) = get_str(r, k) {
                            m.insert(k.into(), truncate_chars(v, 100).into());
                        }
                    }
                }
                packages.push(Value::Object(m));
            }
            "XCLocalSwiftPackageReference" => {
                let mut m = Map::new();
                if let Some(path) = get_str(o, "relativePath") {
                    m.insert("path".into(), user_path(cx, path).into());
                }
                packages.push(Value::Object(m));
            }
            "PBXShellScriptBuildPhase" => scripts += 1,
            _ => {}
        }
    }
    // The project object: attributes and regions.
    if let Some(root) =
        p.as_dictionary().and_then(|d| d.get("rootObject")).and_then(Plist::as_string).and_then(|id| objects.get(id))
    {
        for (key, out) in [("compatibilityVersion", "compatibility"), ("developmentRegion", "development_region")] {
            if let Some(v) = get_str(root, key) {
                cx.format_set(out, v);
            }
        }
        if let Some(a) = root.as_dictionary().and_then(|d| d.get("attributes")) {
            for (key, out) in [
                ("LastUpgradeCheck", "last_upgrade_check"),
                ("LastSwiftUpdateCheck", "last_swift_update_check"),
                ("ORGANIZATIONNAME", "organization"),
            ] {
                if let Some(v) = get_str(a, key) {
                    cx.format_set(out, truncate_chars(v, 200));
                }
            }
            if let Some(o) = get_str(a, "ORGANIZATIONNAME") {
                cx.content().author(truncate_chars(o, 200));
            }
        }
        let regions = root.as_dictionary().and_then(|d| d.get("knownRegions")).and_then(Plist::as_array);
        let regions: Vec<&str> = regions.into_iter().flatten().filter_map(Plist::as_string).collect();
        if !regions.is_empty() {
            cx.format_set("known_regions", regions);
        }
    }
    cx.format_set("targets", json!(targets.into_iter().take(MAX_LIST).collect::<Vec<_>>()));
    if !configs.is_empty() {
        cx.format_set("configurations", configs.into_iter().collect::<Vec<_>>());
    }
    for (key, out) in SETTINGS {
        if let Some(v) = settings.remove(key) {
            cx.format_set(out, v.into_iter().take(MAX_LIST).collect::<Vec<_>>());
        }
    }
    if !packages.is_empty() {
        cx.format_set("packages", Value::Array(packages.into_iter().take(MAX_LIST).collect()));
    }
    if scripts > 0 {
        cx.format_set("script_phases", scripts);
    }
    cx.format_set("object_kinds", count_top(kinds, 40));
    if !file_types.is_empty() {
        cx.format_set("file_types", count_top(file_types, 30));
    }
}

fn workspace(text: &str, cx: &mut Context<'_>) {
    let mut refs = Vec::new();
    let mut groups = 0u64;
    for tag in text.split('<').skip(1) {
        if tag.starts_with("Group") {
            groups += 1;
        }
        if tag.starts_with("FileRef")
            && let Some(start) =
                tag.find("location = \"").map(|i| i + 12).or_else(|| tag.find("location=\"").map(|i| i + 10))
            && let Some(len) = tag[start..].find('"')
        {
            let loc = crate::plugin::decode_entities(&tag[start..start + len]);
            refs.push(user_path(cx, &loc));
        }
    }
    cx.format_set("file_refs", refs.len());
    if groups > 0 {
        cx.format_set("groups", groups);
    }
    let projects: Vec<&str> =
        refs.iter().filter(|r| r.ends_with(".xcodeproj")).take(MAX_LIST).map(String::as_str).collect();
    if !projects.is_empty() {
        cx.format_set("projects", projects);
    }
    let others: Vec<&str> =
        refs.iter().filter(|r| !r.ends_with(".xcodeproj")).take(MAX_LIST).map(String::as_str).collect();
    if !others.is_empty() {
        cx.format_set("references", others);
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn workspace_refs() {
        let ws = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Workspace\n   version = \"1.0\">\n   \
            <FileRef\n      location = \"group:Tides.xcodeproj\">\n   </FileRef>\n   \
            <FileRef\n      location = \"group:Pods/Pods.xcodeproj\">\n   </FileRef>\n</Workspace>\n";
        let r = report_for("contents.xcworkspacedata", ws.as_bytes());
        let f = &r.format["xcworkspace"];
        assert_eq!(f["file_refs"], 2);
        assert_eq!(f["projects"][0], "group:Tides.xcodeproj");
    }

    crate::fixture_tests!("pbxproj", "xcworkspace");
}
