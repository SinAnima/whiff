//! iOS / iPadOS app archives (`.ipa`): `Payload/<App>.app/Info.plist`
//! gives the bundle id, name, version and build, minimum OS, device
//! families, required capabilities, URL schemes, background modes, the
//! privacy usage descriptions the app may ask for (the iOS counterpart of
//! permissions), App Transport Security exceptions and the SDK and Xcode
//! that built it. `embedded.mobileprovision` gives the team, profile name,
//! expiry, entitlements and the kind of distribution (App Store, ad hoc,
//! enterprise, development). `_CodeSignature` means the bundle is signed;
//! `SC_Info` means App Store FairPlay encryption. App extensions and
//! embedded frameworks are listed; entries (the executable among them)
//! are handed on.
//!
//! Specifications: Apple "Information Property List" and "Entitlements"
//! references; Bundle Programming Guide (iOS app bundle layout).

use plist::Value as Plist;

use super::{Package, ext_is, zip_payload};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for iOS app archives.
pub struct Ipa;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.ios",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "ipa",
        name: "iOS app archive",
        family: "package",
        mimes: &["application/octet-stream"],
        extensions: &["ipa"],
        magic: &[],
        parent: Some("zip"),
    }],
};

const MAX_ENTRIES: usize = 1 << 17;

/// The `.app` folder inside `Payload/` (`Payload/X.app/`).
fn app_dir(mut names: impl Iterator<Item = impl AsRef<str>>) -> Option<String> {
    names.find_map(|n| {
        let rest = n.as_ref().strip_prefix("Payload/")?;
        let (app, _) = rest.split_once('/')?;
        ext_is(app, "app").then(|| format!("Payload/{app}/"))
    })
}

fn parse(data: &[u8]) -> Option<Plist> {
    Plist::from_reader(std::io::Cursor::new(data)).ok()
}

fn get_str<'p>(p: &'p Plist, key: &str) -> Option<&'p str> {
    p.as_dictionary()?.get(key)?.as_string().filter(|s| !s.is_empty())
}

fn strings(p: Option<&Plist>) -> Vec<String> {
    p.and_then(Plist::as_array).into_iter().flatten().filter_map(Plist::as_string).map(str::to_string).collect()
}

fn date(p: &Plist, key: &str) -> Option<String> {
    let d = p.as_dictionary()?.get(key)?.as_date()?;
    let t: std::time::SystemTime = d.into();
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    super::archive::unix_time(i64::try_from(secs).ok()?)
}

impl Extractor for Ipa {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 4000);
        let app = app_dir(names.iter())?;
        let plist = format!("{app}Info.plist");
        (names.contains(&plist) || probe.extension == Some("ipa")).then_some(Sniff { format: "ipa", confidence: 0.96 })
    }

    #[allow(clippy::too_many_lines)] // Info.plist, provisioning profile, bundle contents
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, MAX_ENTRIES)?;
        zip.flag_duplicates(cx);
        let app = app_dir(zip.entries.iter().map(|e| e.name.as_str()))
            .ok_or_else(|| ExtractError::malformed("no Payload/<App>.app folder"))?;
        let mut pkg = Package::new("ios");
        let info = zip
            .find(&format!("{app}Info.plist"))
            .cloned()
            .map(|e| zip.read(src, &e, cx, 8 << 20))
            .transpose()?
            .and_then(|d| parse(&d));
        if let Some(p) = &info {
            let s = |k: &str| get_str(p, k).map(str::to_string);
            pkg.name = s("CFBundleIdentifier");
            pkg.version = s("CFBundleShortVersionString").or_else(|| s("CFBundleVersion"));
            pkg.release = s("CFBundleVersion");
            pkg.summary = s("CFBundleDisplayName").or_else(|| s("CFBundleName"));
            if let Some(n) = &pkg.summary {
                pkg.set("display_name", n.clone());
            }
            for (key, out) in [
                ("CFBundleExecutable", "executable"),
                ("MinimumOSVersion", "minimum_os"),
                ("DTPlatformName", "platform"),
                ("DTSDKName", "sdk"),
                ("DTXcode", "xcode"),
                ("BuildMachineOSBuild", "build_machine_os"),
            ] {
                if let Some(v) = s(key) {
                    pkg.set(out, v);
                }
            }
            let dict = p.as_dictionary();
            let families: Vec<&str> = dict
                .and_then(|d| d.get("UIDeviceFamily"))
                .and_then(Plist::as_array)
                .into_iter()
                .flatten()
                .filter_map(Plist::as_unsigned_integer)
                .filter_map(|f| match f {
                    1 => Some("iPhone"),
                    2 => Some("iPad"),
                    3 => Some("Apple TV"),
                    4 => Some("Apple Watch"),
                    6 => Some("Mac"),
                    7 => Some("Apple Vision"),
                    _ => None,
                })
                .collect();
            if !families.is_empty() {
                pkg.set("device_families", families);
            }
            let caps = strings(dict.and_then(|d| d.get("UIRequiredDeviceCapabilities")));
            if !caps.is_empty() {
                pkg.set("required_capabilities", caps);
            }
            let modes = strings(dict.and_then(|d| d.get("UIBackgroundModes")));
            if !modes.is_empty() {
                pkg.set("background_modes", modes);
            }
            let schemes: Vec<String> = dict
                .and_then(|d| d.get("CFBundleURLTypes"))
                .and_then(Plist::as_array)
                .into_iter()
                .flatten()
                .flat_map(|t| strings(t.as_dictionary().and_then(|d| d.get("CFBundleURLSchemes"))))
                .collect();
            if !schemes.is_empty() {
                pkg.set("url_schemes", schemes);
            }
            // Privacy usage descriptions: what the app may ask the user for.
            let usage: Vec<&str> = dict
                .into_iter()
                .flat_map(|d| d.keys())
                .filter(|k| k.starts_with("NS") && k.ends_with("UsageDescription"))
                .map(String::as_str)
                .collect();
            if !usage.is_empty() {
                pkg.set("privacy_usage", usage);
            }
            if dict
                .and_then(|d| d.get("NSAppTransportSecurity"))
                .and_then(Plist::as_dictionary)
                .and_then(|a| a.get("NSAllowsArbitraryLoads"))
                .and_then(Plist::as_boolean)
                == Some(true)
            {
                pkg.set("allows_arbitrary_loads", true);
            }
        }
        // The provisioning profile: a CMS envelope around an XML plist.
        if let Some(e) = zip.find(&format!("{app}embedded.mobileprovision")).cloned() {
            let data = zip.read(src, &e, cx, 4 << 20)?;
            if let Some(p) = profile(&data) {
                provisioning(&p, cx, &mut pkg);
            }
        }
        let code_signature = format!("{app}_CodeSignature/CodeResources");
        pkg.signed = Some(zip.find(&code_signature).is_some());
        if pkg.signed == Some(true) {
            pkg.signatures.push("code_signature".into());
        }
        if zip.entries.iter().any(|e| e.name.starts_with(&format!("{app}SC_Info/"))) {
            pkg.set("fairplay_encrypted", true);
            cx.security().encrypted(true);
        }
        let nested = |dir: &str, ext: &str| -> Vec<String> {
            let prefix = format!("{app}{dir}/");
            let mut v: Vec<String> = zip
                .entries
                .iter()
                .filter_map(|e| {
                    let (first, _) = e.name.strip_prefix(prefix.as_str())?.split_once('/')?;
                    first.ends_with(ext).then(|| first.to_string())
                })
                .collect();
            v.dedup();
            v
        };
        let frameworks = nested("Frameworks", ".framework");
        if !frameworks.is_empty() {
            pkg.set("frameworks", frameworks);
        }
        let extensions = nested("PlugIns", ".appex");
        if !extensions.is_empty() {
            pkg.set("app_extensions", extensions);
        }
        if pkg.extra.get("get_task_allow") == Some(&serde_json::Value::Bool(true)) {
            cx.security().risk("debuggable", Some("get-task-allow entitlement".into()));
        }
        pkg.write(cx);
        zip_payload(src, cx, &zip)
    }
}

crate::register_extractor!(Ipa);

/// The XML plist inside a provisioning profile's CMS envelope.
fn profile(data: &[u8]) -> Option<Plist> {
    let start = data.windows(5).position(|w| w == b"<?xml")?;
    let end = data[start..].windows(8).position(|w| w == b"</plist>")? + start + 8;
    parse(&data[start..end])
}

fn provisioning(p: &Plist, cx: &mut Context<'_>, pkg: &mut Package) {
    let d = p.as_dictionary();
    for (key, out) in [("Name", "profile_name"), ("TeamName", "team_name"), ("AppIDName", "app_id_name")] {
        if let Some(v) = get_str(p, key) {
            pkg.set(out, v);
        }
    }
    if let Some(t) = strings(d.and_then(|d| d.get("TeamIdentifier"))).into_iter().next() {
        pkg.set("team_id", t);
    }
    if let Some(team) = get_str(p, "TeamName") {
        pkg.authors.push(team.to_string());
    }
    if let Some(t) = date(p, "ExpirationDate") {
        pkg.set("profile_expires", t.clone());
        cx.temporal().content_date(DateField::Expires, t, true);
    }
    if let Some(t) = date(p, "CreationDate") {
        pkg.set("profile_created", t);
    }
    let devices = d.and_then(|d| d.get("ProvisionedDevices")).and_then(Plist::as_array).map(Vec::len);
    let all = d.and_then(|d| d.get("ProvisionsAllDevices")).and_then(Plist::as_boolean) == Some(true);
    let entitlements = d.and_then(|d| d.get("Entitlements")).and_then(Plist::as_dictionary);
    let debug = entitlements.and_then(|e| e.get("get-task-allow")).and_then(Plist::as_boolean) == Some(true);
    let kind = if all {
        "enterprise"
    } else if devices.is_some() && debug {
        "development"
    } else if devices.is_some() {
        "ad_hoc"
    } else {
        "app_store"
    };
    pkg.set("distribution", kind);
    if let Some(n) = devices {
        pkg.set("provisioned_devices", n);
    }
    if let Some(e) = entitlements {
        pkg.set("entitlements", e.keys().cloned().collect::<Vec<_>>());
        pkg.set("get_task_allow", debug);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_folder() {
        let names = ["Payload/", "Payload/Tides.app/Info.plist", "iTunesMetadata.plist"];
        assert_eq!(app_dir(names.iter()).as_deref(), Some("Payload/Tides.app/"));
        assert_eq!(app_dir(["Payload/x.txt"].iter()), None);
    }

    crate::fixture_tests!("ipa");
}
