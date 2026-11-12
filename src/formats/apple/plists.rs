//! Property lists, XML, binary and old-style ASCII, with what the common
//! kinds hold:
//! * bundle `Info.plist`: identifier, name, version and build, executable,
//!   package type, minimum OS, platform and SDK, document types, URL
//!   schemes, privacy usage keys, App Transport Security exceptions;
//! * launchd jobs: label, program, arguments count, run conditions;
//! * `NSKeyedArchiver` archives: object count, root class, class histogram;
//! * configuration profiles (`.mobileconfig`, signed or not): identifier,
//!   organisation, scope, payload types, signer; root certificates and
//!   embedded passwords are flagged, never shown;
//! * provisioning profiles: team, app ID, platforms, dates, distribution
//!   kind, device count (never the device IDs), entitlements, signer;
//! * Shortcuts and Automator workflows: actions and their histogram;
//!   actions that run scripts are flagged;
//! * iOS backup `Info.plist`, `Manifest.plist`, `Status.plist`: device
//!   model, iOS version, backup date, encryption, app count (device name,
//!   serial number and identifiers only when privacy is off).
//!
//! Every other plist gets its top-level keys and an inferred schema.
//!
//! Specifications: Apple "Property List Programming Guide", "Information
//! Property List", `launchd.plist(5)`, "Configuration Profile Reference",
//! `NSKeyedArchiver` archive layout (`$archiver`, `$objects`, `$top`).

use std::collections::BTreeMap;

use plist::Value as Plist;
use serde_json::{Map, Value, json};

use super::{census, copy_strings, get_bool, get_str, schema, strings, top_keys};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der,
    is_secret_key, proplist, truncate_chars, user_path,
};

/// Extractor for property lists.
pub struct PropertyList;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.plist",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "plist",
            name: "Apple plist (XML)",
            family: "data.binser",
            mimes: &["application/x-plist"],
            extensions: &["plist"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "bplist",
            name: "Apple plist (binary)",
            family: "data.binser",
            mimes: &["application/x-bplist"],
            extensions: &["plist"],
            magic: &[Magic::at(0, b"bplist00")],
            parent: None,
        },
        FormatSpec {
            id: "info_plist",
            name: "macOS app bundle Info.plist",
            family: "apple",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ios_backup_plist",
            name: "iOS backup Info.plist / Manifest.plist",
            family: "apple",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "mobileconfig",
            name: "Apple configuration profile",
            family: "apple",
            mimes: &["application/x-apple-aspen-config"],
            extensions: &["mobileconfig"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "mobileprovision",
            name: "Apple provisioning profile",
            family: "apple",
            mimes: &[],
            extensions: &["mobileprovision", "provisionprofile"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "shortcut",
            name: "Apple Shortcuts / Automator",
            family: "apple",
            mimes: &[],
            extensions: &["shortcut", "wflow"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Classes kept in a keyed archive's histogram.
const TOP: usize = 30;

/// iOS backup plists: file name and a key only they have.
const BACKUP: [(&str, &[u8]); 3] =
    [("Info.plist", b"Target Identifier"), ("Manifest.plist", b"Lockdown"), ("Status.plist", b"SnapshotState")];

/// Action identifiers that run code: Shortcuts, then Automator.
const SCRIPT_ACTIONS: [&str; 9] = [
    "is.workflow.actions.runshellscript",
    "is.workflow.actions.runsshscript",
    "is.workflow.actions.runjavascriptonwebpage",
    "is.workflow.actions.runapplescript",
    "is.workflow.actions.runjavascriptforautomation",
    "com.apple.RunShellScript",
    "com.apple.Automator.RunScript",
    "com.apple.Automator.RunJavaScript",
    "com.apple.Automator.RunAppleScript",
];

fn has(head: &[u8], needle: &[u8]) -> bool {
    head.windows(needle.len()).any(|w| w == needle)
}

/// A CMS `SignedData` envelope (BER or DER).
fn is_cms(head: &[u8]) -> bool {
    head.first() == Some(&0x30) && has(&head[..head.len().min(32)], b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02")
}

impl Extractor for PropertyList {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let base = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        if is_cms(h) {
            // Signed profiles: the plist is the CMS content.
            let format = if has(h, b"<key>PayloadContent</key>") || has(h, b"<key>PayloadType</key>") {
                "mobileconfig"
            } else if has(h, b"<key>ProvisionedDevices</key>")
                || has(h, b"<key>DeveloperCertificates</key>")
                || has(h, b"<key>ProvisionsAllDevices</key>")
            {
                "mobileprovision"
            } else {
                return None;
            };
            return Some(Sniff { format, confidence: 0.97 });
        }
        if probe.extension == Some("shortcut") && h.starts_with(b"AEA1") {
            return Some(Sniff { format: "shortcut", confidence: 0.95 });
        }
        let enc = proplist::encoding(h)?;
        // The kinds below outrank the binary magic with the `.plist` extension (0.97).
        if let Some(b) = base
            && let Some((_, key)) = BACKUP.iter().find(|(n, _)| *n == b)
            && has(h, key)
        {
            return Some(Sniff { format: "ios_backup_plist", confidence: 0.98 });
        }
        if base.is_some_and(|b| b == "Info.plist" || b.ends_with("-Info.plist")) && has(h, b"CFBundle") {
            return Some(Sniff { format: "info_plist", confidence: 0.98 });
        }
        if has(h, b"WFWorkflowActions") || has(h, b"AMApplicationBuild") {
            return Some(Sniff { format: "shortcut", confidence: 0.98 });
        }
        if has(h, b"PayloadContent") && has(h, b"PayloadType") && has(h, b"Configuration") {
            return Some(Sniff { format: "mobileconfig", confidence: 0.98 });
        }
        match enc {
            proplist::Encoding::Binary => None, // the magic decides
            proplist::Encoding::Xml => Some(Sniff { format: "plist", confidence: 0.9 }),
            proplist::Encoding::Ascii => {
                // `{` and `(` also start JSON and much else: only with the name.
                (probe.extension == Some("plist")).then_some(Sniff { format: "plist", confidence: 0.7 })
            }
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        if cut {
            return Err(ExtractError::malformed("plist larger than the parse limit"));
        }
        if data.starts_with(b"AEA1") {
            // Signed shortcuts: an Apple Encrypted Archive around the plist.
            cx.format_set("kind", "shortcut");
            cx.format_set("container", "apple_encrypted_archive");
            cx.security().signed(true);
            return Ok(());
        }
        let (plist_bytes, signed) = if is_cms(&data) {
            let s = der::signed_data(&data).ok_or_else(|| ExtractError::malformed("CMS envelope"))?;
            let content = s.content.clone().ok_or_else(|| ExtractError::malformed("CMS without content"))?;
            (content, Some(s))
        } else {
            (data, None)
        };
        let (p, enc) = proplist::parse(&plist_bytes).ok_or_else(|| ExtractError::malformed("property list"))?;
        cx.format_set("encoding", enc.as_str());
        if let Some(s) = signed {
            if s.signer.is_some() {
                cx.security().signed(true);
            }
            cx.format_set("signature", Value::Object(s.facts()));
        }
        let top = match &p {
            Plist::Dictionary(_) => "dictionary",
            Plist::Array(_) => "array",
            _ => "scalar",
        };
        cx.format_set("top_level", top);
        let (values, depth) = census(&p);
        cx.format_set("values", values);
        cx.format_set("max_depth", depth);
        cx.checkpoint()?;
        let name = src.name_hint().map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string());
        let kind = kind_of(&p, name.as_deref());
        if let Some(k) = kind {
            cx.format_set("kind", k);
        }
        match kind {
            Some("app_info") => app_info(&p, cx),
            Some("launchd_job") => launchd(&p, cx),
            Some("keyed_archive") => keyed_archive(&p, cx),
            Some("configuration_profile") => profile(&p, cx),
            Some("provisioning_profile") => provisioning(&p, cx),
            Some("shortcut") => shortcut(&p, cx),
            Some("automator_workflow") => automator(&p, cx),
            Some("garageband_song") => garageband_song(&p, cx),
            Some("garageband_project_info") => copy_strings(cx, &p, &[("LastSavedFrom", "last_saved_from")]),
            Some(k) if k.starts_with("ios_backup") => backup(&p, k, cx),
            _ => {
                if let Some(keys) = top_keys(&p) {
                    cx.format_set("keys", keys);
                } else if let Some(a) = p.as_array() {
                    cx.format_set("items", a.len());
                }
                schema(cx, &p);
            }
        }
        Ok(())
    }
}

crate::register_extractor!(PropertyList);

/// What kind of plist this is, from its keys (and name for backups).
fn kind_of(p: &Plist, name: Option<&str>) -> Option<&'static str> {
    let d = p.as_dictionary()?;
    let k = |key: &str| d.contains_key(key);
    Some(match name {
        Some("Info.plist") if k("Target Identifier") || k("Product Version") && k("Build Version") => "ios_backup_info",
        Some("Manifest.plist") if k("Lockdown") || k("BackupKeyBag") => "ios_backup_manifest",
        Some("Status.plist") if k("SnapshotState") || k("BackupState") => "ios_backup_status",
        _ if k("$archiver") && k("$objects") => "keyed_archive",
        _ if k("CFBundleIdentifier") || k("CFBundleExecutable") || k("CFBundlePackageType") => "app_info",
        _ if k("Label") && (k("Program") || k("ProgramArguments")) => "launchd_job",
        _ if k("PayloadContent") && get_str(p, "PayloadType") == Some("Configuration") => "configuration_profile",
        _ if k("ProvisionedDevices") || k("DeveloperCertificates") && k("TeamIdentifier") => "provisioning_profile",
        _ if k("WFWorkflowActions") => "shortcut",
        _ if k("AMApplicationBuild") && k("actions") => "automator_workflow",
        _ if k("SongKey") && k("BeatsPerMinute") && k("NumberOfTracks") => "garageband_song",
        _ if get_str(p, "LastSavedFrom").is_some_and(|v| v.starts_with("GarageBand") || v.starts_with("Logic"))
            && k("VariantNames") =>
        {
            "garageband_project_info"
        }
        _ => return None,
    })
}

fn app_info(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(
        cx,
        p,
        &[
            ("CFBundleIdentifier", "bundle_id"),
            ("CFBundleName", "name"),
            ("CFBundleDisplayName", "display_name"),
            ("CFBundleShortVersionString", "version"),
            ("CFBundleVersion", "build"),
            ("CFBundleExecutable", "executable"),
            ("CFBundlePackageType", "package_type"),
            ("CFBundleDevelopmentRegion", "development_region"),
            ("LSMinimumSystemVersion", "minimum_macos"),
            ("MinimumOSVersion", "minimum_os"),
            ("DTPlatformName", "platform"),
            ("DTSDKName", "sdk"),
            ("DTXcode", "xcode"),
            ("BuildMachineOSBuild", "build_machine_os"),
            ("LSApplicationCategoryType", "category"),
            ("NSPrincipalClass", "principal_class"),
        ],
    );
    if let Some(n) = get_str(p, "CFBundleDisplayName").or_else(|| get_str(p, "CFBundleName")) {
        cx.content().title(truncate_chars(n, 200));
    }
    if let Some(c) = get_str(p, "NSHumanReadableCopyright") {
        cx.rights().copyright(truncate_chars(c, 300));
    }
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    let schemes: Vec<String> = get("CFBundleURLTypes")
        .and_then(Plist::as_array)
        .into_iter()
        .flatten()
        .flat_map(|t| strings(t, "CFBundleURLSchemes"))
        .collect();
    if !schemes.is_empty() {
        cx.format_set("url_schemes", schemes);
    }
    let docs = get("CFBundleDocumentTypes").and_then(Plist::as_array).map_or(0, Vec::len);
    if docs > 0 {
        cx.format_set("document_types", docs);
    }
    let exported: Vec<&str> = get("UTExportedTypeDeclarations")
        .and_then(Plist::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| get_str(t, "UTTypeIdentifier"))
        .collect();
    if !exported.is_empty() {
        cx.format_set("exported_types", exported);
    }
    let usage: Vec<&str> = d
        .into_iter()
        .flat_map(|d| d.keys())
        .filter(|k| k.starts_with("NS") && k.ends_with("UsageDescription"))
        .map(String::as_str)
        .collect();
    if !usage.is_empty() {
        cx.format_set("privacy_usage", usage);
    }
    for (key, out) in [("LSUIElement", "agent_app"), ("LSBackgroundOnly", "background_only")] {
        if get_bool(p, key) == Some(true) {
            cx.format_set(out, true);
        }
    }
    if get("NSAppTransportSecurity").and_then(|a| get_bool(a, "NSAllowsArbitraryLoads")) == Some(true) {
        cx.format_set("allows_arbitrary_loads", true);
    }
    // Environment set for the app by Launch Services.
    if let Some(env) = get("LSEnvironment").and_then(Plist::as_dictionary) {
        let names: Vec<&str> = env.keys().map(String::as_str).collect();
        cx.format_set("environment", names.clone());
        if names.iter().any(|n| n.starts_with("DYLD_")) {
            cx.security().risk("weakened_runtime", Some("LSEnvironment sets DYLD_ variables".into()));
        }
    }
}

fn launchd(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(cx, p, &[("Label", "label"), ("UserName", "user"), ("ProcessType", "process_type")]);
    let args = strings(p, "ProgramArguments");
    if let Some(prog) = get_str(p, "Program").map(str::to_string).or_else(|| args.first().cloned()) {
        let prog = user_path(cx, &prog);
        cx.format_set("program", prog);
    }
    if !args.is_empty() {
        cx.format_set("arguments", args.len());
    }
    for (key, out) in [("RunAtLoad", "run_at_load"), ("Disabled", "disabled")] {
        if let Some(b) = get_bool(p, key) {
            cx.format_set(out, b);
        }
    }
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    if let Some(k) = get("KeepAlive") {
        cx.format_set("keep_alive", k.as_boolean().map_or_else(|| json!("conditional"), Value::from));
    }
    if let Some(n) = get("StartInterval").and_then(Plist::as_unsigned_integer) {
        cx.format_set("start_interval_s", n);
    }
    let triggers: Vec<&str> = ["StartCalendarInterval", "WatchPaths", "QueueDirectories", "Sockets", "MachServices"]
        .into_iter()
        .filter(|k| get(k).is_some())
        .collect();
    if !triggers.is_empty() {
        cx.format_set("triggers", triggers);
    }
}

/// A UID: native in binary plists, `{CF$UID = n}` in XML ones.
fn uid(v: &Plist) -> Option<usize> {
    let n = match v.as_uid() {
        Some(u) => u.get(),
        None => v.as_dictionary().filter(|d| d.len() == 1)?.get("CF$UID")?.as_unsigned_integer()?,
    };
    usize::try_from(n).ok()
}

/// The class name of an object in a keyed archive.
fn class_of<'p>(objects: &'p [Plist], obj: &Plist) -> Option<&'p str> {
    get_str(objects.get(uid(obj.as_dictionary()?.get("$class")?)?)?, "$classname")
}

fn keyed_archive(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(cx, p, &[("$archiver", "archiver")]);
    if let Some(v) = p.as_dictionary().and_then(|d| d.get("$version")).and_then(Plist::as_unsigned_integer) {
        cx.format_set("archive_version", v);
    }
    let objects = p.as_dictionary().and_then(|d| d.get("$objects")).and_then(Plist::as_array);
    let objects = objects.map_or(&[][..], Vec::as_slice);
    cx.format_set("objects", objects.len());
    let mut classes: BTreeMap<&str, u64> = BTreeMap::new();
    for o in objects {
        if let Some(c) = class_of(objects, o) {
            *classes.entry(c).or_default() += 1;
        }
    }
    let top = p.as_dictionary().and_then(|d| d.get("$top")).and_then(Plist::as_dictionary);
    let roots: Vec<String> = top.into_iter().flat_map(|t| t.keys()).take(20).cloned().collect();
    if !roots.is_empty() {
        cx.format_set("top_keys", roots);
    }
    let root = top.and_then(|t| t.get("root")).and_then(uid);
    if let Some(c) = root.and_then(|i| objects.get(i)).and_then(|o| class_of(objects, o)) {
        cx.format_set("root_class", c);
    }
    let mut v: Vec<(&str, u64)> = classes.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if !v.is_empty() {
        let m: Map<String, Value> = v.into_iter().take(TOP).map(|(k, n)| (k.to_string(), n.into())).collect();
        cx.format_set("classes", Value::Object(m));
    }
}

/// Keys in a payload holding a secret with a non-empty value.
fn secrets_in(payload: &Plist) -> bool {
    let mut stack = vec![payload];
    while let Some(v) = stack.pop() {
        match v {
            Plist::Dictionary(d) => {
                for (k, x) in d {
                    let filled =
                        x.as_string().is_some_and(|s| !s.is_empty()) || x.as_data().is_some_and(|b| !b.is_empty());
                    if filled && (is_secret_key(k) || k.contains("Password") || k == "SharedSecret") {
                        return true;
                    }
                    stack.push(x);
                }
            }
            Plist::Array(a) => stack.extend(a),
            _ => {}
        }
    }
    false
}

fn profile(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(
        cx,
        p,
        &[
            ("PayloadIdentifier", "identifier"),
            ("PayloadDisplayName", "display_name"),
            ("PayloadOrganization", "organization"),
            ("PayloadScope", "scope"),
            ("PayloadUUID", "uuid"),
        ],
    );
    if let Some(n) = get_str(p, "PayloadDisplayName") {
        cx.content().title(truncate_chars(n, 200));
    }
    if let Some(d) = get_str(p, "PayloadDescription") {
        cx.content().description(truncate_chars(d, 500));
    }
    if let Some(o) = get_str(p, "PayloadOrganization") {
        cx.content().author(truncate_chars(o, 200));
    }
    if get_bool(p, "PayloadRemovalDisallowed") == Some(true) {
        cx.format_set("removal_disallowed", true);
    }
    let d = p.as_dictionary();
    if let Some(t) = d.and_then(|d| d.get("RemovalDate")).and_then(proplist::date) {
        cx.format_set("removal_date", t.clone());
        cx.temporal().content_date(DateField::Expires, t, true);
    }
    if d.is_some_and(|d| d.contains_key("EncryptedPayloadContent")) {
        cx.format_set("encrypted_payloads", true);
        cx.security().encrypted(true);
    }
    let payloads = d.and_then(|d| d.get("PayloadContent")).and_then(Plist::as_array).map_or(&[][..], Vec::as_slice);
    cx.format_set("payloads", payloads.len());
    let mut types: BTreeMap<&str, u64> = BTreeMap::new();
    for pl in payloads {
        if let Some(t) = get_str(pl, "PayloadType") {
            *types.entry(t).or_default() += 1;
        }
    }
    if !types.is_empty() {
        let m: Map<String, Value> = types.iter().map(|(k, n)| ((*k).to_string(), (*n).into())).collect();
        cx.format_set("payload_types", Value::Object(m));
    }
    if types.contains_key("com.apple.security.root") {
        cx.security().risk("installs_root_certificate", Some("com.apple.security.root payload".into()));
    }
    if payloads.iter().any(secrets_in) {
        cx.security().risk("embedded_secret", Some("payload holds a password or shared secret".into()));
    }
}

fn provisioning(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(cx, p, &[("Name", "name"), ("AppIDName", "app_id_name"), ("TeamName", "team_name"), ("UUID", "uuid")]);
    if let Some(t) = strings(p, "TeamIdentifier").into_iter().next() {
        cx.format_set("team_id", t);
    }
    let platforms = strings(p, "Platform");
    if !platforms.is_empty() {
        cx.format_set("platforms", platforms);
    }
    if let Some(team) = get_str(p, "TeamName") {
        cx.content().author(truncate_chars(team, 200));
    }
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    if let Some(t) = get("CreationDate").and_then(proplist::date) {
        cx.format_set("created", t.clone());
        cx.temporal().content_date(DateField::Created, t, true);
    }
    if let Some(t) = get("ExpirationDate").and_then(proplist::date) {
        cx.format_set("expires", t.clone());
        cx.temporal().content_date(DateField::Expires, t, true);
    }
    let devices = get("ProvisionedDevices").and_then(Plist::as_array).map(Vec::len);
    let all = get_bool(p, "ProvisionsAllDevices") == Some(true);
    let ent = get("Entitlements");
    let debug = ent.and_then(|e| get_bool(e, "get-task-allow")) == Some(true);
    let kind = match (all, devices, debug) {
        (true, ..) => "enterprise",
        (false, Some(_), true) => "development",
        (false, Some(_), false) => "ad_hoc",
        (false, None, _) => "app_store",
    };
    cx.format_set("distribution", kind);
    if let Some(n) = devices {
        cx.format_set("provisioned_devices", n);
    }
    if let Some(n) = get("DeveloperCertificates").and_then(Plist::as_array).map(Vec::len) {
        cx.format_set("developer_certificates", n);
    }
    if let Some(e) = ent {
        if let Some(keys) = top_keys(e) {
            cx.format_set("entitlements", keys);
        }
        copy_strings(cx, e, &[("application-identifier", "application_identifier"), ("aps-environment", "push")]);
        if debug {
            cx.security().risk("debuggable", Some("get-task-allow entitlement".into()));
        }
    }
}

/// Report the action histogram and flag the actions that run scripts.
fn actions(cx: &mut Context<'_>, ids: &[&str]) {
    cx.format_set("actions", ids.len());
    let mut hist: BTreeMap<&str, u64> = BTreeMap::new();
    for id in ids {
        *hist.entry(id).or_default() += 1;
    }
    let mut v: Vec<(&str, u64)> = hist.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if !v.is_empty() {
        let m: Map<String, Value> =
            v.iter().take(TOP).map(|(k, n)| (truncate_chars(k, 120), Value::from(*n))).collect();
        cx.format_set("action_types", Value::Object(m));
    }
    let scripts: Vec<&str> = SCRIPT_ACTIONS.into_iter().filter(|a| ids.contains(a)).collect();
    if !scripts.is_empty() {
        cx.security().risk("shell_action", Some(scripts.join(", ")));
    }
}

fn shortcut(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(
        cx,
        p,
        &[("WFWorkflowClientVersion", "client_version"), ("WFWorkflowMinimumClientVersionString", "minimum_client")],
    );
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    let acts = get("WFWorkflowActions").and_then(Plist::as_array).map_or(&[][..], Vec::as_slice);
    let ids: Vec<&str> = acts.iter().filter_map(|a| get_str(a, "WFWorkflowActionIdentifier")).collect();
    actions(cx, &ids);
    if let Some(n) = get("WFWorkflowImportQuestions").and_then(Plist::as_array).map(Vec::len).filter(|&n| n > 0) {
        cx.format_set("import_questions", n);
    }
    let inputs = strings(p, "WFWorkflowInputContentItemClasses");
    if !inputs.is_empty() {
        cx.format_set("input_types", inputs);
    }
    let types = strings(p, "WFWorkflowTypes");
    if !types.is_empty() {
        cx.format_set("workflow_types", types);
    }
}

fn automator(p: &Plist, cx: &mut Context<'_>) {
    copy_strings(
        cx,
        p,
        &[("AMApplicationBuild", "application_build"), ("AMApplicationVersion", "application_version")],
    );
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    if let Some(t) = get("workflowMetaData").and_then(|m| get_str(m, "workflowTypeIdentifier")) {
        cx.format_set("workflow_type", t);
    }
    let acts = get("actions").and_then(Plist::as_array).map_or(&[][..], Vec::as_slice);
    let ids: Vec<&str> = acts
        .iter()
        .filter_map(|a| a.as_dictionary()?.get("action"))
        .filter_map(|a| get_str(a, "BundleIdentifier").or_else(|| get_str(a, "ActionBundlePath")))
        .collect();
    actions(cx, &ids);
}

/// A GarageBand / Logic `MetaData.plist`: the song's tempo, key, time
/// signature, tracks and sample rate, and how many files of each kind it uses.
fn garageband_song(p: &Plist, cx: &mut Context<'_>) {
    let Some(d) = p.as_dictionary() else { return };
    let int = |k: &str| d.get(k).and_then(Plist::as_signed_integer);
    if let Some(bpm) =
        d.get("BeatsPerMinute").and_then(|v| v.as_real().or_else(|| v.as_signed_integer().map(|i| i as f64)))
    {
        cx.format_set("tempo_bpm", bpm);
    }
    if let Some(key) = get_str(p, "SongKey") {
        let mode = get_str(p, "SongGenderKey").unwrap_or("");
        cx.format_set("key", format!("{key} {mode}").trim().to_string());
    }
    if let (Some(n), Some(m)) = (int("SongSignatureNumerator"), int("SongSignatureDenominator")) {
        cx.format_set("time_signature", format!("{n}/{m}"));
    }
    for (key, out) in [("NumberOfTracks", "tracks"), ("SampleRate", "sample_rate"), ("Version", "version")] {
        if let Some(v) = int(key) {
            cx.format_set(out, v);
        }
    }
    let mut files = serde_json::Map::new();
    for (key, out) in [
        ("AudioFiles", "audio"),
        ("UnusedAudioFiles", "unused_audio"),
        ("SamplerInstrumentsFiles", "sampler_instruments"),
        ("UltrabeatFiles", "ultrabeat"),
        ("AlchemyFiles", "alchemy"),
        ("ImpulsResponsesFiles", "impulse_responses"),
        ("PlaybackFiles", "playback"),
        ("VideoFiles", "video"),
    ] {
        if let Some(n) = d.get(key).and_then(Plist::as_array).map(Vec::len).filter(|&n| n > 0) {
            files.insert(out.into(), n.into());
        }
    }
    if !files.is_empty() {
        cx.format_set("files_used", Value::Object(files));
    }
}

fn backup(p: &Plist, kind: &str, cx: &mut Context<'_>) {
    let strict = cx.privacy_strict();
    let src =
        if kind == "ios_backup_manifest" { p.as_dictionary().and_then(|d| d.get("Lockdown")).unwrap_or(p) } else { p };
    copy_strings(
        cx,
        src,
        &[
            ("Product Type", "product_type"),
            ("ProductType", "product_type"),
            ("Product Version", "ios_version"),
            ("ProductVersion", "ios_version"),
            ("Build Version", "build"),
            ("BuildVersion", "build"),
            ("iTunes Version", "itunes_version"),
            ("BackupState", "state"),
            ("SnapshotState", "snapshot_state"),
        ],
    );
    if !strict {
        copy_strings(
            cx,
            src,
            &[
                ("Device Name", "device_name"),
                ("DeviceName", "device_name"),
                ("Serial Number", "serial_number"),
                ("SerialNumber", "serial_number"),
                ("Target Identifier", "device_id"),
                ("UniqueDeviceID", "device_id"),
            ],
        );
    }
    let d = p.as_dictionary();
    let get = |k: &str| d.and_then(|d| d.get(k));
    for (key, out) in [("Last Backup Date", "backup_date"), ("Date", "backup_date")] {
        if let Some(t) = get(key).and_then(proplist::date) {
            cx.format_set(out, t.clone());
            cx.temporal().content_date(DateField::Created, t, true);
            break;
        }
    }
    for (key, out) in
        [("IsEncrypted", "encrypted"), ("WasPasscodeSet", "passcode_set"), ("IsFullBackup", "full_backup")]
    {
        if let Some(b) = get_bool(p, key) {
            cx.format_set(out, b);
        }
    }
    if get_bool(p, "IsEncrypted") == Some(true) {
        cx.security().encrypted(true);
    }
    if let Some(v) = get_str(p, "Version") {
        cx.format_set("backup_version", v);
    }
    let apps = get("Applications")
        .and_then(Plist::as_dictionary)
        .map(plist::Dictionary::len)
        .or_else(|| get("Installed Applications").and_then(Plist::as_array).map(Vec::len));
    if let Some(n) = apps {
        cx.format_set("applications", n);
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    fn xml(body: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">{body}</plist>"
        )
        .into_bytes()
    }

    #[test]
    fn profile_flags_root_certificates_and_passwords() {
        let body = "<dict><key>PayloadType</key><string>Configuration</string>\
            <key>PayloadContent</key><array>\
            <dict><key>PayloadType</key><string>com.apple.security.root</string></dict>\
            <dict><key>PayloadType</key><string>com.apple.wifi.managed</string>\
            <key>Password</key><string>not-a-real-one</string></dict></array></dict>";
        let r = report_for("x.mobileconfig", &xml(body));
        let f = &r.format["mobileconfig"];
        assert_eq!(f["payload_types"]["com.apple.security.root"], 1);
        let risks: Vec<&str> = r.security.risks.iter().map(|r| r.kind.as_str()).collect();
        assert!(risks.contains(&"installs_root_certificate") && risks.contains(&"embedded_secret"), "{risks:?}");
        assert!(!serde_json::to_string(&r).unwrap().contains("not-a-real-one"));
    }

    #[test]
    fn shortcut_script_actions() {
        let body = "<dict><key>WFWorkflowActions</key><array>\
            <dict><key>WFWorkflowActionIdentifier</key><string>is.workflow.actions.runshellscript</string></dict>\
            <dict><key>WFWorkflowActionIdentifier</key><string>is.workflow.actions.comment</string></dict>\
            </array></dict>";
        let r = report_for("x.shortcut", &xml(body));
        assert_eq!(r.format["shortcut"]["actions"], 2);
        assert!(r.security.risks.iter().any(|r| r.kind == "shell_action"));
    }

    #[test]
    fn keyed_archive_classes() {
        let body = "<dict><key>$archiver</key><string>NSKeyedArchiver</string>\
            <key>$version</key><integer>100000</integer>\
            <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>\
            <key>$objects</key><array><string>$null</string>\
            <dict><key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict></dict>\
            <dict><key>$classname</key><string>NSDictionary</string></dict></array></dict>";
        let r = report_for("x.plist", &xml(body));
        let f = &r.format["plist"];
        assert_eq!((f["kind"].as_str(), f["root_class"].as_str()), (Some("keyed_archive"), Some("NSDictionary")));
    }

    crate::fixture_tests!(
        "plist",
        "bplist",
        "info_plist",
        "ios_backup_plist",
        "mobileconfig",
        "mobileprovision",
        "shortcut"
    );
}
