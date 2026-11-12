//! Well-known document schemas recognised inside JSON, YAML and TOML:
//! what the configuration *is* and the handful of facts that matter for it.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{Context, DateField, TextRole, parse_date, truncate_chars};

/// A detector for one known schema.
type Detector = fn(&Value, &str, &mut Context<'_>) -> Option<Value>;

/// Recognise a known schema in `docs` (one per YAML document). Writes title
/// and description when the schema has them and returns a summary for
/// `format.<id>.known_schema`.
pub(crate) fn detect(docs: &[Value], name: Option<&str>, cx: &mut Context<'_>) -> Option<Value> {
    let name = name.map(str::to_ascii_lowercase).unwrap_or_default();
    let first = docs.first()?;
    let detectors: [Detector; 13] = [
        openapi,
        json_schema,
        geojson,
        har,
        sarif,
        web_manifest,
        browser_extension,
        lottie,
        excalidraw,
        postman,
        compose,
        github_actions,
        helm_chart,
    ];
    // A `kustomization.yaml` has `apiVersion` / `kind` too.
    if let Some(v) = kustomize(first, &name, cx) {
        return Some(v);
    }
    if let Some(v) = kubernetes(docs) {
        return Some(v);
    }
    if let Some(v) = ansible(first) {
        return Some(v);
    }
    if let Some(v) = cloudformation(first) {
        return Some(v);
    }
    for d in detectors {
        if let Some(v) = d(first, &name, cx) {
            return Some(v);
        }
    }
    if let Some(v) = gitlab_ci(first, &name) {
        return Some(v);
    }
    if let Some(v) = conda(first, &name) {
        return Some(v);
    }
    let more: [Detector; 18] = [
        oci,
        tsdb_block_meta,
        terraform_state,
        data_package,
        dbt_artifact,
        js_tool_config,
        takeout_locations,
        drive_shortcut,
        scratch_project,
        vscode_config,
        kustomize,
        serverless,
        dependency_bots,
        pre_commit,
        asyncapi,
        jscalendar,
        jscontact,
        zeppelin,
    ];
    for d in more {
        if let Some(v) = d(first, &name, cx) {
            return Some(v);
        }
    }
    json_ld(first).or_else(|| tsconfig(first, &name))
}

/// Count of each value of `key` across `items`.
fn histogram<'v>(items: impl Iterator<Item = &'v Value>, key: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for i in items {
        if let Some(k) = i.get(key).and_then(Value::as_str) {
            *out.entry(k.to_string()).or_default() += 1;
        }
    }
    out
}

/// Schemas whose values are private (infrastructure state, a person's
/// contact details, where someone has been).
const PRIVATE: [&str; 4] = ["terraform_state", "jscontact", "google_location_history", "google_drive_shortcut"];

/// The generic path summary of a document, without its example values
/// under strict privacy when the document is one of the [`PRIVATE`]
/// schemas: the examples would show what the schema reader keeps back.
pub(crate) fn schema_for(mut schema: Value, known: Option<&Value>, cx: &Context<'_>) -> Value {
    let private = known.and_then(|k| k.get("id")).and_then(Value::as_str).is_some_and(|id| PRIVATE.contains(&id));
    if private
        && cx.privacy_strict()
        && let Some(paths) = schema.get_mut("paths").and_then(Value::as_object_mut)
    {
        for p in paths.values_mut().filter_map(Value::as_object_mut) {
            p.remove("examples");
        }
    }
    schema
}

/// OCI image layouts (`oci-layout`), image indexes (`index.json`, Docker
/// manifest lists) and manifests, ORAS artifacts among them: platforms,
/// references, layers with their media types and sizes, the artifact type.
fn oci(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    if let Some(version) = v.get("imageLayoutVersion").and_then(Value::as_str) {
        return Some(json!({ "id": "oci_layout", "name": "OCI image layout", "version": version }));
    }
    if v.get("schemaVersion")?.as_i64()? != 2 {
        return None;
    }
    let media = v.get("mediaType").and_then(Value::as_str).unwrap_or("");
    let docker = media.starts_with("application/vnd.docker.");
    let annotation = |o: &Value, k: &str| o.pointer(&format!("/annotations/{}", k.replace('/', "~1"))).cloned();
    let mut out = Map::new();
    if let Some(list) = v.get("manifests").and_then(Value::as_array) {
        out.insert("id".into(), json!("oci_index"));
        out.insert("name".into(), json!(if docker { "Docker manifest list" } else { "OCI image index" }));
        out.insert("manifests".into(), json!(list.len()));
        let platforms: Vec<String> = list
            .iter()
            .filter_map(|m| {
                let p = m.get("platform")?;
                let mut s = format!("{}/{}", p.get("os")?.as_str()?, p.get("architecture")?.as_str()?);
                if let Some(var) = p.get("variant").and_then(Value::as_str) {
                    s = format!("{s}/{var}");
                }
                Some(s)
            })
            .take(50)
            .collect();
        if !platforms.is_empty() {
            out.insert("platforms".into(), json!(platforms));
        }
        let refs: Vec<Value> =
            list.iter().filter_map(|m| annotation(m, "org.opencontainers.image.ref.name")).take(50).collect();
        if !refs.is_empty() {
            out.insert("references".into(), json!(refs));
        }
        let types = histogram(list.iter(), "artifactType");
        if !types.is_empty() {
            out.insert("artifact_types".into(), json!(types));
        }
    } else if v.get("config").is_some() || v.get("layers").is_some() || v.get("blobs").is_some() {
        let layers = v.get("layers").or_else(|| v.get("blobs")).and_then(Value::as_array);
        let config_type = v.pointer("/config/mediaType").and_then(Value::as_str);
        let artifact = v
            .get("artifactType")
            .and_then(Value::as_str)
            .or(config_type.filter(|t| !t.ends_with(".image.config.v1+json") && !t.contains("container.image")));
        out.insert("id".into(), json!("oci_manifest"));
        out.insert(
            "name".into(),
            json!(match (docker, artifact.is_some()) {
                (true, _) => "Docker image manifest",
                (false, true) => "OCI artifact manifest (ORAS)",
                (false, false) => "OCI image manifest",
            }),
        );
        if let Some(a) = artifact {
            out.insert("artifact_type".into(), json!(a));
        }
        if let Some(c) = config_type {
            out.insert("config_media_type".into(), json!(c));
        }
        let list = layers.map(Vec::as_slice).unwrap_or_default();
        out.insert("layers".into(), json!(list.len()));
        let size: u64 = list.iter().filter_map(|l| l.get("size").and_then(Value::as_u64)).sum();
        out.insert("layer_bytes".into(), json!(size));
        let types = histogram(list.iter(), "mediaType");
        if !types.is_empty() {
            out.insert("layer_media_types".into(), json!(types));
        }
        let titles: Vec<Value> =
            list.iter().filter_map(|l| annotation(l, "org.opencontainers.image.title")).take(50).collect();
        if !titles.is_empty() {
            out.insert("files".into(), json!(titles));
        }
        if v.get("subject").is_some() {
            out.insert("refers_to".into(), json!(v.pointer("/subject/digest")));
        }
    } else {
        return None;
    }
    if let Some(t) = annotation(v, "org.opencontainers.image.created") {
        out.insert("created".into(), t);
    }
    Some(Value::Object(out))
}

/// A Prometheus TSDB block's `meta.json`: the time range, series, samples
/// and chunks, the compaction level and sources.
fn tsdb_block_meta(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let (min, max) = (v.get("minTime")?.as_i64()?, v.get("maxTime")?.as_i64()?);
    v.get("ulid")?.as_str()?;
    let ms = |t: i64| {
        let ticks = t.checked_mul(10_000)?.checked_add(116_444_736_000_000_000)?;
        crate::plugin::filetime(u64::try_from(ticks).ok()?)
    };
    Some(json!({
        "id": "prometheus_tsdb_block",
        "name": "Prometheus TSDB block metadata",
        "ulid": v.get("ulid"),
        "time_range": [ms(min), ms(max)],
        "series": get(v, &["stats", "numSeries"]),
        "samples": get(v, &["stats", "numSamples"]),
        "chunks": get(v, &["stats", "numChunks"]),
        "compaction_level": get(v, &["compaction", "level"]),
        "sources": len(get(v, &["compaction", "sources"])),
        "version": v.get("version"),
    }))
}

/// Terraform state: resources by type, providers, serial and versions.
/// Attribute and output values only with `--privacy off`, and then never
/// the sensitive ones or anything that looks like a secret.
fn terraform_state(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    v.get("terraform_version")?;
    let resources = v.get("resources")?.as_array()?;
    let mut providers: Vec<String> = resources
        .iter()
        .filter_map(|r| s(r, &["provider"]))
        .map(|p| p.trim_start_matches("provider[\"").split('"').next().unwrap_or(p).to_string())
        .collect();
    providers.sort();
    providers.dedup();
    let instances: usize = resources.iter().map(|r| len(r.get("instances"))).sum();
    let sensitive = resources
        .iter()
        .flat_map(|r| r.get("instances").and_then(Value::as_array).into_iter().flatten())
        .filter(|i| i.get("sensitive_attributes").and_then(Value::as_array).is_some_and(|a| !a.is_empty()))
        .count();
    let mut out = json!({
        "id": "terraform_state",
        "name": "Terraform state",
        "state_version": v.get("version"),
        "terraform_version": v.get("terraform_version"),
        "serial": v.get("serial"),
        "resources": resources.len(),
        "instances": instances,
        "resource_types": histogram(resources.iter().filter(|r| s(r, &["mode"]) != Some("data")), "type"),
        "data_sources": resources.iter().filter(|r| s(r, &["mode"]) == Some("data")).count(),
        "providers": providers,
        "outputs": keys(v.get("outputs"), 100),
        "instances_with_sensitive_attributes": sensitive,
    });
    if !cx.privacy_strict() {
        out["resource_list"] = resources.iter().take(200).map(terraform_resource).collect();
        out["output_values"] = v
            .get("outputs")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .take(100)
                    .map(|(k, e)| {
                        let shown = if e.get("sensitive").and_then(Value::as_bool) == Some(true) {
                            json!("(sensitive)")
                        } else {
                            scalar(e.get("value"))
                        };
                        (k.clone(), shown)
                    })
                    .collect::<serde_json::Map<_, _>>()
            })
            .into();
    }
    Some(out)
}

/// A scalar shown as found, with anything that looks like a secret
/// redacted; arrays and objects are summarised by their size.
fn scalar(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(t)) => json!(crate::plugin::redact_secrets(t)),
        Some(Value::Array(a)) => json!(format!("({} items)", a.len())),
        Some(Value::Object(o)) => json!(format!("({} keys)", o.len())),
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

/// One state resource with `--privacy off`: its address and each
/// instance's top-level attributes, minus the ones Terraform marks
/// sensitive.
fn terraform_resource(r: &Value) -> Value {
    let address = [s(r, &["module"]), s(r, &["mode"]).filter(|m| *m == "data"), s(r, &["type"]), s(r, &["name"])]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(".");
    let instances: Vec<Value> = r
        .get("instances")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20)
        .map(|i| {
            let hidden: Vec<&str> = i
                .get("sensitive_attributes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_array()?.first()?.get("value")?.as_str())
                .collect();
            let attrs: serde_json::Map<String, Value> = i
                .get("attributes")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .take(100)
                .map(|(k, a)| {
                    let secret = hidden.contains(&k.as_str()) || crate::plugin::is_secret_key(k);
                    let shown = if secret { json!("(sensitive)") } else { scalar(Some(a)) };
                    (k.clone(), shown)
                })
                .collect();
            json!({ "index_key": i.get("index_key"), "attributes": attrs })
        })
        .collect();
    json!({ "address": address, "instances": instances })
}

/// Frictionless data packages and CSV on the Web (CSVW) metadata.
fn data_package(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let csvw = v.get("@context").is_some_and(|c| c.to_string().contains("www.w3.org/ns/csvw"));
    if csvw {
        let tables = v.get("tables").and_then(Value::as_array).map_or(1, Vec::len);
        let columns = |t: &Value| len(get(t, &["tableSchema", "columns"]));
        let cols: usize =
            v.get("tables").and_then(Value::as_array).map_or_else(|| columns(v), |a| a.iter().map(columns).sum());
        title(cx, "csvw", s(v, &["dc:title"]).or_else(|| s(v, &["title"])), None);
        return Some(
            json!({ "id": "csvw", "name": "CSV on the Web metadata", "tables": tables, "columns": cols, "url": v.get("url") }),
        );
    }
    let resources = v.get("resources")?.as_array()?;
    if !name.starts_with("datapackage")
        && v.get("profile").is_none()
        && !resources.iter().any(|r| r.get("schema").is_some())
    {
        return None;
    }
    title(cx, "datapackage", s(v, &["title"]), s(v, &["description"]));
    let fields: usize = resources.iter().map(|r| len(get(r, &["schema", "fields"]))).sum();
    Some(json!({
        "id": "datapackage",
        "name": "Frictionless data package",
        "package": v.get("name"),
        "profile": v.get("profile"),
        "resources": resources.len(),
        "resource_names": resources.iter().filter_map(|r| s(r, &["name"])).take(50).collect::<Vec<_>>(),
        "fields": fields,
        "licenses": v.get("licenses").and_then(Value::as_array).map(|a| a.iter().filter_map(|l| s(l, &["name"])).collect::<Vec<_>>()),
    }))
}

/// dbt artifacts: `manifest.json` (models, sources, tests …) and `catalog.json`.
fn dbt_artifact(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let schema = s(v, &["metadata", "dbt_schema_version"])?;
    let kind = schema.rsplit('/').next().unwrap_or(schema).split('.').next().unwrap_or("");
    let nodes = v.get("nodes").and_then(Value::as_object);
    let by_type = nodes.map(|n| histogram(n.values(), "resource_type")).unwrap_or_default();
    Some(json!({
        "id": "dbt_artifact",
        "name": "dbt artifact",
        "artifact": kind,
        "dbt_version": s(v, &["metadata", "dbt_version"]),
        "adapter": s(v, &["metadata", "adapter_type"]),
        "nodes": nodes.map_or(0, Map::len),
        "node_types": by_type,
        "sources": len(v.get("sources")),
        "exposures": len(v.get("exposures")),
        "metrics": len(v.get("metrics")),
    }))
}

/// ESLint, Prettier and Babel configuration files.
fn js_tool_config(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let o = obj(v)?;
    let list = |k: &str| -> Vec<String> {
        match v.get(k) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| {
                    x.as_str().map(str::to_string).or_else(|| x.as_array()?.first()?.as_str().map(str::to_string))
                })
                .collect(),
            _ => Vec::new(),
        }
    };
    if name.contains("eslintrc")
        || (o.contains_key("rules") && (o.contains_key("extends") || o.contains_key("parserOptions")))
    {
        return Some(json!({
            "id": "eslint",
            "name": "ESLint configuration",
            "extends": list("extends"),
            "plugins": list("plugins"),
            "rules": len(v.get("rules")),
            "env": keys(v.get("env"), 20),
            "parser": v.get("parser"),
        }));
    }
    if name.contains("babelrc") || name.starts_with("babel.config") {
        return Some(
            json!({ "id": "babel", "name": "Babel configuration", "presets": list("presets"), "plugins": list("plugins") }),
        );
    }
    if name.contains("prettierrc") {
        return Some(
            json!({ "id": "prettier", "name": "Prettier configuration", "options": o.keys().take(30).cloned().collect::<Vec<_>>() }),
        );
    }
    None
}

/// Google Takeout location history: `Records.json` points and the
/// semantic timeline. Counts and the date range; the bounding box only
/// with `--privacy off`.
fn takeout_locations(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let (kind, items) = if let Some(a) = v.get("locations").and_then(Value::as_array) {
        ("records", a)
    } else {
        ("semantic_timeline", v.get("timelineObjects")?.as_array()?)
    };
    if kind == "records" && !items.iter().take(5).any(|p| p.get("latitudeE7").is_some()) {
        return None;
    }
    let mut stamps: Vec<String> = Vec::new();
    let (mut lat, mut lon) = (Vec::new(), Vec::new());
    for p in items {
        let t = s(p, &["timestamp"]).map(str::to_string).or_else(|| {
            let ms: i64 = s(p, &["timestampMs"])?.parse().ok()?;
            jiff::Timestamp::from_millisecond(ms).ok().map(|t| t.to_string())
        });
        stamps.extend(t);
        if let (Some(a), Some(b)) =
            (p.get("latitudeE7").and_then(Value::as_i64), p.get("longitudeE7").and_then(Value::as_i64))
        {
            lat.push(a);
            lon.push(b);
        }
    }
    stamps.sort();
    let mut out = json!({
        "id": "google_location_history",
        "name": "Google Takeout location history",
        "kind": kind,
        "entries": items.len(),
        "date_range": match (stamps.first(), stamps.last()) {
            (Some(a), Some(b)) => json!([a, b]),
            _ => Value::Null,
        },
    });
    if !cx.privacy_strict()
        && let (Some(a), Some(b), Some(c), Some(d)) =
            (lat.iter().min(), lat.iter().max(), lon.iter().min(), lon.iter().max())
    {
        #[allow(clippy::cast_precision_loss)]
        let deg = |e7: i64| (e7 as f64) / 1e7;
        out["bbox"] = json!([deg(*c), deg(*a), deg(*d), deg(*b)]);
    }
    Some(out)
}

/// Google Drive desktop shortcuts (`.gdoc`, `.gsheet` …): the document id
/// and kind; the account e-mail only without strict privacy.
fn drive_shortcut(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let url = s(v, &["url"])?;
    let kind = name.rsplit('.').next().filter(|e| e.starts_with('g') && e.len() <= 8)?;
    if !url.contains("google.com") {
        return None;
    }
    let mut out = json!({
        "id": "google_drive_shortcut",
        "name": "Google Drive shortcut",
        "kind": kind,
        "doc_id": v.get("doc_id").or_else(|| v.get("resource_id")),
        "url": url,
    });
    if !cx.privacy_strict()
        && let Some(e) = s(v, &["email"])
    {
        out["account"] = e.into();
    }
    Some(out)
}

/// Scratch 3 `project.json`: sprites, blocks, extensions, the editor.
fn scratch_project(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let targets = v.get("targets")?.as_array()?;
    let meta = v.get("meta")?;
    s(meta, &["semver"])?;
    let blocks: usize = targets.iter().map(|t| len(t.get("blocks"))).sum();
    Some(json!({
        "id": "scratch",
        "name": "Scratch project",
        "semver": s(meta, &["semver"]),
        "vm": s(meta, &["vm"]),
        "sprites": targets.iter().filter(|t| t.get("isStage") != Some(&Value::Bool(true))).count(),
        "sprite_names": targets.iter().filter(|t| t.get("isStage") != Some(&Value::Bool(true))).filter_map(|t| s(t, &["name"])).take(50).collect::<Vec<_>>(),
        "blocks": blocks,
        "costumes": targets.iter().map(|t| len(t.get("costumes"))).sum::<usize>(),
        "sounds": targets.iter().map(|t| len(t.get("sounds"))).sum::<usize>(),
        "extensions": v.get("extensions"),
    }))
}

/// VS Code `launch.json` / `tasks.json` and `.code-snippets`.
fn vscode_config(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    if let Some(configs) = v.get("configurations").and_then(Value::as_array) {
        return Some(json!({
            "id": "vscode_launch",
            "name": "VS Code launch configurations",
            "configurations": configs.len(),
            "types": histogram(configs.iter(), "type"),
            "names": configs.iter().filter_map(|c| s(c, &["name"])).take(50).collect::<Vec<_>>(),
        }));
    }
    if let Some(tasks) =
        v.get("tasks").and_then(Value::as_array).filter(|_| name == "tasks.json" || v.get("version").is_some())
        && tasks.iter().any(|t| t.get("label").is_some())
    {
        return Some(json!({
            "id": "vscode_tasks",
            "name": "VS Code tasks",
            "tasks": tasks.len(),
            "labels": tasks.iter().filter_map(|t| s(t, &["label"])).take(50).collect::<Vec<_>>(),
        }));
    }
    let o = obj(v)?;
    let snippet = |x: &Value| x.get("prefix").is_some() && x.get("body").is_some();
    let ext = std::path::Path::new(name).extension().and_then(|x| x.to_str()).unwrap_or("");
    if (ext.eq_ignore_ascii_case("code-snippets") || ext.eq_ignore_ascii_case("json"))
        && !o.is_empty()
        && o.values().all(snippet)
    {
        return Some(json!({
            "id": "vscode_snippets",
            "name": "VS Code snippets",
            "snippets": o.len(),
            "names": o.keys().take(50).cloned().collect::<Vec<_>>(),
            "scopes": histogram(o.values(), "scope"),
        }));
    }
    None
}

/// Kustomize `kustomization.yaml`.
fn kustomize(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let kind = s(v, &["kind"]);
    if kind != Some("Kustomization") && !name.starts_with("kustomization") {
        return None;
    }
    let images: Vec<String> = v
        .get("images")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|i| s(i, &["name"])).map(str::to_string).collect())
        .unwrap_or_default();
    Some(json!({
        "id": "kustomize",
        "name": "Kustomize configuration",
        "resources": len(v.get("resources")),
        "bases": len(v.get("bases")),
        "components": len(v.get("components")),
        "patches": len(v.get("patches")) + len(v.get("patchesStrategicMerge")) + len(v.get("patchesJson6902")),
        "namespace": v.get("namespace"),
        "images": images,
    }))
}

/// Serverless Framework `serverless.yml`.
fn serverless(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let provider = v.get("provider")?;
    let functions = v.get("functions");
    if v.get("service").is_none() || (functions.is_none() && !name.starts_with("serverless")) {
        return None;
    }
    Some(json!({
        "id": "serverless",
        "name": "Serverless Framework service",
        "service": v.get("service"),
        "provider": s(provider, &["name"]).map_or_else(|| provider.clone(), |p| json!(p)),
        "runtime": s(provider, &["runtime"]),
        "functions": keys(functions, 100),
        "plugins": v.get("plugins"),
    }))
}

/// Dependabot (`.github/dependabot.yml`) and Renovate (`renovate.json`).
fn dependency_bots(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    if let Some(updates) = v.get("updates").and_then(Value::as_array)
        && v.get("version").and_then(Value::as_i64) == Some(2)
        && updates.iter().any(|u| u.get("package-ecosystem").is_some())
    {
        return Some(json!({
            "id": "dependabot",
            "name": "Dependabot configuration",
            "ecosystems": histogram(updates.iter(), "package-ecosystem"),
            "intervals": updates.iter().filter_map(|u| s(u, &["schedule", "interval"])).collect::<std::collections::BTreeSet<_>>(),
        }));
    }
    let schema = s(v, &["$schema"]).is_some_and(|x| x.contains("renovate"));
    if schema || name.starts_with("renovate") || name == ".renovaterc" {
        return Some(json!({
            "id": "renovate",
            "name": "Renovate configuration",
            "extends": v.get("extends"),
            "package_rules": len(v.get("packageRules")),
            "schedule": v.get("schedule"),
        }));
    }
    None
}

/// `.pre-commit-config.yaml`: repositories and hooks.
fn pre_commit(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let repos = v.get("repos")?.as_array()?;
    if !name.starts_with(".pre-commit") && !repos.iter().any(|r| r.get("hooks").is_some() && r.get("repo").is_some()) {
        return None;
    }
    let hooks: Vec<&str> = repos
        .iter()
        .flat_map(|r| r.get("hooks").and_then(Value::as_array).into_iter().flatten())
        .filter_map(|h| s(h, &["id"]))
        .collect();
    Some(json!({
        "id": "pre_commit",
        "name": "pre-commit configuration",
        "repositories": repos.iter().filter_map(|r| s(r, &["repo"])).take(50).collect::<Vec<_>>(),
        "hooks": hooks.iter().take(100).collect::<Vec<_>>(),
    }))
}

/// AsyncAPI documents: version, title, channels, messages, servers.
fn asyncapi(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let version = s(v, &["asyncapi"])?;
    title(cx, "asyncapi.info", s(v, &["info", "title"]), s(v, &["info", "description"]));
    let messages = len(get(v, &["components", "messages"]));
    Some(json!({
        "id": "asyncapi",
        "name": "AsyncAPI document",
        "asyncapi": version,
        "api_version": s(v, &["info", "version"]),
        "channels": keys(v.get("channels"), 100),
        "operations": len(v.get("operations")),
        "messages": messages,
        "servers": keys(v.get("servers"), 50),
    }))
}

/// JSCalendar (RFC 8984) objects: events, tasks and groups.
fn jscalendar(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let kind = s(v, &["@type"]).filter(|t| matches!(*t, "Event" | "Task" | "Group"))?;
    v.get("uid")?;
    let entries = v.get("entries").and_then(Value::as_array);
    title(cx, "jscalendar", s(v, &["title"]), s(v, &["description"]));
    if let Some(st) = s(v, &["start"]) {
        cx.temporal().source("jscalendar.start").content_date(DateField::Created, st, s(v, &["timeZone"]).is_some());
    }
    Some(json!({
        "id": "jscalendar",
        "name": "JSCalendar object",
        "type": kind,
        "start": v.get("start"),
        "duration": v.get("duration"),
        "time_zone": v.get("timeZone"),
        "entries": entries.map(Vec::len),
        "entry_types": entries.map(|e| histogram(e.iter(), "@type")),
        "recurrence": v.get("recurrenceRules").is_some(),
    }))
}

/// JSContact (RFC 9553) cards: the kind and which properties are filled;
/// the values (a person's details) only with `--privacy off`.
fn jscontact(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    if s(v, &["@type"]) != Some("Card") || v.get("version").is_none() {
        return None;
    }
    let filled: Vec<&str> =
        obj(v)?.keys().map(String::as_str).filter(|k| !k.starts_with('@') && *k != "version").collect();
    let mut out = json!({
        "id": "jscontact",
        "name": "JSContact card",
        "version": v.get("version"),
        "kind": v.get("kind").unwrap_or(&json!("individual")),
        "properties": filled,
        "emails": len(v.get("emails")),
        "phones": len(v.get("phones")),
        "addresses": len(v.get("addresses")),
    });
    // With `--privacy off`, the card as written.
    if !cx.privacy_strict() {
        out["card"] = v.clone();
    }
    Some(out)
}

/// Apache Zeppelin notes (`.zpln`): paragraphs and interpreters.
fn zeppelin(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let paragraphs = v.get("paragraphs")?.as_array()?;
    let zpln = std::path::Path::new(name).extension().is_some_and(|x| x.eq_ignore_ascii_case("zpln"));
    if !zpln && v.get("config").is_none() {
        return None;
    }
    let mut interpreters: BTreeMap<String, u64> = BTreeMap::new();
    for p in paragraphs {
        if let Some(t) = s(p, &["text"]) {
            let i = t.trim_start().strip_prefix('%').and_then(|r| r.split_whitespace().next()).unwrap_or("(default)");
            *interpreters.entry(i.to_string()).or_default() += 1;
            cx.emit_text(TextRole::Body, t);
        }
    }
    title(cx, "zeppelin", s(v, &["name"]), None);
    Some(json!({
        "id": "zeppelin",
        "name": "Apache Zeppelin note",
        "paragraphs": paragraphs.len(),
        "interpreters": interpreters,
    }))
}

/// HTTP methods of `OpenAPI` path items.
const METHODS: [&str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// `GeoJSON` geometry types.
const GEOMETRIES: [&str; 7] =
    ["Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon", "GeometryCollection"];

/// Browser-extension permissions that reach every site or the browser itself.
const BROAD: [&str; 9] = [
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "tabs",
    "cookies",
    "webRequest",
    "debugger",
    "nativeMessaging",
];

/// Ansible task keys that are not module names.
const TASK_KEYS: [&str; 12] = [
    "name",
    "when",
    "register",
    "become",
    "tags",
    "with_items",
    "loop",
    "notify",
    "vars",
    "args",
    "ignore_errors",
    "delegate_to",
];

/// Top-level GitLab CI keys that are not jobs.
const RESERVED: [&str; 9] =
    ["stages", "variables", "include", "default", "workflow", "image", "services", "cache", "before_script"];

fn s<'v>(v: &'v Value, path: &[&str]) -> Option<&'v str> {
    get(v, path).and_then(Value::as_str)
}

fn get<'v>(v: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter().try_fold(v, |v, k| v.get(*k))
}

fn obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

fn len(v: Option<&Value>) -> usize {
    match v {
        Some(Value::Array(a)) => a.len(),
        Some(Value::Object(o)) => o.len(),
        _ => 0,
    }
}

fn keys(v: Option<&Value>, n: usize) -> Vec<String> {
    v.and_then(Value::as_object).map(|o| o.keys().take(n).cloned().collect()).unwrap_or_default()
}

fn title(cx: &mut Context<'_>, source: &str, t: Option<&str>, d: Option<&str>) {
    if let Some(t) = t {
        cx.content().source(source).title(t);
        cx.emit_text(TextRole::Title, t);
    }
    if let Some(d) = d {
        cx.content().source(source).description(truncate_chars(d, 1000));
        cx.emit_text(TextRole::Body, d);
    }
}

fn openapi(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let version = s(v, &["openapi"]).or_else(|| s(v, &["swagger"]))?;
    let paths = obj(v.get("paths")?)?;
    let mut operations: BTreeMap<&str, u64> = BTreeMap::new();
    let mut tags: BTreeMap<String, u64> = BTreeMap::new();
    for item in paths.values().filter_map(Value::as_object) {
        for (m, op) in item.iter().filter(|(m, _)| METHODS.contains(&m.as_str())) {
            *operations.entry(m.as_str()).or_default() += 1;
            for t in op.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                *tags.entry(t.to_string()).or_default() += 1;
            }
        }
    }
    title(cx, "openapi.info", s(v, &["info", "title"]), s(v, &["info", "description"]));
    if let Some(l) = s(v, &["info", "license", "name"]) {
        cx.rights().source("openapi.info.license").license(Some(l), s(v, &["info", "license", "url"]));
    }
    let servers: Vec<&str> = v.get("servers").and_then(Value::as_array).map_or_else(
        || s(v, &["host"]).into_iter().collect(),
        |a| a.iter().filter_map(|x| x.get("url").and_then(Value::as_str)).take(10).collect(),
    );
    let schemas = len(get(v, &["components", "schemas"]).or_else(|| v.get("definitions")));
    Some(json!({
        "id": "openapi",
        "name": if v.get("swagger").is_some() { "Swagger 2.0" } else { "OpenAPI" },
        "spec_version": version,
        "api_version": s(v, &["info", "version"]),
        "servers": servers,
        "paths": paths.len(),
        "operations": operations,
        "schemas": schemas,
        "security_schemes": keys(get(v, &["components", "securitySchemes"]).or_else(|| v.get("securityDefinitions")), 20),
        "tags": tags.keys().take(30).collect::<Vec<_>>(),
    }))
}

fn json_schema(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let schema = s(v, &["$schema"]).filter(|u| u.contains("json-schema.org"))?;
    title(cx, "json_schema", s(v, &["title"]), s(v, &["description"]));
    Some(json!({
        "id": "json_schema",
        "name": "JSON Schema",
        "draft": schema,
        "schema_id": s(v, &["$id"]).or_else(|| s(v, &["id"])),
        "type": v.get("type"),
        "properties": keys(v.get("properties"), 50),
        "required": v.get("required"),
        "definitions": len(v.get("$defs").or_else(|| v.get("definitions"))),
    }))
}

fn geojson(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let ty = s(v, &["type"])?;
    if ty == "Topology" && v.get("objects").is_some() {
        return Some(json!({ "id": "topojson", "name": "TopoJSON", "objects": keys(v.get("objects"), 50) }));
    }
    if ty != "FeatureCollection" && ty != "Feature" && !GEOMETRIES.contains(&ty) {
        return None;
    }
    if ty == "FeatureCollection" && !v.get("features").is_some_and(Value::is_array) {
        return None;
    }
    let features: Vec<&Value> = match v.get("features") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => vec![v],
    };
    let mut geometry: BTreeMap<String, u64> = BTreeMap::new();
    let mut props: BTreeMap<String, u64> = BTreeMap::new();
    for f in &features {
        let g = if ty == "Feature" || ty == "FeatureCollection" { f.get("geometry") } else { Some(*f) };
        if let Some(t) = g.and_then(|g| s(g, &["type"])) {
            *geometry.entry(t.to_string()).or_default() += 1;
        }
        for k in keys(f.get("properties"), 100) {
            *props.entry(k).or_default() += 1;
        }
    }
    Some(json!({
        "id": "geojson",
        "name": "GeoJSON",
        "type": ty,
        "features": features.len(),
        "geometry_types": geometry,
        "property_keys": props.keys().take(50).collect::<Vec<_>>(),
        "bbox": v.get("bbox"),
    }))
}

fn har(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let entries = get(v, &["log", "entries"])?.as_array()?;
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let mut status: BTreeMap<String, u64> = BTreeMap::new();
    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let mut times: Vec<(String, bool)> = Vec::new();
    for e in entries {
        if let Some(u) = s(e, &["request", "url"]) {
            let host = u.split("://").nth(1).and_then(|r| r.split(['/', '?', ':']).next()).unwrap_or("");
            *hosts.entry(host.to_ascii_lowercase()).or_default() += 1;
        }
        if let Some(m) = s(e, &["request", "method"]) {
            *methods.entry(m.to_string()).or_default() += 1;
        }
        if let Some(st) = get(e, &["response", "status"]) {
            *status.entry(st.to_string()).or_default() += 1;
        }
        if let Some(t) = s(e, &["startedDateTime"]).and_then(parse_date) {
            times.push(t);
        }
    }
    times.sort();
    if let Some((t, tz)) = times.first() {
        cx.temporal().source("har.startedDateTime").content_date(DateField::Created, t.clone(), *tz);
    }
    let mut top: Vec<(String, u64)> = hosts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(json!({
        "id": "har",
        "name": "HTTP Archive",
        "creator": s(v, &["log", "creator", "name"]),
        "browser": s(v, &["log", "browser", "name"]),
        "pages": len(get(v, &["log", "pages"])),
        "entries": entries.len(),
        "methods": methods,
        "status": status,
        "top_hosts": top.into_iter().take(10).map(|(h, n)| json!({ "host": h, "requests": n })).collect::<Vec<_>>(),
        "first_request": times.first().map(|t| &t.0),
        "last_request": times.last().map(|t| &t.0),
    }))
}

fn sarif(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let runs = v.get("runs")?.as_array()?;
    if !(s(v, &["$schema"]).is_some_and(|u| u.contains("sarif"))
        || s(v, &["version"]).is_some_and(|x| x.starts_with('2')))
    {
        return None;
    }
    let mut rules: BTreeMap<String, u64> = BTreeMap::new();
    let mut levels: BTreeMap<String, u64> = BTreeMap::new();
    let mut tools = Vec::new();
    let mut results = 0;
    for r in runs {
        if let Some(t) = s(r, &["tool", "driver", "name"]) {
            tools.push(t.to_string());
        }
        for res in r.get("results").and_then(Value::as_array).into_iter().flatten() {
            results += 1;
            if let Some(id) = s(res, &["ruleId"]) {
                *rules.entry(id.to_string()).or_default() += 1;
            }
            *levels.entry(s(res, &["level"]).unwrap_or("warning").to_string()).or_default() += 1;
        }
    }
    let mut top: Vec<(String, u64)> = rules.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(json!({
        "id": "sarif",
        "name": "SARIF static-analysis results",
        "version": s(v, &["version"]),
        "tools": tools,
        "results": results,
        "levels": levels,
        "top_rules": top.into_iter().take(10).map(|(r, n)| json!({ "rule": r, "results": n })).collect::<Vec<_>>(),
    }))
}

fn web_manifest(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let o = obj(v)?;
    let looks = o.contains_key("start_url") || (o.contains_key("icons") && o.contains_key("display"));
    if !looks || o.contains_key("manifest_version") {
        return None;
    }
    let _ = name;
    title(cx, "web_manifest.name", s(v, &["name"]), s(v, &["description"]));
    Some(json!({
        "id": "web_manifest",
        "name": "Web app manifest",
        "app_name": s(v, &["name"]),
        "short_name": s(v, &["short_name"]),
        "start_url": s(v, &["start_url"]),
        "display": s(v, &["display"]),
        "icons": len(v.get("icons")),
    }))
}

/// A WebExtension manifest's permissions (API and host), with the
/// broad-permission risk reported.
pub(crate) fn extension_permissions(v: &Value, cx: &mut Context<'_>) -> Vec<String> {
    let mut perms: Vec<String> = Vec::new();
    for key in ["permissions", "host_permissions", "optional_permissions"] {
        for p in v.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            perms.push(p.to_string());
        }
    }
    let broad: Vec<&String> = perms.iter().filter(|p| BROAD.contains(&p.as_str())).collect();
    if !broad.is_empty() {
        let detail = broad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        cx.security().risk("broad_extension_permissions", Some(detail));
    }
    perms
}

fn browser_extension(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let mv = v.get("manifest_version")?.as_u64()?;
    let o = obj(v)?;
    if !(o.contains_key("permissions") || o.contains_key("background") || o.contains_key("content_scripts")) {
        return None;
    }
    let perms = extension_permissions(v, cx);
    title(cx, "extension.name", s(v, &["name"]).filter(|n| !n.starts_with("__MSG_")), s(v, &["description"]));
    Some(json!({
        "id": "browser_extension",
        "name": "Browser extension manifest",
        "extension_name": s(v, &["name"]),
        "version": s(v, &["version"]),
        "manifest_version": mv,
        "permissions": perms,
        "content_scripts": len(v.get("content_scripts")),
    }))
}

fn lottie(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let o = obj(v)?;
    if !["v", "fr", "ip", "op", "layers"].iter().all(|k| o.contains_key(*k)) {
        return None;
    }
    let fr = v.get("fr").and_then(Value::as_f64).unwrap_or(0.0);
    let frames =
        v.get("op").and_then(Value::as_f64).unwrap_or(0.0) - v.get("ip").and_then(Value::as_f64).unwrap_or(0.0);
    Some(json!({
        "id": "lottie",
        "name": "Lottie animation",
        "version": s(v, &["v"]),
        "fps": fr,
        "frames": frames,
        "duration_s": if fr > 0.0 { Some((frames / fr * 1000.0).round() / 1000.0) } else { None },
        "width": v.get("w"),
        "height": v.get("h"),
        "layers": len(v.get("layers")),
    }))
}

fn excalidraw(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    if s(v, &["type"]) != Some("excalidraw") {
        return None;
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for e in v.get("elements").and_then(Value::as_array).into_iter().flatten() {
        if let Some(t) = s(e, &["type"]) {
            *kinds.entry(t.to_string()).or_default() += 1;
            if t == "text"
                && let Some(text) = s(e, &["text"])
            {
                cx.emit_text(TextRole::Body, text);
            }
        }
    }
    Some(json!({ "id": "excalidraw", "name": "Excalidraw drawing", "elements": kinds }))
}

fn postman(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    s(v, &["info", "schema"]).filter(|u| u.contains("getpostman.com"))?;
    // Count requests in nested folders without recursion.
    let (mut requests, mut folders) = (0u64, 0u64);
    let mut stack: Vec<&Value> =
        v.get("item").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    while let Some(item) = stack.pop() {
        if let Some(children) = item.get("item").and_then(Value::as_array) {
            folders += 1;
            stack.extend(children.iter());
        } else if item.get("request").is_some() {
            requests += 1;
        }
    }
    title(cx, "postman.info", s(v, &["info", "name"]), s(v, &["info", "description"]));
    Some(json!({ "id": "postman", "name": "Postman collection", "requests": requests, "folders": folders }))
}

fn compose(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let services = obj(v.get("services")?)?;
    let named = name.contains("compose");
    let looks = services.values().all(|s| s.get("image").is_some() || s.get("build").is_some());
    if !named && (!looks || services.is_empty()) {
        return None;
    }
    let mut images = Vec::new();
    let mut ports = Vec::new();
    for svc in services.values() {
        if let Some(i) = s(svc, &["image"]) {
            images.push(i.to_string());
        }
        for p in svc.get("ports").and_then(Value::as_array).into_iter().flatten() {
            ports.push(match p {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
    }
    Some(json!({
        "id": "docker_compose",
        "name": "Docker Compose",
        "services": services.keys().collect::<Vec<_>>(),
        "images": images,
        "ports": ports,
        "volumes": keys(v.get("volumes"), 30),
        "networks": keys(v.get("networks"), 30),
    }))
}

fn github_actions(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let jobs = obj(v.get("jobs")?)?;
    let on = v.get("on")?;
    let _ = name;
    let triggers: Vec<String> = match on {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Value::Object(o) => o.keys().cloned().collect(),
        _ => Vec::new(),
    };
    let mut uses: BTreeMap<String, u64> = BTreeMap::new();
    let mut runs_on = Vec::new();
    for job in jobs.values() {
        if let Some(r) = job.get("runs-on") {
            runs_on.push(match r {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
        for step in job.get("steps").and_then(Value::as_array).into_iter().flatten() {
            if let Some(u) = s(step, &["uses"]) {
                *uses.entry(u.to_string()).or_default() += 1;
            }
        }
        if let Some(u) = s(job, &["uses"]) {
            *uses.entry(u.to_string()).or_default() += 1;
        }
    }
    if let Some(n) = s(v, &["name"]) {
        cx.content().source("workflow.name").title(n);
    }
    runs_on.dedup();
    Some(json!({
        "id": "github_actions",
        "name": "GitHub Actions workflow",
        "workflow": s(v, &["name"]),
        "triggers": triggers,
        "jobs": jobs.keys().collect::<Vec<_>>(),
        "runs_on": runs_on,
        "actions": uses.keys().take(50).collect::<Vec<_>>(),
        "permissions": v.get("permissions"),
    }))
}

fn helm_chart(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    if !name.ends_with("chart.yaml") && !name.ends_with("chart.yml") {
        return None;
    }
    s(v, &["name"])?;
    title(cx, "chart.name", s(v, &["name"]), s(v, &["description"]));
    let deps: Vec<&str> = v
        .get("dependencies")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|d| d.get("name").and_then(Value::as_str)).collect())
        .unwrap_or_default();
    Some(json!({
        "id": "helm_chart",
        "name": "Helm chart",
        "chart": s(v, &["name"]),
        "version": s(v, &["version"]),
        "app_version": v.get("appVersion"),
        "api_version": s(v, &["apiVersion"]),
        "dependencies": deps,
    }))
}

fn kubernetes(docs: &[Value]) -> Option<Value> {
    let resources: Vec<&Value> = docs
        .iter()
        .flat_map(|d| match (s(d, &["kind"]), d.get("items")) {
            (Some("List"), Some(Value::Array(items))) => items.iter().collect::<Vec<_>>(),
            _ => vec![d],
        })
        .filter(|d| s(d, &["apiVersion"]).is_some() && s(d, &["kind"]).is_some())
        .collect();
    if resources.is_empty() {
        return None;
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut images: Vec<String> = Vec::new();
    let mut list = Vec::new();
    for r in &resources {
        let kind = s(r, &["kind"]).unwrap_or_default();
        *kinds.entry(kind.to_string()).or_default() += 1;
        if list.len() < 50 {
            list.push(json!({
                "kind": kind,
                "name": s(r, &["metadata", "name"]),
                "namespace": s(r, &["metadata", "namespace"]),
            }));
        }
        // Containers sit at different depths per kind; search for them.
        let mut stack = vec![*r];
        while let Some(v) = stack.pop() {
            match v {
                Value::Object(o) => {
                    for (k, x) in o {
                        if (k == "containers" || k == "initContainers")
                            && let Value::Array(cs) = x
                        {
                            for c in cs {
                                if let Some(i) = s(c, &["image"])
                                    && !images.iter().any(|x| x == i)
                                    && images.len() < 50
                                {
                                    images.push(i.to_string());
                                }
                            }
                        } else {
                            stack.push(x);
                        }
                    }
                }
                Value::Array(a) => stack.extend(a.iter()),
                _ => {}
            }
        }
    }
    Some(
        json!({ "id": "kubernetes", "name": "Kubernetes manifest", "kinds": kinds, "resources": list, "images": images }),
    )
}

fn ansible(v: &Value) -> Option<Value> {
    let plays = v.as_array()?;
    let is_play = |p: &Value| p.get("hosts").is_some() && (p.get("tasks").is_some() || p.get("roles").is_some());
    if plays.is_empty() || !plays.iter().all(|p| is_play(p) || p.get("import_playbook").is_some()) {
        return None;
    }
    let mut modules: BTreeMap<String, u64> = BTreeMap::new();
    let mut roles = Vec::new();
    let mut hosts = Vec::new();
    for p in plays {
        if let Some(h) = p.get("hosts") {
            hosts.push(h.clone());
        }
        for r in p.get("roles").and_then(Value::as_array).into_iter().flatten() {
            roles.push(
                r.as_str().map(str::to_string).or_else(|| s(r, &["role"]).map(str::to_string)).unwrap_or_default(),
            );
        }
        for t in p.get("tasks").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
            if let Some(m) = t.keys().find(|k| !TASK_KEYS.contains(&k.as_str())) {
                *modules.entry(m.clone()).or_default() += 1;
            }
        }
    }
    Some(
        json!({ "id": "ansible_playbook", "name": "Ansible playbook", "plays": plays.len(), "hosts": hosts, "roles": roles, "modules": modules }),
    )
}

fn cloudformation(v: &Value) -> Option<Value> {
    let resources = obj(v.get("Resources")?)?;
    let typed = resources.values().filter_map(|r| s(r, &["Type"])).filter(|t| t.contains("::")).count();
    if v.get("AWSTemplateFormatVersion").is_none() && typed == 0 {
        return None;
    }
    let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
    for r in resources.values() {
        if let Some(t) = s(r, &["Type"]) {
            *by_type.entry(t.to_string()).or_default() += 1;
        }
    }
    Some(json!({
        "id": "cloudformation",
        "name": if v.get("Transform").is_some() { "AWS SAM template" } else { "AWS CloudFormation template" },
        "description": s(v, &["Description"]),
        "resources": by_type,
        "parameters": keys(v.get("Parameters"), 50),
        "outputs": keys(v.get("Outputs"), 50),
    }))
}

fn gitlab_ci(v: &Value, name: &str) -> Option<Value> {
    if !name.ends_with(".gitlab-ci.yml") && !name.ends_with(".gitlab-ci.yaml") {
        return None;
    }
    let o = obj(v)?;
    let jobs: Vec<&String> = o
        .iter()
        .filter(|(k, j)| !RESERVED.contains(&k.as_str()) && !k.starts_with('.') && j.is_object())
        .map(|(k, _)| k)
        .collect();
    Some(json!({ "id": "gitlab_ci", "name": "GitLab CI pipeline", "stages": v.get("stages"), "jobs": jobs }))
}

fn conda(v: &Value, name: &str) -> Option<Value> {
    let deps = v.get("dependencies")?.as_array()?;
    if !(name.starts_with("environment") || v.get("channels").is_some()) {
        return None;
    }
    Some(
        json!({ "id": "conda_environment", "name": "conda environment", "env": s(v, &["name"]), "channels": v.get("channels"), "dependencies": deps.len() }),
    )
}

fn json_ld(v: &Value) -> Option<Value> {
    v.get("@context")?;
    let types: Vec<&Value> = match v.get("@graph") {
        Some(Value::Array(g)) => g.iter().filter_map(|n| n.get("@type")).take(20).collect(),
        _ => v.get("@type").into_iter().collect(),
    };
    Some(json!({ "id": "json_ld", "name": "JSON-LD", "types": types }))
}

fn tsconfig(v: &Value, name: &str) -> Option<Value> {
    let opts = v.get("compilerOptions")?;
    if !name.starts_with("tsconfig") && !name.starts_with("jsconfig") && v.get("include").is_none() {
        return None;
    }
    Some(json!({
        "id": "tsconfig",
        "name": "TypeScript project config",
        "target": s(opts, &["target"]),
        "module": s(opts, &["module"]),
        "strict": opts.get("strict"),
        "extends": v.get("extends"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Terraform values appear only with `--privacy off`, and attributes
    /// marked sensitive or named like secrets never do (neutral sample).
    #[test]
    fn terraform_values_follow_privacy() {
        let state = br#"{"version":4,"terraform_version":"1.9.0","serial":1,"outputs":{"site":{"value":"example.org"},"key":{"value":"k1","sensitive":true}},
            "resources":[{"mode":"managed","type":"t_user","name":"u","provider":"provider[\"x/t\"]","instances":[{"sensitive_attributes":[[{"type":"get_attr","value":"pin"}]],
            "attributes":{"name":"alpha","pin":"1234","api_token":"zz"}}]}]}"#;
        let strict = crate::plugin::testing::report_for("a.tfstate", state);
        let text = serde_json::to_string(&strict).unwrap();
        assert!(!text.contains("alpha") && !text.contains("example.org"));
        let off = crate::plugin::testing::report_without_privacy("a.tfstate", state);
        let k = &off.format["json"]["known_schema"];
        assert_eq!(k["resource_list"][0]["address"], "t_user.u");
        let attrs = &k["resource_list"][0]["instances"][0]["attributes"];
        assert_eq!(attrs["name"], "alpha");
        assert_eq!(attrs["pin"], "(sensitive)");
        assert_eq!(attrs["api_token"], "(sensitive)");
        assert_eq!(k["output_values"]["site"], "example.org");
        assert_eq!(k["output_values"]["key"], "(sensitive)");
    }

    #[test]
    fn kubernetes_images() {
        let docs = [json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "web" },
            "spec": { "template": { "spec": { "containers": [{ "image": "nginx:1.27" }] } } }
        })];
        let k = kubernetes(&docs).unwrap();
        assert_eq!(k["images"], json!(["nginx:1.27"]));
        assert_eq!(k["kinds"]["Deployment"], 1);
    }
}
