//! .NET: `MSBuild` projects (`.csproj`, `.fsproj`, `.vbproj`, `.vcxproj`,
//! `Directory.*.props`), NuGet `packages.config` and Visual Studio
//! solutions (`.sln`).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{MAX_DEPS, Package, put_pairs};
use crate::plugin::xmlwalk::{Ev, attr, walk};
use crate::plugin::{Context, user_path};

/// Elements walked at most.
const MAX_EVENTS: usize = 500_000;

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) {
    let result = match id {
        "dotnet_project" => msbuild(text, cx),
        "nuget_packages" => packages_config(text, cx),
        _ => {
            solution(text, cx);
            Ok(())
        }
    };
    if let Err(e) = result {
        cx.warn(e.to_string());
    }
}

/// `MSBuild` properties reported as format fields.
const PROPERTIES: &[(&str, &str)] = &[
    ("TargetFramework", "target_framework"),
    ("OutputType", "output_type"),
    ("AssemblyName", "assembly_name"),
    ("RootNamespace", "root_namespace"),
    ("LangVersion", "lang_version"),
    ("Nullable", "nullable"),
    ("ImplicitUsings", "implicit_usings"),
    ("IsPackable", "is_packable"),
    ("UseWPF", "use_wpf"),
    ("UseWindowsForms", "use_windows_forms"),
    ("ManagePackageVersionsCentrally", "central_package_management"),
    ("ConfigurationType", "configuration_type"),
    ("PlatformToolset", "platform_toolset"),
    ("WindowsTargetPlatformVersion", "windows_sdk"),
    ("Company", "company"),
];

#[derive(Default)]
struct Project {
    sdk: Option<String>,
    props: BTreeMap<String, String>,
    packages: Vec<(String, String)>,
    projects: Vec<String>,
    framework_refs: Vec<String>,
    items: BTreeMap<&'static str, u64>,
    configurations: Vec<String>,
    targets: Vec<String>,
    exec_tasks: u64,
}

fn msbuild(text: &str, cx: &mut Context<'_>) -> Result<(), crate::plugin::ExtractError> {
    let mut p = Project::default();
    let mut path: Vec<String> = Vec::new();
    // A `<PackageReference>` whose version is a child element.
    let mut open_package: Option<usize> = None;
    walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        Ev::Start(name, a) => {
            path.push(name.to_string());
            let include = attr(a, "Include").or_else(|| attr(a, "Update"));
            match name {
                "Project" if path.len() == 1 => p.sdk = attr(a, "Sdk").map(str::to_string),
                "Sdk" | "Import" if p.sdk.is_none() => {
                    p.sdk = attr(a, "Sdk").or_else(|| attr(a, "Name")).map(str::to_string);
                }
                "PackageReference" | "PackageVersion" => {
                    if let Some(i) = include {
                        p.packages.push((i.to_string(), attr(a, "Version").unwrap_or("*").to_string()));
                        open_package = Some(p.packages.len() - 1);
                    }
                }
                "ProjectReference" => p.projects.extend(include.map(|i| user_path(cx, i))),
                "FrameworkReference" | "Reference" => p.framework_refs.extend(include.map(str::to_string)),
                "ProjectConfiguration" => p.configurations.extend(include.map(str::to_string)),
                "Target" => p.targets.extend(attr(a, "Name").map(str::to_string)),
                "Exec" => p.exec_tasks += 1,
                "Compile" | "ClCompile" | "ClInclude" | "Content" | "None" | "EmbeddedResource" => {
                    let kind = match name {
                        "Compile" | "ClCompile" => "compile",
                        "ClInclude" => "include",
                        "Content" => "content",
                        "EmbeddedResource" => "embedded_resource",
                        _ => "none",
                    };
                    *p.items.entry(kind).or_default() += 1;
                }
                _ => {}
            }
        }
        Ev::Text(t) => {
            let n = path.len();
            if n >= 2 && path[n - 2] == "PropertyGroup" && p.props.len() < 200 {
                p.props.entry(path[n - 1].clone()).or_insert_with(|| t.to_string());
            } else if n >= 2
                && path[n - 1] == "Version"
                && path[n - 2] == "PackageReference"
                && let Some(i) = open_package
            {
                p.packages[i].1 = t.to_string();
            }
        }
        Ev::End(name) => {
            if name == "PackageReference" || name == "PackageVersion" {
                open_package = None;
            }
            path.pop();
        }
    })?;
    report(p, cx);
    Ok(())
}

fn report(p: Project, cx: &mut Context<'_>) {
    let get = |k: &str| p.props.get(k).map(String::as_str);
    let name = get("PackageId").or_else(|| get("AssemblyName"));
    Package {
        ecosystem: "nuget",
        name,
        version: get("Version").or_else(|| get("VersionPrefix")).or_else(|| get("PackageVersion")),
        description: get("Description"),
        license: get("PackageLicenseExpression"),
        authors: get("Authors")
            .map(|a| a.split([';', ',']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default(),
        repository: get("RepositoryUrl").or_else(|| get("PackageProjectUrl")),
    }
    .write(cx);
    if let Some(sdk) = &p.sdk {
        cx.format_set("sdk", sdk.as_str());
    }
    if let Some(tfms) = get("TargetFrameworks") {
        let list: Vec<&str> = tfms.split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
        cx.format_set("target_frameworks", json!(list));
    }
    for (prop, key) in PROPERTIES {
        if let Some(v) = get(prop) {
            cx.format_set(key, v);
        }
    }
    put_pairs(cx, "dependencies", p.packages);
    for (key, list) in [
        ("project_references", p.projects),
        ("framework_references", p.framework_refs),
        ("configurations", p.configurations),
        ("targets", p.targets),
    ] {
        if !list.is_empty() {
            cx.format_set(key, json!(list.iter().take(MAX_DEPS).collect::<Vec<_>>()));
        }
    }
    if !p.items.is_empty() {
        cx.format_set("items", json!(p.items));
    }
    // `<Exec>` runs a command when the project is built.
    if p.exec_tasks > 0 {
        cx.format_set("exec_tasks", p.exec_tasks);
    }
}

fn packages_config(text: &str, cx: &mut Context<'_>) -> Result<(), crate::plugin::ExtractError> {
    let mut packages = Vec::new();
    let mut frameworks = std::collections::BTreeSet::new();
    let mut dev = 0u64;
    walk(text, cx, MAX_EVENTS, |_, ev| {
        if let Ev::Start("package", a) = ev
            && let Some(id) = attr(a, "id")
        {
            packages.push((id.to_string(), attr(a, "version").unwrap_or("*").to_string()));
            frameworks.extend(attr(a, "targetFramework").map(str::to_string));
            dev += u64::from(attr(a, "developmentDependency") == Some("true"));
        }
    })?;
    cx.format_set("ecosystem", "nuget");
    put_pairs(cx, "dependencies", packages);
    if !frameworks.is_empty() {
        cx.format_set("target_frameworks", json!(frameworks));
    }
    if dev > 0 {
        cx.format_set("development_dependencies", dev);
    }
    Ok(())
}

/// Project type GUIDs of the common project kinds.
fn project_type(guid: &str) -> &'static str {
    match guid.to_ascii_uppercase().as_str() {
        "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC" | "9A19103F-16F7-4668-BE54-9A1E7A4F7556" => "C#",
        "F184B08F-C81C-45F6-A57F-5ABD9991F28F" | "778DAE3C-4631-46EA-AA77-85C1314464D9" => "Visual Basic",
        "F2A71F9B-5D33-465A-A702-920D77279786" | "6EC3EE1D-3C4E-46DD-8F32-0CC8E7565705" => "F#",
        "8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942" => "C++",
        "2150E333-8FDC-42A3-9474-1A3956D46DE8" => "solution folder",
        "E24C65DC-7377-472B-9ABA-BC803B73C61A" => "web site",
        "888888A0-9F3D-457C-B088-3A5042F75D52" => "Python",
        "54435603-DBB4-11D2-8724-00A0C9A8B90C" => "setup",
        _ => "other",
    }
}

/// `.sln`: format and Visual Studio versions, projects (name, kind, path) and configurations.
fn solution(text: &str, cx: &mut Context<'_>) {
    let mut projects = Vec::new();
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    let mut configurations = Vec::new();
    let mut in_configs = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Microsoft Visual Studio Solution File, Format Version ") {
            cx.format_set("format_version", v.trim());
        } else if let Some(v) = t.strip_prefix("VisualStudioVersion =") {
            cx.format_set("visual_studio_version", v.trim());
        } else if let Some(v) = t.strip_prefix("MinimumVisualStudioVersion =") {
            cx.format_set("minimum_visual_studio_version", v.trim());
        } else if let Some(rest) = t.strip_prefix("Project(\"{") {
            // Project("{TYPE}") = "Name", "path\to.csproj", "{GUID}"
            let guid = rest.split('}').next().unwrap_or("");
            let fields = super::quoted(rest.split_once('=').map_or("", |(_, r)| r));
            let kind = project_type(guid);
            *kinds.entry(kind).or_default() += 1;
            if kind != "solution folder" && projects.len() < MAX_DEPS {
                let mut p = serde_json::Map::new();
                p.insert("name".into(), json!(fields.first()));
                p.insert("kind".into(), json!(kind));
                if let Some(path) = fields.get(1) {
                    p.insert("path".into(), json!(user_path(cx, path)));
                }
                projects.push(Value::Object(p));
            }
        } else if t.starts_with("GlobalSection(SolutionConfigurationPlatforms)") {
            in_configs = true;
        } else if t.starts_with("EndGlobalSection") {
            in_configs = false;
        } else if in_configs && let Some((c, _)) = t.split_once('=') {
            configurations.push(c.trim().to_string());
        }
    }
    cx.format_set("ecosystem", "nuget");
    cx.format_set("project_count", projects.len());
    cx.format_set("projects", Value::Array(projects));
    cx.format_set("project_kinds", json!(kinds));
    if !configurations.is_empty() {
        cx.format_set("configurations", json!(configurations));
    }
}
