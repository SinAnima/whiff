//! Configuration and deployment files that are not Dockerfiles or
//! Makefiles:
//! * Terraform / HCL (`.tf`, `.tfvars`, `.hcl`): blocks by type, resources
//!   and data sources by type, providers with their sources and versions,
//!   modules with their sources, the backend, required Terraform version,
//!   variables (sensitive ones counted) and outputs;
//! * ignore files (`.gitignore`, `.dockerignore`, `.npmignore` …):
//!   patterns, negations, directory patterns;
//! * crontabs: jobs, schedules (`@reboot`, every minute), the commands run,
//!   variables;
//! * SSH `ssh_config` / `sshd_config`: hosts, options, the settings that
//!   matter for security (`known_hosts` and `authorized_keys` are
//!   `crypto.ssh`'s);
//! * web servers: nginx and Apache (`httpd.conf`, `.htaccess`): server
//!   blocks / virtual hosts, server names, listen ports, TLS, locations,
//!   proxies, rewrites, modules, includes;
//! * Procfiles, Justfiles and Vagrantfiles: processes, recipes, boxes,
//!   providers and provisioners;
//! * Caddyfiles and `HAProxy` configurations: sites, directives,
//!   frontends, backends, servers.
//!
//! Host names in SSH client configurations are counted, not listed,
//! unless privacy is off.
//!
//! Specifications: HCL native syntax specification; Terraform language
//! documentation; gitignore(5); crontab(5); `ssh_config`(5), `sshd_config`(5); nginx and Apache HTTP Server directive references; Heroku
//! Procfile; the just manual; Vagrant docs; Caddyfile concepts; `HAProxy`
//! configuration manual.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
    user_path,
};

/// Extractor for configuration and deployment files.
pub struct Config;

macro_rules! formats {
    ($( $id:literal $name:literal $mime:literal [$($ext:literal),*] )*) => {
        &[$(FormatSpec {
            id: $id, name: $name, family: "code.infra", mimes: &[$mime], extensions: &[$($ext),*],
            magic: &[], parent: Some("text"),
        }),*]
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "code.config",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: formats! {
        "terraform" "Terraform / HCL" "text/x-hcl" ["tf", "tfvars", "hcl"]
        "ignore_file" ".gitignore / .dockerignore" "text/plain" ["gitignore", "dockerignore", "npmignore"]
        "crontab" "crontab" "text/plain" ["crontab", "cron"]
        "ssh_config" "SSH config" "text/plain" []
        "web_server_config" "nginx / Apache config" "text/plain" ["htaccess"]
        "procfile" "Procfile" "text/plain" []
        "justfile" "Justfile" "text/x-just" ["just"]
        "vagrantfile" "Vagrantfile" "text/x-ruby" []
        "caddyfile" "Caddyfile" "text/plain" ["caddyfile"]
        "haproxy_config" "HAProxy configuration" "text/plain" []
    },
};

/// The format of a file known by its name.
fn by_name(path: &str) -> Option<&'static str> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lower = base.to_ascii_lowercase();
    let in_ssh_dir = path.contains(".ssh/") || path.contains("/etc/ssh/");
    Some(match lower.as_str() {
        "ssh_config" | "sshd_config" => "ssh_config",
        "config" if in_ssh_dir => "ssh_config",
        "crontab" => "crontab",
        "nginx.conf" | "httpd.conf" | "apache2.conf" | ".htaccess" | "htaccess" => "web_server_config",
        "procfile" => "procfile",
        "justfile" | ".justfile" => "justfile",
        "vagrantfile" => "vagrantfile",
        "caddyfile" => "caddyfile",
        "haproxy.cfg" => "haproxy_config",
        _ if lower.starts_with('.') && lower.ends_with("ignore") && lower.len() > 7 => "ignore_file",
        _ if lower.starts_with("sshd_config.") || lower.starts_with("ssh_config.") => "ssh_config",
        _ => return None,
    })
}

impl Extractor for Config {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if let Some(f) = probe.name.and_then(by_name) {
            return Some(Sniff { format: f, confidence: 0.95 });
        }
        // nginx files under conf.d / sites-available end in `.conf` (INI's).
        if probe.extension == Some("conf") {
            let head = std::str::from_utf8(&probe.head[..probe.head.len().min(4096)]).ok()?;
            let nginx = head.lines().map(str::trim).any(|l| {
                (l.starts_with("server {") || l.starts_with("http {") || l.starts_with("upstream "))
                    || l.starts_with("location ") && l.ends_with('{')
            });
            let apache = head.contains("<VirtualHost") || head.contains("<Directory") || head.contains("\nLoadModule ");
            return (nginx || apache).then_some(Sniff { format: "web_server_config", confidence: 0.9 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let name = src.name_hint().unwrap_or("").to_string();
        let id = cx.format_id().to_string();
        cx.emit_text(if id == "ssh_config" { TextRole::Data } else { TextRole::Code }, &text);
        match id.as_str() {
            "terraform" => terraform(&text, &name, cx),
            "ignore_file" => ignore_file(&text, &name, cx),
            "crontab" => crontab(&text, cx),
            "ssh_config" => ssh_config(&text, &name, cx),
            "web_server_config" => web_server(&text, &name, cx),
            "procfile" => procfile(&text, cx),
            "justfile" => justfile(&text, cx),
            "vagrantfile" => vagrantfile(&text, cx),
            "caddyfile" => caddyfile(&text, cx),
            _ => haproxy(&text, cx),
        }
        Ok(())
    }
}

crate::register_extractor!(Config);

fn regex(p: &str) -> Regex {
    Regex::new(p).expect("valid")
}

fn bump(h: &mut BTreeMap<String, u64>, k: &str) {
    if h.len() < 200 || h.contains_key(k) {
        *h.entry(k.to_string()).or_default() += 1;
    }
}

fn set_list(cx: &mut Context<'_>, key: &str, v: impl IntoIterator<Item = String>) {
    let v: Vec<String> = v.into_iter().take(100).collect();
    if !v.is_empty() {
        cx.format_set(key, json!(v));
    }
}

fn set_hist(cx: &mut Context<'_>, key: &str, h: &BTreeMap<String, u64>) {
    if !h.is_empty() {
        cx.format_set(key, json!(h));
    }
}

// --- HCL / Terraform ------------------------------------------------------

/// One line of HCL with strings, heredocs and comments removed, and the
/// brace depth at its start.
struct HclLine {
    depth: usize,
    code: String,
}

fn hcl_lines(text: &str) -> Vec<HclLine> {
    let mut out = Vec::new();
    let (mut depth, mut in_block_comment) = (0usize, false);
    let mut heredoc: Option<String> = None;
    for raw in text.lines() {
        if let Some(end) = &heredoc {
            if raw.trim() == end {
                heredoc = None;
            }
            continue;
        }
        let start_depth = depth;
        let mut code = String::new();
        let mut chars = raw.char_indices().peekable();
        let mut in_str = false;
        while let Some((i, c)) = chars.next() {
            let rest = &raw[i..];
            if in_block_comment {
                if rest.starts_with("*/") {
                    in_block_comment = false;
                    chars.next();
                }
            } else if in_str {
                if c == '\\' {
                    chars.next();
                } else {
                    // Keep the string's text: block labels are strings.
                    code.push(c);
                    in_str = c != '"';
                }
            } else if c == '#' || rest.starts_with("//") {
                break;
            } else if rest.starts_with("/*") {
                in_block_comment = true;
                chars.next();
            } else if let Some(tag) = rest.strip_prefix("<<") {
                let tag = tag.trim_start_matches('-').trim();
                if !tag.is_empty() && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    heredoc = Some(tag.to_string());
                }
                break;
            } else {
                match c {
                    '"' => in_str = true,
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                code.push(c);
            }
        }
        out.push(HclLine { depth: start_depth, code });
    }
    out
}

#[allow(clippy::too_many_lines)] // one branch per block kind
fn terraform(text: &str, name: &str, cx: &mut Context<'_>) {
    static BLOCK: LazyLock<Regex> = LazyLock::new(|| regex(r#"^\s*([\w-]+)((?:\s+"[^"]*"|\s+[\w-]+)*)\s*\{"#));
    static ATTR: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*([\w-]+)\s*=\s*(.*)$"));
    static PROVIDER: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*([\w-]+)\s*=\s*\{(.*)\}?"));
    static QUOTED: LazyLock<Regex> = LazyLock::new(|| regex(r#"(\w+)\s*=\s*"([^"]*)""#));
    let lines = hcl_lines(text);
    if name.ends_with(".tfvars") || name.ends_with(".tfvars.json") {
        let vars: Vec<String> = lines
            .iter()
            .filter(|l| l.depth == 0)
            .filter_map(|l| ATTR.captures(&l.code).map(|c| c[1].to_string()))
            .collect();
        cx.format_set("kind", "variable values");
        cx.format_set("variable_count", vars.len());
        set_list(cx, "variables", vars);
        return;
    }
    let mut blocks: BTreeMap<String, u64> = BTreeMap::new();
    let (mut resources, mut data): (BTreeMap<String, u64>, BTreeMap<String, u64>) = Default::default();
    let mut providers: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut modules = Vec::new();
    let (mut variables, mut outputs) = (Vec::new(), Vec::new());
    let (mut sensitive, mut backend, mut required_version) = (0u64, None, None);
    // The open block at each depth: (type, labels).
    let mut stack: Vec<(String, Vec<String>)> = Vec::new();
    for l in &lines {
        stack.truncate(l.depth);
        let parent = stack.last().map_or("", |(t, _)| t.as_str());
        let grandparent = stack.len().checked_sub(2).and_then(|i| stack.get(i)).map_or("", |(t, _)| t.as_str());
        if let Some(c) = BLOCK.captures(&l.code) {
            let kind = c[1].to_string();
            let labels: Vec<String> =
                c[2].split_whitespace().map(|s| s.trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect();
            if l.depth == 0 {
                bump(&mut blocks, &kind);
                let first = labels.first().cloned().unwrap_or_default();
                match kind.as_str() {
                    "resource" => bump(&mut resources, &first),
                    "data" => bump(&mut data, &first),
                    "variable" => variables.push(first),
                    "output" => outputs.push(first),
                    "provider" => {
                        providers.entry(first).or_default();
                    }
                    _ => {}
                }
            } else if parent == "terraform" && kind == "backend" {
                backend = labels.first().cloned();
            } else if parent == "required_providers"
                && let Some(c) = PROVIDER.captures(&l.code)
            {
                let entry = providers.entry(c[1].to_string()).or_default();
                for q in QUOTED.captures_iter(&c[2]) {
                    entry.insert(q[1].to_string(), json!(truncate_chars(&q[2], 200)));
                }
            }
            // A one-line block (`x = { a = 1 }`, `variable "v" {}`) closes on its line.
            if !l.code.trim_end().ends_with('}') || l.code.matches('{').count() > l.code.matches('}').count() {
                stack.push((kind, labels));
            }
            continue;
        }
        if let Some(c) = ATTR.captures(&l.code) {
            let (key, value) = (&c[1], c[2].trim().trim_matches('"'));
            match (parent, key) {
                ("terraform", "required_version") => required_version = Some(value.to_string()),
                ("variable", "sensitive") if value == "true" => sensitive += 1,
                ("module", "source") => {
                    let label = stack.last().and_then(|(_, l)| l.first()).cloned().unwrap_or_default();
                    modules.push(json!({ "name": label, "source": truncate_chars(value, 300) }));
                }
                (_, "source" | "version") if grandparent == "required_providers" => {
                    if let Some((p, _)) = stack.last()
                        && let Some(e) = providers.get_mut(p)
                    {
                        e.insert(key.to_string(), json!(truncate_chars(value, 200)));
                    }
                }
                _ => {}
            }
        }
    }
    // Resource types name their provider: `aws_s3_bucket` → `aws`.
    for t in resources.keys().chain(data.keys()) {
        if let Some((p, _)) = t.split_once('_') {
            providers.entry(p.to_string()).or_default();
        }
    }
    set_hist(cx, "blocks", &blocks);
    set_hist(cx, "resources", &resources);
    set_hist(cx, "data_sources", &data);
    if !providers.is_empty() {
        cx.format_set("providers", json!(providers));
    }
    if !modules.is_empty() {
        cx.format_set("modules", Value::Array(modules.into_iter().take(100).collect()));
    }
    if let Some(b) = backend {
        cx.format_set("backend", b);
    }
    if let Some(v) = required_version {
        cx.format_set("required_version", v);
    }
    if !variables.is_empty() {
        cx.format_set("variable_count", variables.len());
    }
    set_list(cx, "variables", variables);
    set_list(cx, "outputs", outputs);
    if sensitive > 0 {
        cx.format_set("sensitive_variables", sensitive);
    }
}

// --- ignore files ----------------------------------------------------------

fn ignore_file(text: &str, name: &str, cx: &mut Context<'_>) {
    // `.gitignore` and `site.gitignore` are both git's.
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase();
    let tool = base.rsplit('.').next().unwrap_or("").trim_end_matches("ignore");
    let (mut patterns, mut negated, mut dirs, mut rooted) = (Vec::new(), 0u64, 0u64, 0u64);
    for line in text.lines() {
        let t = line.trim_end();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        negated += u64::from(t.starts_with('!'));
        dirs += u64::from(t.ends_with('/'));
        rooted += u64::from(t.trim_start_matches('!').starts_with('/'));
        patterns.push(truncate_chars(t, 200));
    }
    if !tool.is_empty() {
        cx.format_set("tool", tool);
    }
    cx.format_set("pattern_count", patterns.len());
    for (k, v) in [("negations", negated), ("directory_patterns", dirs), ("rooted_patterns", rooted)] {
        if v > 0 {
            cx.format_set(k, v);
        }
    }
    set_list(cx, "patterns", patterns);
}

// --- crontab ---------------------------------------------------------------

fn crontab(text: &str, cx: &mut Context<'_>) {
    let (mut jobs, mut every_minute, mut system) = (0u64, 0u64, 0u64);
    let (mut specials, mut commands): (BTreeMap<String, u64>, BTreeMap<String, u64>) = Default::default();
    let mut variables = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((k, _)) = t.split_once('=')
            && !k.contains(char::is_whitespace)
            && !t.starts_with('@')
        {
            variables.insert(k.trim().to_string());
            continue;
        }
        let words: Vec<&str> = t.split_whitespace().collect();
        let rest = if let Some(s) = words.first().and_then(|w| w.strip_prefix('@')) {
            bump(&mut specials, s);
            &words[1.min(words.len())..]
        } else if words.len() >= 6
            && words[..5].iter().all(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || "*/,-".contains(c)))
        {
            if words[..5] == ["*"; 5] || words[0] == "*/1" {
                every_minute += 1;
            }
            &words[5..]
        } else {
            continue;
        };
        jobs += 1;
        // System crontabs (`/etc/crontab`, `cron.d`) name the user before the command.
        let mut cmd = rest;
        if rest.len() >= 2 && is_user_name(rest[0]) && looks_like_command(rest[1]) {
            system += 1;
            cmd = &rest[1..];
        }
        if let Some(c) = cmd.first() {
            let base = c.rsplit('/').next().unwrap_or(c);
            bump(&mut commands, &truncate_chars(base, 100));
        }
    }
    cx.format_set("jobs", jobs);
    if system > 0 && system * 2 >= jobs {
        cx.format_set("system_crontab", true);
    }
    set_hist(cx, "special_schedules", &specials);
    if every_minute > 0 {
        cx.format_set("every_minute_jobs", every_minute);
    }
    set_hist(cx, "commands", &commands);
    set_list(cx, "variables", variables);
}

fn is_user_name(w: &str) -> bool {
    matches!(w, "root" | "nobody" | "www-data" | "daemon")
        || (w.len() <= 32
            && w.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            && w.chars().next().is_some_and(|c| c.is_ascii_lowercase()))
}

fn looks_like_command(w: &str) -> bool {
    w.starts_with('/') || w.starts_with("test") || w.starts_with('[') || w.contains('/') || w == "cd"
}

// --- SSH -------------------------------------------------------------------

/// `sshd_config` settings worth reporting as they are.
const SSHD_KEYS: [&str; 12] = [
    "port",
    "permitrootlogin",
    "passwordauthentication",
    "pubkeyauthentication",
    "permitemptypasswords",
    "kbdinteractiveauthentication",
    "challengeresponseauthentication",
    "x11forwarding",
    "allowtcpforwarding",
    "usepam",
    "protocol",
    "subsystem",
];

fn ssh_config(text: &str, name: &str, cx: &mut Context<'_>) {
    let server = name.rsplit(['/', '\\']).next().unwrap_or(name).starts_with("sshd");
    let (mut hosts, mut matches, mut identity_files) = (Vec::new(), 0u64, Vec::new());
    let mut options: BTreeMap<String, u64> = BTreeMap::new();
    let mut settings = Map::new();
    let (mut forward_agent, mut no_host_check, mut proxies) = (0u64, 0u64, 0u64);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (k, v) = t.split_once([' ', '\t', '=']).unwrap_or((t, ""));
        let (k, v) = (k.to_ascii_lowercase(), v.trim().trim_start_matches('=').trim());
        bump(&mut options, &k);
        match k.as_str() {
            "host" => hosts.extend(v.split_whitespace().map(str::to_string)),
            "match" => matches += 1,
            "identityfile" => identity_files.push(user_path(cx, v)),
            "forwardagent" if v.eq_ignore_ascii_case("yes") => forward_agent += 1,
            "stricthostkeychecking" if v.eq_ignore_ascii_case("no") => no_host_check += 1,
            "proxyjump" | "proxycommand" => proxies += 1,
            _ if server && SSHD_KEYS.contains(&k.as_str()) => {
                settings.entry(k).or_insert_with(|| json!(truncate_chars(v, 100)));
            }
            _ => {}
        }
    }
    cx.format_set("role", if server { "server" } else { "client" });
    if !server {
        cx.format_set("host_blocks", hosts.len());
        if !cx.privacy_strict() {
            set_list(cx, "hosts", hosts);
        }
    }
    if matches > 0 {
        cx.format_set("match_blocks", matches);
    }
    set_hist(cx, "options", &options);
    if !identity_files.is_empty() {
        set_list(cx, "identity_files", identity_files);
    }
    for (k, v) in
        [("forward_agent", forward_agent), ("strict_host_key_checking_off", no_host_check), ("proxies", proxies)]
    {
        if v > 0 {
            cx.format_set(k, v);
        }
    }
    if !settings.is_empty() {
        cx.format_set("settings", Value::Object(settings));
    }
}

// --- nginx and Apache ------------------------------------------------------

fn web_server(text: &str, name: &str, cx: &mut Context<'_>) {
    let apache = name.ends_with("htaccess")
        || text.lines().any(|l| {
            let t = l.trim_start();
            t.starts_with("<VirtualHost")
                || t.starts_with("<Directory")
                || t.starts_with("LoadModule ")
                || t.starts_with("RewriteEngine")
                || t.starts_with("ServerRoot")
        });
    if apache { apache_config(text, name, cx) } else { nginx(text, cx) }
}

fn nginx(text: &str, cx: &mut Context<'_>) {
    let mut directives: BTreeMap<String, u64> = BTreeMap::new();
    let (mut servers, mut locations, mut upstreams) = (0u64, 0u64, Vec::new());
    let (mut names, mut listens, mut includes) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
    let (mut tls, mut proxies) = (false, 0u64);
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        for stmt in t.split_inclusive([';', '{', '}']) {
            let s = stmt.trim().trim_end_matches([';', '{']).trim();
            let mut words = s.split_whitespace();
            let Some(d) = words.next().filter(|w| *w != "}") else { continue };
            bump(&mut directives, d);
            let args: Vec<&str> = words.collect();
            match d {
                "server" if stmt.ends_with('{') => servers += 1,
                "location" => locations += 1,
                "upstream" => upstreams.extend(args.first().map(|s| (*s).to_string())),
                "server_name" => names.extend(args.iter().filter(|a| **a != "_").map(|a| (*a).to_string())),
                "listen" => {
                    tls |= args.contains(&"ssl") || args.contains(&"quic");
                    if let Some(a) = args.first() {
                        listens.insert(a.rsplit(':').next().unwrap_or(a).to_string());
                    }
                }
                "ssl_certificate" => tls = true,
                "proxy_pass" | "fastcgi_pass" | "uwsgi_pass" | "grpc_pass" => proxies += 1,
                "include" => includes.extend(args.first().map(|s| truncate_chars(s, 300))),
                _ => {}
            }
        }
    }
    cx.format_set("server", "nginx");
    cx.format_set("server_blocks", servers);
    cx.format_set("locations", locations);
    set_list(cx, "server_names", names);
    set_list(cx, "listen", listens);
    cx.format_set("tls", tls);
    if proxies > 0 {
        cx.format_set("proxies", proxies);
    }
    set_list(cx, "upstreams", upstreams);
    set_list(cx, "includes", includes);
    set_hist(cx, "directives", &directives);
}

fn apache_config(text: &str, name: &str, cx: &mut Context<'_>) {
    let mut directives: BTreeMap<String, u64> = BTreeMap::new();
    let (mut vhosts, mut sections) = (0u64, BTreeMap::new());
    let (mut names, mut listens, mut modules, mut includes) =
        (BTreeSet::new(), BTreeSet::new(), Vec::new(), Vec::new());
    let (mut rewrites, mut redirects, mut tls, mut auth) = (0u64, 0u64, false, None);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(sec) = t.strip_prefix('<').filter(|s| !s.starts_with('/')) {
            let kind = sec.split([' ', '>']).next().unwrap_or("");
            bump(&mut sections, kind);
            vhosts += u64::from(kind.eq_ignore_ascii_case("VirtualHost"));
            continue;
        }
        if t.starts_with("</") {
            continue;
        }
        let mut words = t.split_whitespace();
        let Some(d) = words.next() else { continue };
        bump(&mut directives, d);
        let args: Vec<&str> = words.collect();
        match d.to_ascii_lowercase().as_str() {
            "servername" | "serveralias" => names.extend(args.iter().map(|a| (*a).to_string())),
            "listen" => listens.extend(args.first().map(|a| a.rsplit(':').next().unwrap_or(a).to_string())),
            "loadmodule" => modules.extend(args.first().map(|a| (*a).to_string())),
            "include" | "includeoptional" => includes.extend(args.first().map(|a| truncate_chars(a, 300))),
            "rewriterule" => rewrites += 1,
            "redirect" | "redirectmatch" | "redirectpermanent" => redirects += 1,
            "sslengine" | "sslcertificatefile" => tls = true,
            "authtype" => auth = args.first().map(|a| (*a).to_string()),
            _ => {}
        }
    }
    cx.format_set("server", "apache");
    if name.ends_with("htaccess") {
        cx.format_set("kind", "htaccess");
    }
    if vhosts > 0 {
        cx.format_set("virtual_hosts", vhosts);
    }
    set_hist(cx, "sections", &sections);
    set_list(cx, "server_names", names);
    set_list(cx, "listen", listens);
    set_list(cx, "modules", modules);
    set_list(cx, "includes", includes);
    for (k, v) in [("rewrite_rules", rewrites), ("redirects", redirects)] {
        if v > 0 {
            cx.format_set(k, v);
        }
    }
    cx.format_set("tls", tls);
    if let Some(a) = auth {
        cx.format_set("auth_type", a);
    }
    set_hist(cx, "directives", &directives);
}

// --- Procfile, Justfile, Vagrantfile ---------------------------------------

fn procfile(text: &str, cx: &mut Context<'_>) {
    let mut processes = Map::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some((name, cmd)) = t.split_once(':')
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            && processes.len() < 50
        {
            let program = cmd.split_whitespace().find(|w| !w.contains('=')).unwrap_or("");
            processes
                .insert(name.to_string(), json!(truncate_chars(program.rsplit('/').next().unwrap_or(program), 100)));
        }
    }
    cx.format_set("process_count", processes.len());
    cx.format_set("processes", Value::Object(processes));
}

fn justfile(text: &str, cx: &mut Context<'_>) {
    static RECIPE: LazyLock<Regex> = LazyLock::new(|| regex(r"^@?([A-Za-z_][\w-]*)(?:\s+[^:=]*)?:(?:[^=]|$)"));
    static ASSIGN: LazyLock<Regex> = LazyLock::new(|| regex(r"^(?:export\s+)?([A-Za-z_][\w-]*)\s*:="));
    let (mut recipes, mut variables, mut settings, mut imports) = (Vec::new(), Vec::new(), Map::new(), Vec::new());
    let mut default = None;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) || line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let t = line.trim_end();
        if let Some(rest) = t.strip_prefix("set ") {
            let (k, v) = rest.split_once(":=").unwrap_or((rest, "true"));
            settings.insert(k.trim().to_string(), json!(truncate_chars(v.trim(), 200)));
        } else if let Some(rest) = t.strip_prefix("import").or_else(|| t.strip_prefix("mod")) {
            imports.push(truncate_chars(rest.trim().trim_start_matches('?').trim().trim_matches(['\'', '"']), 300));
        } else if let Some(c) = ASSIGN.captures(t) {
            variables.push(c[1].to_string());
        } else if let Some(c) = RECIPE.captures(t)
            && !t.starts_with('[')
        {
            default.get_or_insert_with(|| c[1].to_string());
            if recipes.len() < 200 {
                recipes.push(c[1].to_string());
            }
        }
    }
    if let Some(d) = default {
        cx.format_set("default_recipe", d);
    }
    cx.format_set("recipe_count", recipes.len());
    set_list(cx, "recipes", recipes);
    set_list(cx, "variables", variables);
    if !settings.is_empty() {
        cx.format_set("settings", Value::Object(settings));
    }
    set_list(cx, "imports", imports);
}

fn vagrantfile(text: &str, cx: &mut Context<'_>) {
    static BOX: LazyLock<Regex> = LazyLock::new(|| regex(r#"\.vm\.box\s*=\s*["']([^"']+)"#));
    static PROVIDER: LazyLock<Regex> = LazyLock::new(|| regex(r#"\.vm\.provider\s*\(?\s*[:"']([\w-]+)"#));
    static PROVISION: LazyLock<Regex> = LazyLock::new(|| regex(r#"\.vm\.provision\s*\(?\s*[:"']([\w-]+)"#));
    static DEFINE: LazyLock<Regex> = LazyLock::new(|| regex(r#"\.vm\.define\s*\(?\s*[:"']([\w.-]+)"#));
    static API: LazyLock<Regex> = LazyLock::new(|| regex(r#"Vagrant\.configure\(\s*["']?(\d)"#));
    let collect = |re: &Regex| -> BTreeSet<String> { re.captures_iter(text).map(|c| c[1].to_string()).collect() };
    if let Some(c) = API.captures(text) {
        cx.format_set("config_version", c[1].to_string());
    }
    set_list(cx, "boxes", collect(&BOX));
    set_list(cx, "machines", collect(&DEFINE));
    set_list(cx, "providers", collect(&PROVIDER));
    set_list(cx, "provisioners", collect(&PROVISION));
    let forwarded = text.matches("forwarded_port").count();
    if forwarded > 0 {
        cx.format_set("forwarded_ports", forwarded);
    }
    let synced = text.matches("synced_folder").count();
    if synced > 0 {
        cx.format_set("synced_folders", synced);
    }
}

// --- Caddyfile, HAProxy ----------------------------------------------------

fn caddyfile(text: &str, cx: &mut Context<'_>) {
    let mut depth = 0usize;
    let (mut sites, mut directives, mut global) = (Vec::new(), BTreeMap::new(), false);
    for line in text.lines() {
        let t = line.split(" #").next().unwrap_or(line).trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if depth == 0 {
            if t == "{" {
                global = true;
            } else if let Some(addr) = t.strip_suffix('{') {
                sites.extend(addr.split([',', ' ']).filter(|a| !a.is_empty()).map(|a| truncate_chars(a, 200)));
            } else if !t.starts_with('}') && !t.starts_with('(') && !t.starts_with("import") {
                sites.extend(t.split([',', ' ']).filter(|a| !a.is_empty()).take(1).map(|a| truncate_chars(a, 200)));
            }
        } else if depth == 1
            && let Some(d) = t.split_whitespace().next().filter(|d| *d != "}")
        {
            bump(&mut directives, d);
        }
        depth = (depth + t.matches('{').count()).saturating_sub(t.matches('}').count());
    }
    cx.format_set("global_options", global);
    cx.format_set("site_count", sites.len());
    set_list(cx, "sites", sites);
    set_hist(cx, "directives", &directives);
}

fn haproxy(text: &str, cx: &mut Context<'_>) {
    let mut sections: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let (mut binds, mut servers, mut modes, mut tls) = (BTreeSet::new(), 0u64, BTreeSet::new(), false);
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim_end();
        if t.trim().is_empty() {
            continue;
        }
        let mut words = t.split_whitespace();
        let Some(first) = words.next() else { continue };
        if !line.starts_with([' ', '\t'])
            && matches!(
                first,
                "global" | "defaults" | "frontend" | "backend" | "listen" | "resolvers" | "peers" | "userlist"
            )
        {
            let names = sections.entry(first.to_string()).or_default();
            if let Some(n) = words.next()
                && names.len() < 100
            {
                names.push(n.to_string());
            }
            continue;
        }
        match first {
            "bind" => {
                if let Some(a) = words.next() {
                    binds.insert(a.rsplit(':').next().unwrap_or(a).to_string());
                }
                tls |= t.contains(" ssl ");
            }
            "server" => servers += 1,
            "mode" => modes.extend(words.next().map(str::to_string)),
            _ => {}
        }
    }
    let counts: Map<String, Value> = sections.iter().map(|(k, v)| (k.clone(), json!(v.len().max(1)))).collect();
    cx.format_set("sections", Value::Object(counts));
    for kind in ["frontend", "backend", "listen"] {
        if let Some(n) = sections.get(kind).filter(|n| !n.is_empty()) {
            cx.format_set(&format!("{kind}s"), json!(n));
        }
    }
    set_list(cx, "bind_ports", binds);
    cx.format_set("servers", servers);
    set_list(cx, "modes", modes);
    cx.format_set("tls", tls);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(by_name("/home/x/.ssh/config"), Some("ssh_config"));
        assert_eq!(by_name("config"), None);
        assert_eq!(by_name(".dockerignore"), Some("ignore_file"));
        assert_eq!(by_name("Procfile"), Some("procfile"));
        assert_eq!(by_name(".ignore"), None);
    }

    #[test]
    fn hcl_strips_comments_and_heredocs() {
        let l = hcl_lines("a = \"x { y\" # c\nb = <<EOT\n{\nEOT\nc {\n}\n");
        let depths: Vec<_> = l.iter().map(|l| l.depth).collect();
        assert_eq!(depths, [0, 0, 0, 1]);
        assert_eq!(l[0].code.trim(), "a = \"x { y\"");
    }

    crate::fixture_tests!(
        "terraform",
        "ignore_file",
        "crontab",
        "ssh_config",
        "web_server_config",
        "procfile",
        "justfile",
        "vagrantfile",
        "caddyfile",
        "haproxy_config"
    );
}
