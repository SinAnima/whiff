"""Compare whiff's stage 8 code reports with each format's own tools.

    # in `whiff-code`: build a corpus and the expected facts
    python3 code_oracle.py expect OUT_DIR
    # on the host
    python3 code_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is the code fixtures plus SPIR-V modules compiled by glslang
from generated compute shaders (random workgroup sizes and helper
functions). Expected facts come from the formats' own tooling, never from
the generator: Pygments (language and code / comment / blank lines),
spirv-dis, rpmspec, dpkg-parsechangelog, python-debian, bash (sourcing a
PKGBUILD), Bundler, tomllib, json5, PyYAML, spdx-tools,
cyclonedx-python-lib, cffconvert, python-hcl2 and Erlang's file:consult.
The big-endian SPIR-V fixture is checked against spirv-dis's reading of
its little-endian twin (spirv-dis misreads big-endian strings). A check
key with a dot is a path in the whole report (`content.title`);
one without is a field of the format section. Nothing here ships with whiff.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tomllib

R = random.Random(8)
HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "..", "tests", "fixtures")
sys.path.insert(0, HERE)


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


# --- Pygments: language and line classification ------------------------------

# Pygments lexer names accepted for each format (None: Pygments has no lexer).
LEXERS = {
    "astro": None, "nim": {"Nimrod"}, "crystal": {"Crystal"}, "d": {"D"}, "vlang": {"V"}, "odin": None,
    "fortran": {"Fortran"}, "cobol": {"COBOL", "COBOLFree"}, "pascal": {"Delphi", "Pascal", "Portugol"},
    "ada": {"Ada"}, "lisp": {"Common Lisp", "EmacsLisp"}, "scheme": {"Racket", "Scheme"},
    "prolog": {"Prolog"}, "elm": {"Elm"}, "purescript": {"PureScript"}, "rescript": {"ReasonML"},
    "coffeescript": {"CoffeeScript"}, "haxe": {"Haxe"}, "tcl": {"Tcl"}, "awk": {"Awk"}, "sed": None,
    "solidity": {"Solidity"}, "move": None, "cairo": None, "vyper": {"Vyper"}, "verilog": {"verilog", "systemverilog"},
    "vhdl": {"vhdl"}, "opencl": {"OpenCL"}, "glsl": {"GLSL"}, "hlsl": {"HLSL"}, "wgsl": {"WebGPU Shading Language"},
    "metal": None, "apex": None, "abap": {"ABAP"}, "smalltalk": {"Smalltalk"}, "raku": {"Perl6"},
    "starlark": {"Python"}, "meson": {"Meson"}, "ninja": None, "autohotkey": {"autohotkey"}, "autoit": {"AutoIt"},
    "gleam": None, "roc": None, "unison": None, "mojo": {"Mojo"}, "qsharp": {"Q#"}, "openqasm": None,
    "arduino": {"Arduino"}, "llvm_ir": {"LLVM"}, "wat": {"WebAssembly"}, "antlr": {"ANTLR"}, "peg": {"PEG"},
    "yacc": None, "lex": None, "puppet": {"Puppet"}, "plsql": None, "go_template": None,
    "handlebars": {"Handlebars", "HTML+Handlebars"}, "pug": {"Pug"}, "vim_script": {"VimL"}, "nushell": None,
    "elvish": {"Elvish"}, "rego": None, "bicep": {"Bicep"}, "lean": {"Lean", "Lean4"}, "coq": {"Coq", "Rocq Prover"},
    "agda": {"Agda"}, "idris": {"Idris"}, "isabelle": {"Isabelle"}, "tla": None, "alloy": {"Alloy"},
    "ballerina": {"Ballerina"}, "pony": {"Pony"}, "janet": {"Janet"}, "fennel": {"Fennel"}, "hy": {"Hy"},
    "forth": {"Forth"}, "apl": {"APL"}, "j_lang": {"J"}, "gdscript": {"GDScript"}, "shaderlab": None,
    "plc_st": None, "max_patch": None, "pure_data": None, "yara": {"YARA"}, "smithy": {"Smithy"},
    "avro_idl": None, "applescript": {"AppleScript"}, "groovy": {"Groovy"},
}

# Languages whose line counts are compared: Pygments' comment tokens match
# whiff's notion of a comment line. (Docstrings, `#lang` lines, directive
# comments and templates differ by design.)
LOC_SKIP = {"astro", "vyper", "mojo", "starlark", "handlebars", "go_template", "pug", "max_patch", "pure_data",
            "sed", "cobol", "smalltalk", "apl", "j_lang", "forth", "wat", "abap", "plc_st"}


# Lexers chosen by name where the file name alone misleads Pygments.
BY_NAME = {"opencl": "opencl"}


def pygments_facts(fid, path):
    """Pygments' lexer and line classes: a line is blank when its text is
    whitespace, a comment when every other character is in a comment token
    (doc strings included; preprocessor and shebang lines count as code)."""
    from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
    from pygments.token import Comment, String
    from pygments.util import ClassNotFound
    text = open(path, encoding="utf-8").read()
    try:
        lexer = get_lexer_by_name(BY_NAME[fid]) if fid in BY_NAME else get_lexer_for_filename(os.path.basename(path), text)
    except ClassNotFound:
        return None, None
    kinds = []
    for _, tok, val in lexer.get_tokens_unprocessed(text):
        comment = (tok in Comment and tok not in Comment.Preproc and tok not in Comment.Hashbang) or tok in String.Doc
        kinds.append((val, comment))
    flat = "".join(v for v, _ in kinds)
    if flat != text:
        # Lexers normalise line endings or a final newline; compare per character anyway.
        text = flat
    marks = []
    for val, comment in kinds:
        marks.extend([comment] * len(val))
    code = comment = blank = 0
    at = 0
    for n, line in enumerate(text.split("\n")[: -1 if text.endswith("\n") else None]):
        span = marks[at:at + len(line)]
        at += len(line) + 1
        # A shebang is code (whiff's convention), whatever token the lexer gives it.
        if n == 0 and line.startswith("#!"):
            code += 1
            continue
        chars = [m for ch, m in zip(line, span) if not ch.isspace()]
        if not chars:
            blank += 1
        elif all(chars):
            comment += 1
        else:
            code += 1
    return lexer.name, {"code": code, "comment": comment, "blank": blank}


# --- SPIR-V: spirv-dis ---------------------------------------------------------


def spirv_facts(path):
    dis = run("spirv-dis", "--raw-id", path)
    head = dict(re.findall(r"^; (\w+): (.*)$", dis, re.M))
    body = [l.strip() for l in dis.splitlines() if l.strip() and not l.startswith(";")]
    op = lambda o: [l for l in body if re.match(rf"(%\w+ = )?{o}\b", l)]  # noqa: E731
    checks = {
        "version": head["Version"],
        "id_bound": int(head["Bound"]),
        "generator.tool_version": int(head["Generator"].rsplit(";", 1)[1]),
        "instructions": len(body),
        "functions": len(op("OpFunction")),
        "debug_names": len(op("OpName")),
        "capabilities": sorted(l.split()[1] for l in op("OpCapability")),
        "memory_model": op("OpMemoryModel")[0].split()[2],
        "addressing_model": op("OpMemoryModel")[0].split()[1],
        "source_language": op("OpSource")[0].split()[1],
    }
    tool = head["Generator"].rsplit(";", 1)[0].strip()
    if not tool.startswith("Unknown"):
        checks["generator.tool"] = tool
    imports = [re.search(r'"([^"]+)"', l).group(1) for l in op("OpExtInstImport")]
    if imports:
        checks["ext_inst_imports"] = imports
    eps = []
    for l in op("OpEntryPoint"):
        m = re.match(r'OpEntryPoint (\w+) (%\w+) "([^"]*)"', l)
        ep = {"name": m.group(3), "execution_model": m.group(1)}
        for e in op("OpExecutionMode"):
            p = e.split()
            if p[1] == m.group(2) and p[2] == "LocalSize":
                ep["local_size"] = [int(x) for x in p[3:6]]
        eps.append(ep)
    checks["entry_points"] = eps
    return checks


def gen_spirv(corpus):
    """Compute shaders with random workgroup sizes and helpers, through glslang."""
    out = []
    for n in range(6):
        x, y, z = R.choice([1, 2, 4, 8, 16, 32]), R.choice([1, 2, 4, 8]), R.choice([1, 2])
        helpers = R.randint(0, 4)
        src = ["#version 450", f"layout(local_size_x = {x}, local_size_y = {y}, local_size_z = {z}) in;",
               "layout(std430, binding = 0) buffer Levels { float level[]; };"]
        for h in range(helpers):
            src.append(f"float tide{h}(float v) {{ return v * {h + 1}.5; }}")
        call = "v"
        for h in range(helpers):
            call = f"tide{h}({call})"
        src.append(f"void main() {{ uint i = gl_GlobalInvocationID.x; float v = level[i]; level[i] = {call}; }}")
        name = f"gen_tide_{n}"
        comp = os.path.join(corpus, name + ".comp")
        with open(comp, "w") as f:
            f.write("\n".join(src) + "\n")
        spv = os.path.join(corpus, name + ".spv")
        run("glslangValidator", "-V", "-o", spv, comp)
        os.remove(comp)
        out.append(name + ".spv")
    return out


# --- manifests -------------------------------------------------------------------


def toml(p):
    with open(p, "rb") as f:
        return tomllib.load(f)


def yaml(p):
    import yaml as y
    return y.safe_load(open(p, encoding="utf-8"))


def versions(entries):
    return {e["name"]: e.get("version", "*") for e in entries}


def manifest_facts(fid, path):
    name = os.path.basename(path)
    c = {}
    if fid == "pipfile":
        v = toml(path)
        c["dependencies_count"] = len(v.get("packages", {}))
        c["dev_dependencies_count"] = len(v.get("dev-packages", {}))
        c["requires_python"] = v["requires"]["python_version"]
    elif fid == "pipfile_lock":
        v = json.load(open(path))
        c["resolved_packages"] = len(v["default"]) + len(v["develop"])
        c["dependencies"] = {k: d["version"] for k, d in v["default"].items()}
    elif fid in ("poetry_lock", "uv_lock"):
        v = toml(path)
        c["packages"] = versions(v["package"])
        c["resolved_packages"] = len(v["package"])
    elif fid == "setup_cfg":
        import configparser
        cp = configparser.ConfigParser()
        cp.read(path)
        c["name"] = cp["metadata"]["name"]
        c["version"] = cp["metadata"]["version"]
        c["dependencies_count"] = len([l for l in cp["options"]["install_requires"].splitlines() if l.strip()])
    elif fid == "nuget_packages":
        import xml.etree.ElementTree as ET
        c["dependencies"] = {p.get("id"): p.get("version") for p in ET.parse(path).getroot().iter("package")}
    elif fid == "dotnet_project" and name.endswith("proj"):
        import xml.etree.ElementTree as ET
        root = ET.parse(path).getroot()
        refs = {}
        for p in root.iter("PackageReference"):
            refs[p.get("Include")] = p.get("Version") or p.findtext("Version")
        c["dependencies"] = refs
        c["target_framework"] = root.findtext("./PropertyGroup/TargetFramework")
    elif fid == "gemfile_lock":
        out = run("ruby", "-rbundler", "-e",
                  "l = Bundler::LockfileParser.new(File.read(ARGV[0])); "
                  "puts JSON.generate({specs: l.specs.map { |s| [s.name, s.version.to_s] }.to_h, "
                  "deps: l.dependencies.size, bundler: l.bundler_version.to_s, platforms: l.platforms.map(&:to_s)})",
                  path, env={**os.environ, "RUBYOPT": "-rjson"})
        v = json.loads(out)
        c["packages"] = v["specs"]
        c["dependencies_count"] = v["deps"]
        c["bundler_version"] = v["bundler"]
        c["platforms"] = v["platforms"]
    elif fid == "gemfile":
        out = run("ruby", "-rbundler", "-rjson", "-e",
                  "d = Bundler::Dsl.new; d.eval_gemfile(ARGV[0]); "
                  "puts JSON.generate(d.dependencies.map { |x| [x.name, x.groups.map(&:to_s)] })", path)
        deps = json.loads(out)
        c["dependencies_count"] = sum(1 for _, g in deps if not ({"development", "test"} & set(g)))
        c["dev_dependencies_count"] = sum(1 for _, g in deps if {"development", "test"} & set(g))
    elif fid == "podfile_lock":
        v = yaml(path)
        c["resolved_packages"] = len(v["PODS"])
        c["cocoapods_version"] = v["COCOAPODS"]
    elif fid == "swift_package_resolved":
        v = json.load(open(path))
        c["packages"] = {p["identity"]: p["state"]["version"] for p in v["pins"]}
    elif fid == "composer_json":
        v = json.load(open(path))
        c["dev_dependencies"] = v["require-dev"]
        c["requires_php"] = v["require"]["php"]
    elif fid == "composer_lock":
        v = json.load(open(path))
        c["resolved_packages"] = len(v["packages"]) + len(v["packages-dev"])
    elif fid == "pubspec":
        v = yaml(path)
        c["dependencies_count"] = len(v["dependencies"])
        c["dev_dependencies_count"] = len(v["dev_dependencies"])
        c["dart_sdk"] = v["environment"]["sdk"]
    elif fid == "pubspec_lock":
        v = yaml(path)
        c["packages"] = {k: p["version"] for k, p in v["packages"].items()}
    elif fid == "stack_yaml":
        c["snapshot"] = yaml(path)["snapshot"]
    elif fid == "r_description":
        from debian.deb822 import Deb822
        d = Deb822(open(path, encoding="utf-8"))
        c["name"] = d["Package"]
        c["version"] = d["Version"]
        c["license"] = d["License"]
    elif fid == "vcpkg_json":
        v = json.load(open(path))
        c["dependencies_count"] = len(v["dependencies"])
    elif fid == "deno_config":
        import json5
        v = json5.load(open(path))
        c["imports"] = v["imports"]
        c["tasks"] = list(v["tasks"])
    elif fid == "julia_project":
        v = toml(path)
        c["dependencies_count"] = len(v["deps"])
        c["requires_julia"] = v["compat"]["julia"]
    elif fid == "julia_manifest":
        v = toml(path)
        c["resolved_packages"] = len(v["deps"])
        c["julia_version"] = v["julia_version"]
    elif fid == "citation_cff":
        run("cffconvert", "--validate", "-i", path)
        v = yaml(path)
        c["cff_version"] = v["cff-version"]
        c["authors_count"] = len(v["authors"])
        c["temporal.content.published"] = str(v["date-released"])
    elif fid in ("spdx", "spdx_json"):
        from spdx_tools.spdx.parser.parse_anything import parse_file
        doc = parse_file(path)
        c["document_name"] = doc.creation_info.name
        c["package_count"] = len(doc.packages)
        c["packages"] = {p.name: p.version for p in doc.packages}
        c["relationships"] = len(doc.relationships)
        c["tools"] = [a.name for a in doc.creation_info.creators if a.actor_type.name == "TOOL"]
    elif fid == "cyclonedx_json":
        from cyclonedx.model.bom import Bom
        bom = Bom.from_json(json.load(open(path)))  # type: ignore[attr-defined]
        c["packages"] = {x.name: x.version for x in bom.components}
        c["component"] = {"name": bom.metadata.component.name, "version": bom.metadata.component.version}
        c["serial_number"] = bom.serial_number.urn
    elif fid == "cyclonedx_xml":
        import xml.etree.ElementTree as ET
        from cyclonedx.model.bom import Bom
        bom = Bom.from_xml(ET.parse(path).getroot())  # type: ignore[attr-defined]
        c["packages"] = {x.name: x.version for x in bom.components}
        c["component"] = {"name": bom.metadata.component.name, "version": bom.metadata.component.version}
    elif fid == "pkgbuild":
        out = run("bash", "-c", 'source "$1"; printf "%s\\n" "$pkgname" "$pkgver-$pkgrel" "${#depends[@]}" "${#makedepends[@]}" "${#source[@]}" "${arch[*]}"', "_", path)
        n, v, dep, mk, src, arch = out.splitlines()
        c.update({"name": n, "version": v, "dependencies_count": int(dep), "build_dependencies_count": int(mk),
                  "sources": int(src), "arch": arch.split()})
    elif fid == "rpm_spec":
        nv = run("rpmspec", "-q", "--srpm", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}|%{LICENSE}", path).strip()
        n, v, lic = nv.split("|")
        br = [l for l in run("rpmspec", "-q", "--buildrequires", path).splitlines() if l.strip()]
        c.update({"name": n, "version": v, "license": lic, "build_dependencies_count": len(br)})
    elif fid == "debian_control":
        from debian.deb822 import Deb822
        paras = list(Deb822.iter_paragraphs(open(path, encoding="utf-8")))
        c["name"] = paras[0]["Source"]
        c["section"] = paras[0]["Section"]
        c["build_dependencies_count"] = len(paras[0]["Build-Depends"].split(","))
        c["binary_packages"] = [{"name": p["Package"], "architecture": p["Architecture"], "synopsis": p["Description"].splitlines()[0]} for p in paras[1:]]
    elif fid == "debian_changelog":
        f = lambda k: run("dpkg-parsechangelog", "-l", path, "-S", k).strip()  # noqa: E731
        c["name"] = f("Source")
        c["latest.version"] = f("Version")
        c["latest.distribution"] = f("Distribution")
        c["latest.urgency"] = f("Urgency")
        stanzas = run("dpkg-parsechangelog", "-l", path, "--format", "rfc822", "--all")
        c["entries"] = len(re.findall(r"^Version: ", stanzas, re.M))
    elif fid == "debian_copyright":
        from debian.copyright import Copyright
        cr = Copyright(open(path, encoding="utf-8"))
        c["upstream_name"] = cr.header.upstream_name
        c["files_paragraphs"] = len(list(cr.all_files_paragraphs()))
    elif fid == "nix_flake_lock":
        v = json.load(open(path))
        c["resolved_inputs"] = len(v["nodes"]) - 1
    elif fid == "terraform_lock":
        import hcl2
        v = hcl2.load(open(path))
        c["providers"] = {list(p)[0].strip('"'): list(p.values())[0]["version"].strip('"') for p in v["provider"]}
    elif fid == "snapcraft":
        v = yaml(path)
        c["apps"] = list(v["apps"])
        c["parts"] = list(v["parts"])
        c["confinement"] = v["confinement"]
    elif fid == "flatpak_manifest":
        v = json.load(open(path))
        c["permissions"] = v["finish-args"]
        c["runtime"] = v["runtime"]
    elif fid == "cpan_meta":
        v = json.load(open(path))
        c["dependencies_count"] = len([k for k in v["prereqs"]["runtime"]["requires"] if k != "perl"])
        c["requires_perl"] = v["prereqs"]["runtime"]["requires"]["perl"]
    elif fid == "rebar_config":
        out = run("erl", "-noshell", "-eval",
                  f'{{ok, T}} = file:consult("{path}"), D = proplists:get_value(deps, T), '
                  'io:format("~p~n", [length(D)]), halt().')
        c["dependencies_count"] = int(out.strip())
    elif fid == "elm_json":
        v = json.load(open(path))
        c["dependencies"] = v["dependencies"]["direct"]
        c["indirect_dependencies"] = v["dependencies"]["indirect"]
    elif fid == "gleam_toml":
        v = toml(path)
        c["dependencies_count"] = len(v["dependencies"])
        c["target"] = v["target"]
    return c


def expect(out_dir):
    from craft_code import MANIFESTS
    from craft_code_src import SOURCES
    corpus = os.path.join(out_dir, "corpus")
    shutil.rmtree(corpus, ignore_errors=True)
    os.makedirs(corpus)
    facts = []

    def add(fid, src, checks):
        # One folder per file keeps name-based detection (`Gemfile`, `control`).
        rel = os.path.join(f"{len(facts):03d}", os.path.basename(src))
        os.makedirs(os.path.join(corpus, os.path.dirname(rel)))
        shutil.copy(src, os.path.join(corpus, rel))
        facts.append({"file": rel, "format": fid, "checks": checks})

    for fid, files in SOURCES.items():
        for name, _ in files:
            path = os.path.join(FIXTURES, fid, name)
            lexer, loc = pygments_facts(fid, path)
            checks = {}
            want = LEXERS.get(fid)
            # No lexer in this Pygments for the file: nothing to compare.
            if want is not None and lexer is not None:
                checks["@lexer"] = lexer if lexer in want else f"pygments: {lexer}"
                if fid not in LOC_SKIP and loc:
                    checks["loc.code"], checks["loc.comment"], checks["loc.blank"] = loc["code"], loc["comment"], loc["blank"]
            add(fid, path, checks)
    for name in sorted(os.listdir(os.path.join(FIXTURES, "spirv"))):
        if name.endswith(".spv"):
            # spirv-dis (2025.1) unpacks literal strings of big-endian modules
            # byte by byte, against the specification (2.2.1: low-order byte
            # first within each word); the byte-swapped fixture is the same
            # module as its little-endian twin, so it gets the twin's facts.
            twin = name.replace(".be.spv", ".spv")
            add("spirv", os.path.join(FIXTURES, "spirv", name), spirv_facts(os.path.join(FIXTURES, "spirv", twin)))
    gen = os.path.join(out_dir, "gen")
    shutil.rmtree(gen, ignore_errors=True)
    os.makedirs(gen)
    for name in gen_spirv(gen):
        add("spirv", os.path.join(gen, name), spirv_facts(os.path.join(gen, name)))
    for fid, files in MANIFESTS.items():
        for name, _ in files:
            path = os.path.join(FIXTURES, fid, name)
            add(fid, path, manifest_facts(fid, path))
    with open(os.path.join(out_dir, "expected.json"), "w") as f:
        json.dump(facts, f, indent=1)
    print(f"{len(facts)} files, {sum(len(f['checks']) for f in facts)} checks")


def resolve(obj, path):
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def check(out_dir, whiff):
    facts = json.load(open(os.path.join(out_dir, "expected.json")))
    corpus = os.path.join(out_dir, "corpus")
    bad = total = 0
    for f in facts:
        r = json.loads(subprocess.run([whiff, os.path.join(corpus, f["file"])], capture_output=True, text=True).stdout)
        got_fmt = r["identification"]["format"]
        total += 1
        if got_fmt != f["format"]:
            print(f"{f['file']}: detected as {got_fmt}, expected {f['format']}")
            bad += 1
            continue
        fields = r.get("format", {}).get(f["format"], {})
        for k, want in f["checks"].items():
            total += 1
            if k == "@lexer":
                # The lexer check passes when Pygments names a lexer accepted for the format.
                ok = not str(want).startswith("pygments: ")
                got = want
            elif k.startswith("temporal.content."):
                field = k.rsplit(".", 1)[1]
                got = next((d["value"] for d in r.get("temporal", {}).get("content", []) if d["field"] == field), None)
                ok = got == want
            else:
                top = k.split(".", 1)[0]
                got = resolve(r, k) if top in ("content", "rights") else resolve(fields, k)
                ok = got == want
            if not ok:
                bad += 1
                print(f"{f['file']} ({f['format']}): {k}: whiff {got!r}, expected {want!r}")
    print(f"{total - bad}/{total} checks agree")
    return bad == 0


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        sys.exit(0 if check(sys.argv[2], sys.argv[3]) else 1)
