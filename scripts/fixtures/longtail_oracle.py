"""Compare whiff's long-tail reports with each format's own tools.

    # in `whiff-longtail`: build a corpus and the expected facts
    python3 longtail_oracle.py expect OUT_DIR
    # on the host
    python3 longtail_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is the long-tail fixtures plus generated documents: markup
with random numbers of sections, code blocks and tables (reStructuredText,
AsciiDoc, Org, Textile, MediaWiki, Creole, DokuWiki, man pages) and SWF
clips from ffmpeg with random sizes and frame rates. Expected facts come
from pandoc, asciidoctor, docutils, lexgrog (man-db), Perl's Pod::Simple,
makeinfo, python-hcl2, libmagic (`file`), ffprobe, warcio, Python's
http.cookiejar and urllib.robotparser, never from the generator. A check
key with a dot is a path in the whole report (`content.title`); one
without is a field of the format section. Nothing here ships with whiff.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys

R = random.Random(9)
WORDS = ["Harbour", "Tide", "Gull", "Pier", "Lantern", "Buoy", "Anchor", "Mist", "Keeper", "Reef", "Bell", "Rope"]
HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "..", "tests", "fixtures")


def words(n, sep=" "):
    return sep.join(R.choice(WORDS) for _ in range(n))


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def file_b(p):
    return run("file", "-b", p).strip()


# --- pandoc ---------------------------------------------------------------


def pandoc_ast(path, reader):
    return json.loads(run("pandoc", "-f", reader, "-t", "json", path))


def walk_blocks(blocks):
    for b in blocks:
        yield b
        c = b.get("c")
        kids = []
        if b["t"] in ("BlockQuote", "Div"):
            kids = [c[-1]] if b["t"] == "Div" else [c]
        elif b["t"] in ("BulletList",):
            kids = c
        elif b["t"] == "OrderedList":
            kids = c[1]
        for k in kids:
            yield from walk_blocks(k)


def pandoc_counts(path, reader):
    ast = pandoc_ast(path, reader)
    blocks = list(walk_blocks(ast["blocks"]))
    return {
        "headings": sum(b["t"] == "Header" for b in blocks),
        "code_blocks": sum(b["t"] == "CodeBlock" for b in blocks),
        "tables": sum(b["t"] == "Table" for b in blocks),
    }, ast.get("meta", {})


def docutils_tree(path):
    from docutils.core import publish_doctree

    return publish_doctree(open(path).read(), settings_overrides={"report_level": 5, "file_insertion_enabled": False})


def docutils_counts(path):
    """reST tables and literal blocks, from docutils (pandoc turns the
    bibliographic fields into a table)."""
    tree = docutils_tree(path)

    def in_message(n):
        # A system message quotes its directive as a literal block.
        while n is not None:
            if n.tagname == "system_message":
                return True
            n = n.parent
        return False

    return {
        "code_blocks": sum(1 for _ in tree.findall(lambda n: n.tagname == "literal_block" and not in_message(n))),
        "tables": sum(1 for _ in tree.findall(lambda n: n.tagname == "table")),
    }


def meta_text(m):
    """Plain text of a pandoc MetaValue."""
    if m["t"] == "MetaInlines":
        return "".join(i.get("c", " ") if i["t"] == "Str" else " " for i in m["c"]).strip()
    if m["t"] == "MetaString":
        return m["c"]
    if m["t"] == "MetaList":
        return [meta_text(x) for x in m["c"]]
    return None


# --- generated markup -------------------------------------------------------


def gen_rst(n_sec, n_code, n_tab):
    out = [words(2), "=" * 20, "", words(8) + ".", ""]
    for i in range(n_sec):
        t = words(2) + f" {i}"
        out += [t, "-" * len(t), "", words(10) + ".", ""]
    for _ in range(n_code):
        out += [".. code-block:: python", "", "   x = 1", ""]
    for _ in range(n_tab):
        out += ["+-----+-----+", "| a   | b   |", "+=====+=====+", "| 1   | 2   |", "+-----+-----+", ""]
    return "\n".join(out)


def gen_adoc(n_sec, n_code, n_tab):
    out = ["= " + words(2), "Ada Quayside", "v1." + str(R.randrange(9)) + ", 2025-11-05", ""]
    for i in range(n_sec):
        out += [f"== {words(2)} {i}", "", words(10) + ".", ""]
    for _ in range(n_code):
        out += ["[source,rust]", "----", "fn main() {}", "----", ""]
    for _ in range(n_tab):
        out += ["|===", "| a | b", "| 1 | 2", "|===", ""]
    return "\n".join(out)


def gen_org(n_sec, n_code, n_tab):
    out = ["#+TITLE: " + words(2), "#+AUTHOR: Ada Quayside", ""]
    for i in range(n_sec):
        out += [f"{'*' * R.randint(1, 3)} {words(2)} {i}", words(8)]
    for _ in range(n_code):
        out += ["#+BEGIN_SRC python", "x = 1", "#+END_SRC", ""]
    for _ in range(n_tab):
        out += ["| a | b |", "|---+---|", "| 1 | 2 |", ""]
    return "\n".join(out)


def gen_textile(n_sec, n_code, n_tab):
    out = []
    for i in range(n_sec):
        out += [f"h{R.randint(1, 3)}. {words(2)} {i}", "", words(8), ""]
    for _ in range(n_code):
        out += ["bc. x = 1", ""]
    for _ in range(n_tab):
        out += ["|_. a |_. b |", "| 1 | 2 |", ""]
    return "\n".join(out)


def gen_mediawiki(n_sec, n_code, n_tab):
    out = [words(8)]
    for i in range(n_sec):
        eq = "=" * R.randint(2, 4)
        out += [f"{eq} {words(2)} {i} {eq}", words(8)]
    for _ in range(n_code):
        out += ['<syntaxhighlight lang="python">', "x = 1", "</syntaxhighlight>"]
    for _ in range(n_tab):
        out += ['{| class="wikitable"', "! a !! b", "|-", "| 1 || 2", "|}"]
    return "\n".join(out)


def gen_creole(n_sec, n_code, n_tab):
    out = []
    for i in range(n_sec):
        eq = "=" * R.randint(1, 3)
        out += [f"{eq} {words(2)} {i} {eq}", words(8), ""]
    for _ in range(n_code):
        out += ["{{{", "x = 1", "}}}", ""]
    for _ in range(n_tab):
        out += ["|=a |=b |", "|1 |2 |", ""]
    return "\n".join(out)


def gen_dokuwiki(n_sec, n_code, n_tab):
    out = []
    for i in range(n_sec):
        eq = "=" * R.randint(2, 6)
        out += [f"{eq} {words(2)} {i} {eq}", words(8), ""]
    for _ in range(n_code):
        out += ["<code python>", "x = 1", "</code>", ""]
    for _ in range(n_tab):
        out += ["^ a ^ b ^", "| 1 | 2 |", ""]
    return "\n".join(out)


def gen_man(n_sec, name):
    out = [f'.TH {name.upper()} 1 "November 2025" "harbour-tools" "Harbour Commands"', ".SH NAME", f"{name} \\- {words(4).lower()}"]
    for i in range(n_sec):
        out += [f".SH {words(1).upper()}{i}", words(8)]
    return "\n".join(out) + "\n"


GENERATED = [
    ("rst", "rst", "rst", gen_rst),
    ("adoc", "asciidoc", None, gen_adoc),
    ("org", "org", "org", gen_org),
    ("textile", "textile", "textile", gen_textile),
    ("wiki", "mediawiki", "mediawiki", gen_mediawiki),
    ("creole", "creole", "creole", gen_creole),
    ("dokuwiki", "dokuwiki", "dokuwiki", gen_dokuwiki),
]


def asciidoctor_facts(path):
    script = (
        "require 'asciidoctor'; d = Asciidoctor.load_file(ARGV[0], safe: :safe); "
        "secs = d.find_by(context: :section).reject { |s| s.level == 0 }; "
        "puts({title: d.doctitle, authors: d.authors.map(&:name), revnumber: d.attr('revnumber'), "
        "revdate: d.attr('revdate'), sections: secs.size, listings: d.find_by(context: :listing).size, "
        "tables: d.find_by(context: :table).size}.to_json)"
    )
    return json.loads(run("ruby", "-rjson", "-e", script, path))


def lexgrog(path):
    """`name - description` as man-db reads it."""
    line = run("lexgrog", path).strip()
    m = re.search(r'"(.+?) - (.+)"$', line)
    return (m.group(1), m.group(2)) if m else (None, None)


def expect(out_dir):
    corpus = os.path.join(out_dir, "corpus")
    shutil.rmtree(corpus, ignore_errors=True)
    os.makedirs(corpus)
    facts = []

    def add(name, fmt, checks):
        facts.append({"file": name, "format": fmt, "checks": checks})

    def copy(fmt, name):
        # Under the format's folder: some formats are known by their file name.
        os.makedirs(os.path.join(corpus, fmt), exist_ok=True)
        dst = f"{fmt}/{name}"
        shutil.copy(os.path.join(FIXTURES, fmt, name), os.path.join(corpus, dst))
        return dst, os.path.join(corpus, dst)

    # Generated markup, counted by pandoc / asciidoctor.
    for ext, fmt, reader, gen in GENERATED:
        for i in range(6):
            n_sec, n_code, n_tab = R.randint(0, 6), R.randint(0, 3), R.randint(0, 2)
            name = f"gen-{fmt}-{i}.{ext}"
            path = os.path.join(corpus, name)
            open(path, "w").write(gen(n_sec, n_code, n_tab))
            if reader:
                counts, meta = pandoc_counts(path, reader)
                checks = docutils_counts(path) if fmt == "rst" else dict(counts)
                if fmt == "org":
                    checks["content.title"] = meta_text(meta["title"])
                add(name, fmt, checks)
            else:
                a = asciidoctor_facts(path)
                add(name, fmt, {"content.title": a["title"], "content.authors": a["authors"], "version": a["revnumber"],
                                "headings": a["sections"], "code_blocks": a["listings"], "tables": a["tables"]})
    for i in range(5):
        name = f"tool{i}"
        path = os.path.join(corpus, f"{name}.1")
        open(path, "w").write(gen_man(R.randint(1, 5), name))
        n, desc = lexgrog(path)
        counts, _ = pandoc_counts(path, "man")
        add(f"{name}.1", "roff", {"content.description": desc, "page.names": [n], "headings": counts["headings"]})

    # The markup fixtures.
    for fmt, name, reader in [
        ("rst", "harbour-guide.rst", "rst"),
        ("org", "maintenance.org", "org"),
        ("textile", "notice.textile", "textile"),
        ("mediawiki", "Saltmere_Harbour.wiki", "mediawiki"),
        ("creole", "harbour.creole", "creole"),
        ("dokuwiki", "harbour.dokuwiki", "dokuwiki"),
    ]:
        dst, path = copy(fmt, name)
        counts, meta = pandoc_counts(path, reader)
        checks = docutils_counts(path) if fmt == "rst" else dict(counts)
        if fmt == "rst":
            # docutils: the document title, subtitle and bibliographic fields.
            tree = docutils_tree(path)
            checks["content.title"] = tree.get("title")
            sub = [n for n in tree.findall(lambda n: n.tagname == "subtitle")]
            checks["subtitle"] = sub[0].astext() if sub else None
            info = {n.tagname: n.astext() for n in tree.findall(lambda n: n.tagname in ("author", "date", "version"))}
            checks["content.authors"] = [info["author"]]
            checks["version"] = info["version"]
        if fmt == "org":
            checks["content.title"] = meta_text(meta["title"])
            checks["content.authors"] = [meta_text(meta["author"])] if isinstance(meta_text(meta["author"]), str) else meta_text(meta["author"])
        add(dst, fmt, checks)
    dst, path = copy("asciidoc", "tide-tables.adoc")
    a = asciidoctor_facts(path)
    add(dst, "asciidoc", {"content.title": a["title"], "content.authors": a["authors"], "version": a["revnumber"],
                          "headings": a["sections"], "code_blocks": a["listings"], "tables": a["tables"]})
    for name in ["harbourctl.1", "tidewatch.8"]:
        dst, path = copy("roff", name)
        n, desc = lexgrog(path)
        add(dst, "roff", {"content.description": desc, "page.names" if name.endswith(".1") else "content.title": [n] if name.endswith(".1") else f"{n}(8)"})
    dst, path = copy("pod", "Saltmere-Tides.pod")
    pod = json.loads(run("perl", "-MPod::Simple::SimpleTree", "-MJSON::PP", "-e", POD_SCRIPT, path))
    add(dst, "pod", {"content.title": pod["name"].split(" - ")[0], "content.description": pod["name"].split(" - ")[1],
                     "headings": pod["heads"], "code_blocks": pod["verbatim"]})
    dst, path = copy("texinfo", "saltmere.texi")
    xml = run("makeinfo", "--xml", "-o", "-", path)
    add(dst, "texinfo", {"nodes": xml.count("<node "), "content.title": re.search(r"<settitle[^>]*>(.*?)</settitle>", xml).group(1)})
    dst, path = copy("gnu_info", "saltmere.info")
    add(dst, "gnu_info", {"nodes": xml.count("<node ")})

    # Configuration: python-hcl2.
    import hcl2

    dst, path = copy("terraform", "main.tf")
    tf = unquote(hcl2.load(open(path)))
    resources = {}
    for r in tf.get("resource", []):
        for t in r:
            resources[t] = resources.get(t, 0) + 1
    tfb = tf["terraform"][0]
    add(dst, "terraform", {
        "resources": resources,
        "data_sources": {t: 1 for d in tf.get("data", []) for t in d},
        "variables": [k for v in tf["variable"] for k in v],
        "outputs": [k for v in tf["output"] for k in v],
        "required_version": tfb["required_version"],
        "backend": next(iter(tfb["backend"][0])),
        "modules": [{"name": k, "source": v["source"]} for m in tf["module"] for k, v in m.items()],
    })

    # libmagic: versions in binary headers.
    for fmt, name, key, pattern, conv in [
        ("swf", "tides-as3.swf", "version", r"version (\d+)", int),
        # (libmagic does not know LZMA-compressed `ZWS` files.)
        ("swf", "harbour-clip.swf", "version", r"version (\d+)", int),
        ("vim_swap", "harbour.txt.swp", "vim_version", r"version (\S+?),", str),
        ("vim_swap", "harbour.txt.swp", "file", r"file ([^,\s]+)", str),
        ("warc", "harbour.warc", "version", r"version (\S+)", str),
    ]:
        dst, path = copy(fmt, name)
        m = re.search(pattern, file_b(path))
        add(dst, fmt, {key: conv(m.group(1))})
    for name in ["pier-r2000.dwg", "pier-r2004.dwg", "pier-r2018.dwg"]:
        dst, path = copy("dwg", name)
        add(dst, "dwg", {"release": re.search(r"AutoCAD (?:R)?(\d{4})", file_b(path)).group(1)})

    # ffprobe: the SWF muxer's stage and rate.
    for i in range(6):
        w, h, rate = R.choice([32, 64, 96, 160]), R.choice([24, 48, 90, 120]), R.choice([5, 10, 12, 24, 25])
        name = f"clip{i}.swf"
        path = os.path.join(corpus, name)
        run("ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i", f"testsrc=size={w}x{h}:rate={rate}:duration=1",
            "-c:v", "flv1", "-fflags", "+bitexact", path)
        s = json.loads(run("ffprobe", "-v", "error", "-show_streams", "-of", "json", path))["streams"][0]
        num, den = map(int, s["r_frame_rate"].split("/"))
        add(name, "swf", {"stage": {"width": s["width"], "height": s["height"]}, "frame_rate": num / den})

    # warcio, http.cookiejar, robotparser, metalink XML, bookmarks JSON.
    from warcio.archiveiterator import ArchiveIterator

    dst, path = copy("warc", "harbour.warc")
    types = {}
    for rec in ArchiveIterator(open(path, "rb")):
        types[rec.rec_type] = types.get(rec.rec_type, 0) + 1
    add(dst, "warc", {"records": sum(types.values()), "record_types": types})
    import http.cookiejar as cj

    dst, path = copy("cookie_jar", "cookies.txt")
    jar = cj.MozillaCookieJar()
    jar.load(path, ignore_discard=True, ignore_expires=True)
    cookies = list(jar)
    add(dst, "cookie_jar", {"cookies": len(cookies), "http_only": sum(c.has_nonstandard_attr("HTTPOnly") for c in cookies),
                            "secure": sum(c.secure for c in cookies)})
    import urllib.robotparser as rp

    dst, path = copy("robots_txt", "robots.txt")
    robots = rp.RobotFileParser()
    robots.parse(open(path).read().splitlines())
    blocked = sorted(a for a in ["gptbot", "ccbot", "claudebot"] if not robots.can_fetch(a, "/anything"))
    add(dst, "robots_txt", {"crawl_delay": float(robots.crawl_delay("*")), "sitemaps": robots.site_maps(), "ai_crawlers_blocked": blocked})
    import xml.etree.ElementTree as ET

    for name in ["tide-atlas.meta4", "charts.metalink"]:
        dst, path = copy("metalink", name)
        root = ET.parse(path).getroot()
        files = [e.get("name") for e in root.iter() if e.tag.endswith("}file")]
        urls = [e for e in root.iter() if e.tag.endswith("}url")]
        add(dst, "metalink", {"files": files, "urls": len(urls)})
    dst, path = copy("bookmarks", "Bookmarks")
    tree = json.load(open(path))
    urls = []
    stack = [tree["roots"]]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("type") == "url":
                urls.append(n["url"])
            stack.extend(n.values())
        elif isinstance(n, list):
            stack.extend(n)
    add(dst, "bookmarks", {"bookmarks": len(urls)})

    json.dump(facts, open(os.path.join(out_dir, "expected.json"), "w"), indent=1)
    print(len(facts), "files,", sum(len(f["checks"]) for f in facts), "checks")


POD_SCRIPT = r"""
my $t = Pod::Simple::SimpleTree->new->parse_file($ARGV[0])->root;
my ($heads, $verb, $name, $in_name) = (0, 0, "", 0);
sub text { my $n = shift; return ref $n ? join("", map { text($_) } @$n[2..$#$n]) : $n }
for my $n (@$t[2..$#$t]) {
  my $k = $n->[0];
  if ($k =~ /^head(\d)/) { $heads++; $in_name = text($n) eq "NAME"; next }
  $verb++ if $k eq "Verbatim";
  if ($in_name && $k eq "Para") { $name = text($n); $in_name = 0 }
}
print encode_json({heads => $heads, verbatim => $verb, name => $name});
"""


def unquote(v):
    """python-hcl2 8 keeps the quotes of labels and strings."""
    if isinstance(v, dict):
        return {unquote(k): unquote(x) for k, x in v.items()}
    if isinstance(v, list):
        return [unquote(x) for x in v]
    if isinstance(v, str) and len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1]
    return v


def resolve(report, key):
    if "." in key:
        cur = report
        for part in key.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
    return None


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
            top, _, rest = k.partition(".")
            if top in ("content", "rights", "temporal", "physical"):
                got = resolve(r, k)
            elif rest:
                got = resolve(fields, k)
            else:
                got = fields.get(k)
            ok = got == want or (isinstance(want, float) and isinstance(got, (int, float)) and abs(got - want) < 0.01)
            if not ok:
                bad += 1
                print(f"{f['file']}: {k}: whiff {got!r}, expected {want!r}")
    print(f"{total - bad} of {total} agree ({len(facts)} files)")
    return bad == 0


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        sys.exit(0 if check(sys.argv[2], sys.argv[3]) else 1)
