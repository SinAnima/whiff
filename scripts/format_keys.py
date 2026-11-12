#!/usr/bin/env python3
"""Consistency report for the keys extractors write under `format.<id>`,
read from the insta snapshots (the extractors' output contract).

    python3 scripts/format_keys.py [tests/snapshots] > target/format-keys.md

Lists keys that spell one idea several ways: counts (`rows` / `row_count` /
`n_rows`), units in names (`_bytes`, `_kb`, `_mb`, `_ms`, `_s`, …), dates
(`created` / `creation_time` / `created_at` …), versions, and singular /
plural pairs. Nothing is changed; the report is for review.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/snapshots")
uses = defaultdict(set)  # key -> {format ids}
kinds = defaultdict(lambda: defaultdict(set))  # key -> value kind -> {format ids}


def kind(x):
    if isinstance(x, bool):
        return "boolean"
    if isinstance(x, (int, float)):
        return "number"
    if isinstance(x, str):
        return "string"
    if isinstance(x, list):
        return "list"
    if isinstance(x, dict):
        return "object"
    return "null"


def walk(v, fmt, depth=0):
    if isinstance(v, dict):
        for k, x in v.items():
            if re.fullmatch(r"[a-z][a-z0-9_]*", k):
                uses[k].add(fmt)
                if depth == 0:
                    kinds[k][kind(x)].add(fmt)
            if depth < 3:
                walk(x, fmt, depth + 1)
    elif isinstance(v, list) and depth < 3:
        for x in v[:5]:
            walk(x, fmt, depth + 1)


def reports(v):
    yield v
    for e in v.get("embedded", []) or []:
        yield from reports(e)


for snap in sorted(root.glob("*.snap")):
    text = snap.read_text()
    body = text.split("---\n", 2)[2] if text.startswith("---") else text
    try:
        r = json.loads(body)
    except json.JSONDecodeError:
        continue
    for rep in reports(r):
        for fmt, section in (rep.get("format") or {}).items():
            walk(section, fmt)

keys = sorted(uses)


def stem(k):
    """The idea a key names: counting and unit spellings removed."""
    s = re.sub(r"^(n|num|number_of|total)_", "", k)
    s = re.sub(r"_(count|total|num)$", "", s)
    s = re.sub(r"_(bytes|kb|kib|mb|mib|gb|ms|s|sec|secs|seconds|us|ns|hz|khz|px|m|mm|deg|bps|kbps)$", "", s)
    if s.endswith("ies"):
        s = s[:-3] + "y"
    elif s.endswith("ses") or s.endswith("xes"):
        s = s[:-2]
    elif s.endswith("s") and not s.endswith("ss"):
        s = s[:-1]
    return s


groups = defaultdict(list)
for k in keys:
    groups[stem(k)].append(k)

print("# `format.*` key consistency\n")
print(f"{len(keys)} distinct keys over {len({f for s in uses.values() for f in s})} formats.\n")
print("## One key, several value types (top level of `format.<id>`)\n")
print("| Key | Types (formats) | Example formats |\n|---|---|---|")
for k in sorted(kinds, key=lambda k: -sum(len(v) for v in kinds[k].values())):
    ks = {t: f for t, f in kinds[k].items() if t != "null"}
    if len(ks) > 1:
        cells = ", ".join(f"{t} ({len(f)})" for t, f in sorted(ks.items(), key=lambda kv: -len(kv[1])))
        minority = min(ks.items(), key=lambda kv: len(kv[1]))
        print(f"| `{k}` | {cells} | {minority[0]}: {', '.join(sorted(minority[1])[:4])} |")
print()
print("## Same idea, several spellings\n")
print("| Idea | Spellings (formats using each) |\n|---|---|")
for s, ks in sorted(groups.items()):
    if len(ks) > 1:
        cells = ", ".join(f"`{k}` ({len(uses[k])})" for k in sorted(ks, key=lambda k: -len(uses[k])))
        print(f"| {s} | {cells} |")

print("\n## Date and time keys\n")
dates = [k for k in keys if re.search(r"(^|_)(date|time|created|modified|saved|written|timestamp|at)$|_at$|^(created|modified|saved)", k)]
print(", ".join(f"`{k}` ({len(uses[k])})" for k in sorted(dates, key=lambda k: -len(uses[k]))))

print("\n## Version keys\n")
vers = [k for k in keys if "version" in k]
print(", ".join(f"`{k}` ({len(uses[k])})" for k in sorted(vers, key=lambda k: -len(uses[k]))))

print("\n## Units in key names\n")
units = defaultdict(list)
for k in keys:
    m = re.search(r"_(bytes|kb|kib|mb|mib|gb|ms|s|sec|secs|seconds|us|ns|hz|khz|px|mm|deg|bps|kbps|100ns)$", k)
    if m:
        units[m.group(1)].append(k)
for u, ks in sorted(units.items()):
    print(f"- `_{u}`: " + ", ".join(f"`{k}`" for k in sorted(ks)))

print("\n## Count keys\n")
counts = [k for k in keys if re.search(r"(^(n|num|number_of)_|_count$)", k)]
print(", ".join(f"`{k}` ({len(uses[k])})" for k in sorted(counts, key=lambda k: -len(uses[k]))))
