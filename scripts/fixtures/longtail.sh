#!/usr/bin/env bash
# Regenerate the long-tail fixtures under tests/fixtures/<format>/.
#
# Written in a container run with podman, for the fictitious Saltmere
# Harbour, CC0-1.0: craft_longtail.py in `whiff-longtail` (the Containerfile
# below) drives makeinfo 7.1 (GNU info), Vim 9.1 (a swap file), ffmpeg 7.1 (an SWF video),
# warcio 1.8 (WARC) and Python's http.cookiejar (a Netscape cookie jar).
# The rest is written by hand or by craft_longtail.py from the formats'
# specifications.
#
#     scripts/fixtures/longtail.sh [STEP ...]   (markup config plain web cad source)
#
# Containerfile (`podman build -t whiff-longtail`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           texinfo vim-nox ffmpeg file pandoc asciidoctor man-db perl ca-certificates
#     RUN pip install --no-cache-dir warcio docutils python-hcl2
#
# (`file`, ffprobe, pandoc, asciidoctor, lexgrog, Perl's Pod::Simple,
# docutils and python-hcl2 are for longtail_oracle.py.)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/longtail-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-longtail python3 scripts/fixtures/craft_longtail.py "$w" "$@"

for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for the fictitious Saltmere Harbour. Regenerate with \`scripts/fixtures/longtail.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
# `text` and `objective_c` already have SOURCE.md files listing other
# fixtures; their new files are added to those by hand.
while IFS='|' read -r id name origin; do
    [ -d "$fx/$id" ] && source_md "$id" "$name" "$origin"
done <<'LIST'
rst|reStructuredText|written by hand
asciidoc|AsciiDoc|written by hand
org|Org-mode|written by hand
textile|Textile|written by hand
mediawiki|MediaWiki markup|written by hand
pod|Perl POD|written by hand
roff|troff / man page|written by hand (man, mdoc, ms)
texinfo|Texinfo|written by hand
creole|Creole|written by hand
dokuwiki|DokuWiki|written by hand
djot|Djot|written by hand
gemtext|Gemtext|written by hand
gnu_info|GNU info|makeinfo 7.1 from the `texinfo` fixture
terraform|Terraform / HCL|written by hand
ignore_file|Ignore file|written by hand
crontab|crontab|written by hand (system and user crontabs)
ssh_config|SSH config|written by hand (client and server)
web_server_config|nginx / Apache config|written by hand
procfile|Procfile|written by hand
justfile|Justfile|written by hand
vagrantfile|Vagrantfile|written by hand
caddyfile|Caddyfile|written by hand
haproxy_config|HAProxy configuration|written by hand
nfo|NFO / DIZ / ANSI art|craft_longtail.py (code page 437, SAUCE 00.5 records)
hosts|Hosts file|written by hand
codeowners|CODEOWNERS|written by hand
vim_swap|Vim swap file|Vim 9.1, killed after `:preserve`; user, host and file name set by craft_longtail.py
kindle_clippings|Kindle clippings|written by hand (Kindle `My Clippings.txt` layout)
robots_txt|robots.txt / security.txt / humans.txt|written by hand
pac|Proxy auto-config|written by hand
metalink|Metalink|written by hand (Metalink 4 and 3)
adblock_list|Adblock filter list|written by hand
cookie_jar|Netscape cookie jar|Python http.cookiejar (`MozillaCookieJar`); one line marked `#HttpOnly_`
bookmarks|Browser bookmarks|written by hand (Netscape HTML), craft_longtail.py (Chrome JSON)
netrc|.netrc / .curlrc / .wgetrc|written by hand (fictitious credentials)
warc|WARC web archive|warcio 1.8
swf|Shockwave Flash|craft_longtail.py (SWF 19 tags; zlib and LZMA), ffmpeg 7.1 (SWF muxer)
dwg|AutoCAD DWG|craft_longtail.py (ODA specification file headers only)
matlab|MATLAB / Octave script|written by hand
LIST
echo "fixtures written; scratch files in $work"
