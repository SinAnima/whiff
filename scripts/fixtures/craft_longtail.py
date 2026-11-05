"""Make whiff's long-tail fixtures (run by scripts/fixtures/longtail.sh in `whiff-longtail`).

    python3 craft_longtail.py OUT_DIR [STEP ...]   (markup config plain web cad source)

Everything belongs to the fictitious Saltmere Harbour. Files are written by
their own tools where one exists: makeinfo (the GNU info file, from the
Texinfo source), Vim
(a swap file left by a killed session), ffmpeg (an SWF video), warcio
(WARC) and Python's http.cookiejar (a Netscape cookie jar). Markup,
configuration and the other text files are written by hand; SWF tags,
DWG headers, NFO / ANSI art with SAUCE records and the Kindle clippings
file are written here from their specifications.
"""

import io
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib

OUT = TMP = None
STEPS = []
os.environ["SOURCE_DATE_EPOCH"] = "1762329600"  # 2025-11-05T08:00:00Z
EPOCH = 1762329600


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def out(fmt, name):
    d = os.path.join(OUT, fmt)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def write(fmt, name, data):
    if isinstance(data, str):
        data = data.encode()
    with open(out(fmt, name), "wb") as f:
        f.write(data)


def want(step):
    return not STEPS or step in STEPS


# ---------------------------------------------------------------- markup

RST = """\
===============
Saltmere Harbour
===============

----------------------------
A guide for visiting sailors
----------------------------

:Author: Ada Quayside
:Date: 2025-11-05
:Version: 1.4
:Copyright: 2025 Saltmere Harbour Board

.. meta::
   :description: Moorings, tides and services at Saltmere Harbour.
   :keywords: harbour, moorings, tides

Arriving
========

Call the harbour master on VHF channel 12 before entering. See the
`tide tables <https://tides.example.org/saltmere>`_ and the
:ref:`moorings` section.

.. image:: images/approach.png
   :alt: The approach to Saltmere

Moorings
--------

.. _moorings:

Visitor moorings are on the east pontoon. [#fees]_

.. list-table:: Mooring fees
   :header-rows: 1

   * - Length
     - Per night
   * - Under 10 m
     - 18.00

Checking the tide::

   tide --port saltmere --days 3

.. code-block:: python

   from tides import forecast
   print(forecast("saltmere"))

.. include:: services.rst

.. [#fees] Fees are reviewed every April.

.. _board: https://board.example.org/
"""

ADOC = """\
= Saltmere Tide Tables
Ada Quayside <harbourmaster@example.org>; Ben Netmaker
v2.1, 2025-11-05: Winter edition
:description: Tide times and heights for Saltmere Harbour.
:keywords: tides, harbour, Saltmere
:lang: en
:doctype: book
:toc: left
:email: harbourmaster@example.org

== Reading the tables

NOTE: Times are local (GMT in winter).

Heights are in metres above chart datum. See <<springs>> and the
https://tides.example.org/saltmere[online tables].

image::charts/datum.png[Chart datum]

[#springs]
== Spring tides

[source,python]
----
def height(hour):
    return 2.4 + 1.6 * cos(hour / 12.42 * 2 * pi)
----

|===
| Date | High water | Height
| 2025-11-05 | 06:12 | 4.1 m
|===

WARNING: The bar dries at low water springs.

include::appendix.adoc[]
"""

ORG = """\
#+TITLE: Harbour maintenance log
#+AUTHOR: Ben Netmaker
#+DATE: <2025-11-05 Wed>
#+LANGUAGE: en
#+FILETAGS: :harbour:maintenance:
#+TODO: TODO WAITING | DONE CANCELLED

* TODO [#A] Repaint the east pontoon :pontoon:
  SCHEDULED: <2025-11-10 Mon>
  :PROPERTIES:
  :COST: 400
  :END:
  - [X] Buy paint
  - [ ] Book the crane
* WAITING Replace the harbour light bulb :light:
  DEADLINE: <2025-11-20 Thu>
** DONE Order the bulb
   CLOSED: [2025-11-03 Mon 10:15]
   CLOCK: [2025-11-03 Mon 09:00]--[2025-11-03 Mon 10:15] =>  1:15
* CANCELLED Dredge the inner basin
* Notes
  See [[https://board.example.org/minutes][the board minutes]] and [[file:charts/basin.png]].

  #+BEGIN_SRC shell
  tide --port saltmere --days 7
  #+END_SRC

  | Job     | Cost |
  |---------+------|
  | Paint   |  400 |
  | Bulb    |   35 |
"""

TEXTILE = """\
h1. Notice to mariners

p. The *east pontoon* is closed for painting from 10 November.

h2. Diversions

* Visitors moor on the _west_ pontoon.
* Fuel is available as usual.

bq. Please keep to 3 knots inside the harbour.

bc. VHF channel 12

|_. Pontoon |_. Status |
| East | closed |
| West | open |

See "the harbour board":https://board.example.org/notices and !images/pontoon.png!.

fn1. Issued by the harbour master.
"""

MEDIAWIKI = """\
{{Infobox harbour
| name     = Saltmere Harbour
| country  = Fictitious
| moorings = 120
}}
'''Saltmere Harbour''' is a small fishing and leisure harbour.<ref>Harbour Board, ''Annual report'', 2025.</ref>
__NOTOC__

== History ==
The harbour wall was built in 1852.<ref name="wall">{{cite book |title=Walls of the Coast |year=1990}}</ref>

=== The lighthouse ===
[[File:Saltmere lighthouse.jpg|thumb|The lighthouse at dusk]]
The [[lighthouse]] was automated in 1988.

== Facilities ==
{| class="wikitable"
! Facility !! Open
|-
| Fuel || all year
|-
| Showers || April to October
|}

<syntaxhighlight lang="text">
VHF 12
</syntaxhighlight>

== External links ==
* [https://board.example.org/ Harbour Board]

== References ==
<references />

[[Category:Harbours]]
[[Category:Fictitious places]]
[[fr:Port de Saltmere]]
"""

MEDIAWIKI_REDIRECT = "#REDIRECT [[Saltmere Harbour]]\n\n[[Category:Redirects]]\n"

POD = """\
=encoding utf8

=head1 NAME

Saltmere::Tides - tide predictions for Saltmere Harbour

=head1 VERSION

Version 0.42

=head1 SYNOPSIS

    use Saltmere::Tides;
    my $t = Saltmere::Tides->new(port => 'saltmere');
    print $t->next_high_water;

=head1 DESCRIPTION

B<Saltmere::Tides> predicts high and low water from the harbour's
harmonic constants. See L<Saltmere::Charts> and
L<the board|https://board.example.org/>.

=head2 Methods

=over 4

=item new(%args)

Creates a predictor.

=item next_high_water

Returns the next high water as an epoch.

=back

=begin html

<p>Tide <em>tables</em>.</p>

=end html

=head1 AUTHOR

Ada Quayside

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
"""

MAN = r""".\" Manual page for harbourctl
.TH HARBOURCTL 1 "November 2025" "harbour-tools 1.4" "Harbour Commands"
.SH NAME
harbourctl \- control the Saltmere harbour lights and gates
.SH SYNOPSIS
.B harbourctl
[\fB\-v\fR]
\fIcommand\fR
.SH DESCRIPTION
.B harbourctl
switches the harbour lights and opens or closes the tide gates.
.SS Commands
.TP
.B lights on|off
Switch the lights.
.TP
.B gate open|close
Move the tide gate.
.SH EXAMPLES
.EX
harbourctl gate close
.EE
.SH SEE ALSO
.BR tidewatch (8)
.UR https://board.example.org/tools
Harbour tools
.UE
"""

MDOC = """\
.Dd November 5, 2025
.Dt TIDEWATCH 8
.Os Saltmere
.Sh NAME
.Nm tidewatch
.Nd watch the tide gauge and raise alarms
.Sh SYNOPSIS
.Nm
.Op Fl d
.Ar gauge
.Sh DESCRIPTION
The
.Nm
daemon reads the tide gauge every minute.
.Bd -literal
tidewatch -d /dev/gauge0
.Ed
.Sh SEE ALSO
.Xr harbourctl 1
"""

MS = """\
.TL
Annual Report of the Saltmere Harbour Board
.AU
Ada Quayside
.AI
Saltmere Harbour Board
.NH
Moorings
.PP
All one hundred and twenty moorings were let.
.NH
Works
.PP
The east pontoon was repainted.
.TS
tab(;);
l l.
Job;Cost
Paint;400
.TE
"""

TEXI = """\\input texinfo
@setfilename saltmere.info
@documentencoding UTF-8
@documentlanguage en
@settitle Saltmere Harbour Handbook
@set VERSION 1.4
@set UPDATED 5 November 2025

@copying
This handbook is for Saltmere Harbour, version @value{VERSION}.

Copyright @copyright{} 2025 Saltmere Harbour Board.
@end copying

@dircategory Harbours
@direntry
* Saltmere: (saltmere).  The Saltmere Harbour handbook.
@end direntry

@titlepage
@title Saltmere Harbour Handbook
@subtitle For visiting sailors
@author Ada Quayside
@end titlepage

@node Top
@top Saltmere Harbour

This handbook describes the harbour.

@menu
* Arriving::    Entering the harbour.
* Moorings::    Where to moor.
@end menu

@node Arriving
@chapter Arriving

Call the harbour master on @strong{VHF 12}. See @uref{https://board.example.org/}.

@example
tide --port saltmere
@end example

@node Moorings
@chapter Moorings

@section Fees

@multitable @columnfractions .5 .5
@headitem Length @tab Per night
@item Under 10 m @tab 18.00
@end multitable

@bye
"""

CREOLE = """\
= Saltmere Harbour =

== Moorings ==
Visitors moor on the **east pontoon**. See [[Moorings|the mooring plan]]
and [[https://board.example.org/|the board]].

{{images/pontoon.png|The east pontoon}}

== Fees ==
|=Length |=Per night |
|Under 10 m |18.00 |

{{{
VHF 12
}}}
"""

DOKUWIKI = """\
====== Saltmere Harbour ======

===== Moorings =====
Visitors moor on the **east pontoon**. See [[moorings|the mooring plan]]
and [[https://board.example.org/|the board]].

{{:pontoon.png?200|The east pontoon}}

==== Fees ====
^ Length ^ Per night ^
| Under 10 m | 18.00 |

<code bash>
tide --port saltmere
</code>

{{tag>harbour moorings}}
"""

DJOT = """\
# Saltmere Harbour

Visitors moor on the *east pontoon*. See [the board](https://board.example.org/)
and <https://tides.example.org/saltmere>.

![The east pontoon](images/pontoon.png)

## Fees

| Length     | Per night |
|------------|-----------|
| Under 10 m | 18.00     |

``` python
print("VHF 12")
```

::: warning
The bar dries at low water springs.[^bar]
:::

[^bar]: Charted at 0.4 m.

{#moorings}
## Moorings
"""

GEMTEXT = """\
# Saltmere Harbour

Welcome to the harbour capsule.

## Tides
=> gemini://tides.example.org/saltmere Tide tables
=> https://board.example.org/ The harbour board (web)
=> moorings.gmi Moorings
=> images/pontoon.png The east pontoon

### Weather
* Wind: south-west 4
* Sea: slight

> The bar dries at low water springs.

```text
VHF 12
```
"""


def markup():
    write("rst", "harbour-guide.rst", RST)
    write("asciidoc", "tide-tables.adoc", ADOC)
    write("org", "maintenance.org", ORG)
    write("textile", "notice.textile", TEXTILE)
    write("mediawiki", "Saltmere_Harbour.wiki", MEDIAWIKI)
    write("mediawiki", "Saltmere.wiki", MEDIAWIKI_REDIRECT)
    write("pod", "Saltmere-Tides.pod", POD)
    write("roff", "harbourctl.1", MAN)
    write("roff", "tidewatch.8", MDOC)
    write("roff", "annual-report.ms", MS)
    write("texinfo", "saltmere.texi", TEXI)
    write("creole", "harbour.creole", CREOLE)
    write("dokuwiki", "harbour.dokuwiki", DOKUWIKI)
    write("djot", "harbour.dj", DJOT)
    write("gemtext", "index.gmi", GEMTEXT)
    # makeinfo writes the info file from the Texinfo source.
    src = os.path.join(TMP, "saltmere.texi")
    open(src, "w").write(TEXI)
    run("makeinfo", "--no-split", "-o", out("gnu_info", "saltmere.info"), src)


# ---------------------------------------------------------------- config

TERRAFORM = """\
terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.0"
    }
  }

  backend "s3" {
    bucket = "saltmere-terraform-state"
    key    = "harbour/terraform.tfstate"
    region = "eu-west-2"
  }
}

provider "aws" {
  region = var.region
}

# Tide gauge readings.
resource "aws_s3_bucket" "gauge" {
  bucket = "saltmere-tide-gauge"
  tags = {
    Harbour = "Saltmere"
  }
}

resource "aws_s3_bucket_versioning" "gauge" {
  bucket = aws_s3_bucket.gauge.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
  name    = "harbour"
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "gauge_token" {
  type      = string
  sensitive = true
}

locals {
  policy = <<EOT
{ "Version": "2012-10-17" }
EOT
}

output "bucket" {
  value = aws_s3_bucket.gauge.bucket
}
"""

TFVARS = 'region = "eu-west-2"\nmoorings = 120\nharbour_name = "Saltmere"\n'

GITIGNORE = """\
# Build output
/target/
*.log
!keep.log
.env
node_modules/
charts/*.tmp
"""

DOCKERIGNORE = ".git\ntarget/\n*.md\n!README.md\n"

SYSTEM_CRONTAB = """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=harbour

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
*/5 *   * * *   harbour /usr/local/bin/tidewatch --poll
30 4    * * 1   root    /usr/sbin/logrotate /etc/logrotate.conf
"""

USER_CRONTAB = """\
# Harbour jobs
MAILTO=harbour
@reboot /usr/local/bin/harbourctl lights on
0 6 * * * /usr/local/bin/tide-report --mail
* * * * * /usr/local/bin/gauge-sample
@daily /usr/bin/find /var/harbour/tmp -mtime +7 -delete
"""

SSH_CONFIG = """\
# Harbour hosts
Host gauge
    HostName gauge.saltmere.example
    User harbour
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes

Host lighthouse lighthouse-backup
    HostName lighthouse.saltmere.example
    ProxyJump gauge
    StrictHostKeyChecking no

Match host *.saltmere.example
    ServerAliveInterval 30

Host *
    AddKeysToAgent yes
"""

SSHD_CONFIG = """\
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
AllowUsers harbour
"""

NGINX = """\
user www-data;
worker_processes auto;

events {
    worker_connections 768;
}

http {
    include /etc/nginx/mime.types;

    upstream tides {
        server 127.0.0.1:8080;
    }

    server {
        listen 80;
        server_name saltmere.example www.saltmere.example;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        server_name saltmere.example;
        ssl_certificate /etc/ssl/saltmere.pem;
        ssl_certificate_key /etc/ssl/saltmere.key;

        location / {
            root /var/www/harbour;
        }

        location /tides/ {
            proxy_pass http://tides;
        }
    }
}
"""

HTTPD = """\
ServerRoot "/etc/httpd"
Listen 80
Listen 443
LoadModule ssl_module modules/mod_ssl.so
LoadModule rewrite_module modules/mod_rewrite.so
Include conf.d/*.conf

<VirtualHost *:443>
    ServerName saltmere.example
    ServerAlias www.saltmere.example
    DocumentRoot /var/www/harbour
    SSLEngine on
    SSLCertificateFile /etc/ssl/saltmere.pem
    <Directory /var/www/harbour>
        AllowOverride All
    </Directory>
</VirtualHost>
"""

HTACCESS = """\
RewriteEngine On
RewriteRule ^tides/(.*)$ /tide.php?day=$1 [L]
Redirect 301 /old-moorings /moorings
AuthType Basic
AuthName "Harbour staff"
Require valid-user
"""

PROCFILE = "web: gunicorn harbour.wsgi --bind 0.0.0.0:$PORT\nworker: celery -A harbour worker\nrelease: python manage.py migrate\n"

JUSTFILE = """\
set shell := ["bash", "-c"]
set dotenv-load

port := "saltmere"
export RUST_LOG := "info"

import 'ci.just'

# Show the next tides
default: tides

tides days="3":
    tide --port {{port}} --days {{days}}

@deploy: build
    ./deploy.sh

build:
    cargo build --release
"""

VAGRANTFILE = """\
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"

  config.vm.define "gauge" do |gauge|
    gauge.vm.hostname = "gauge"
    gauge.vm.network "forwarded_port", guest: 80, host: 8080
  end

  config.vm.define "lighthouse" do |l|
    l.vm.box = "debian/trixie64"
  end

  config.vm.synced_folder "./charts", "/srv/charts"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 1024
  end

  config.vm.provision "shell", inline: "apt-get install -y nginx"
  config.vm.provision "ansible" do |a|
    a.playbook = "harbour.yml"
  end
end
"""

CADDYFILE = """\
{
    email harbourmaster@example.org
}

saltmere.example, www.saltmere.example {
    root * /var/www/harbour
    file_server
    encode gzip
    reverse_proxy /tides/* 127.0.0.1:8080
}

gauge.saltmere.example {
    reverse_proxy 127.0.0.1:9090
    tls internal
}
"""

HAPROXY = """\
global
    log /dev/log local0
    maxconn 2000

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend harbour_web
    bind *:80
    bind *:443 ssl crt /etc/haproxy/saltmere.pem
    default_backend tides

backend tides
    balance roundrobin
    server tide1 10.0.0.11:8080 check
    server tide2 10.0.0.12:8080 check

listen stats
    bind *:8404
    mode http
    stats enable
"""


def config():
    write("terraform", "main.tf", TERRAFORM)
    write("terraform", "harbour.tfvars", TFVARS)
    write("ignore_file", "harbour.gitignore", GITIGNORE)
    write("ignore_file", "harbour.dockerignore", DOCKERIGNORE)
    write("crontab", "crontab", SYSTEM_CRONTAB)
    write("crontab", "harbour.cron", USER_CRONTAB)
    write("ssh_config", "ssh_config", SSH_CONFIG)
    write("ssh_config", "sshd_config", SSHD_CONFIG)
    write("web_server_config", "nginx.conf", NGINX)
    write("web_server_config", "httpd.conf", HTTPD)
    write("web_server_config", "harbour.htaccess", HTACCESS)
    write("procfile", "Procfile", PROCFILE)
    write("justfile", "justfile", JUSTFILE)
    write("vagrantfile", "Vagrantfile", VAGRANTFILE)
    write("caddyfile", "Caddyfile", CADDYFILE)
    write("haproxy_config", "haproxy.cfg", HAPROXY)


# ---------------------------------------------------------------- plain text

CP437 = {c: i for i, c in enumerate(bytes(range(128)).decode("ascii"))}
CP437_HIGH = (
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐"
    "└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\xa0"
)
CP437.update({c: 0x80 + i for i, c in enumerate(CP437_HIGH)})


def cp437(s):
    return bytes(CP437[c] for c in s)


def sauce(title, author, group, date, size, file_type, width, height, font="IBM VGA", flags=0):
    r = b"SAUCE00"
    r += title.encode().ljust(35) + author.encode().ljust(20) + group.encode().ljust(20) + date.encode()
    r += struct.pack("<IBBHHHHBB", size, 1, file_type, width, height, 0, 0, 0, flags)
    r += font.encode().ljust(22, b"\0")
    assert len(r) == 128
    return b"\x1a" + r


NFO = """\
╔══════════════════════════════════════════════╗
║          SALTMERE HARBOUR ARCHIVE            ║
╚══════════════════════════════════════════════╝

  Title ..........: Saltmere Tide Atlas
  Release Date ...: 2025-11-05
  Size ...........: 2 x 1.44MB
  Format .........: ZIP
  Language .......: English
  Group ..........: Harbour Board

  ░▒▓ Notes ▓▒░
  Hand-drawn charts of the harbour approaches.
"""

DIZ = """\
Saltmere Tide Atlas v1.0
───────────────────────
Charts of the harbour.
(1/2)
"""

ANS = (
    "\x1b[0;1;36m╔════════╗\r\n"
    "\x1b[0;33m║ \x1b[1;37mTIDES\x1b[0;33m  ║\r\n"
    "\x1b[0;1;36m╚════════╝\x1b[0m\r\n"
)

HOSTS = """\
127.0.0.1   localhost
::1         localhost ip6-localhost ip6-loopback
10.0.0.11   gauge.saltmere.example gauge
10.0.0.12   lighthouse.saltmere.example
# blocked
0.0.0.0     ads.example.com
0.0.0.0     tracker.example.net
0.0.0.0     telemetry.example.org
"""

CODEOWNERS = """\
# Harbour repository owners
*                   @saltmere/harbour-board
/charts/            @saltmere/cartographers @ada-quayside
/tides/*.py         @ben-netmaker harbourmaster@example.org
/docs/
[Lighthouse]
/lighthouse/        @saltmere/keepers
"""

CLIPPINGS = """\
﻿The Walls of the Coast (Morgan, Iris)
- Your Highlight on page 12 | Location 180-182 | Added on Wednesday, 5 November 2025 08:12:40

The harbour wall was built from stone carried on the tide.
==========
The Walls of the Coast (Morgan, Iris)
- Your Note on page 12 | Location 182 | Added on Wednesday, 5 November 2025 08:13:05

Compare with Saltmere.
==========
Tides and Their Keepers (Quayside, Ada)
- Your Bookmark on Location 410 | Added on Thursday, 6 November 2025 21:00:00


==========
Tides and Their Keepers (Quayside, Ada)
- Your Highlight on Location 512-515 | Added on Thursday, 6 November 2025 21:04:10

Every harbour has two tides a day, and every keeper knows both.
==========
"""

README = """\
Saltmere Harbour tools
======================

Command-line tools for the Saltmere harbour lights, gates and tide gauge.

Install with `make install`. See CHANGELOG for what changed.
"""

CHANGELOG = """\
Changelog
=========

## Unreleased

- Gate timing follows the tide gauge.

## [1.4.0] - 2025-11-05

- harbourctl: `gate` command.

## [1.3.2] - 2025-06-30

- Fix the light timer at midnight.

## [1.0.0] - 2024-04-01

- First release.
"""


def vim_swap():
    """A swap file left behind by a Vim session killed after `:preserve`."""
    d = os.path.join(TMP, "vim")
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "harbour.txt")
    open(f, "w").write("Saltmere Harbour notes\n")
    p = subprocess.Popen(
        ["vim", "-u", "NONE", "-N", "-es", "-c", "normal Gonew moorings", "-c", "preserve", "-c", "sleep 30", f],
        cwd=d,
        env={**os.environ, "HOME": d, "USER": "harbour", "LOGNAME": "harbour"},
    )
    swp = os.path.join(d, ".harbour.txt.swp")
    for _ in range(100):
        if os.path.exists(swp) and os.path.getsize(swp) >= 4096:
            break
        time.sleep(0.1)
    time.sleep(0.5)
    p.kill()
    p.wait()
    # The container's user, host name and home differ on every run: set
    # them (block 0: user at 28 and host at 68, 40 bytes each; the file
    # name at 108, whose field also holds the encoding at its far end).
    b = bytearray(open(swp, "rb").read())
    for at, value in [(28, b"harbour"), (68, b"saltmere-gauge")]:
        b[at : at + 40] = value.ljust(40, b"\0")
    old_len = b.index(0, 108) - 108
    name = b"~harbour/harbour.txt"
    b[108 : 108 + max(old_len, len(name)) + 1] = name.ljust(max(old_len, len(name)) + 1, b"\0")
    open(out("vim_swap", "harbour.txt.swp"), "wb").write(bytes(b))


def plain():
    nfo = cp437(NFO)
    write("nfo", "saltmere.nfo", nfo + sauce("Saltmere Tide Atlas", "Ada Quayside", "Harbour Board", "20251105", len(nfo), 0, 48, 14))
    write("nfo", "file_id.diz", cp437(DIZ))
    ans = cp437(ANS)
    write("nfo", "tides.ans", ans + sauce("Tides", "Ben Netmaker", "Harbour Board", "20251105", len(ans), 1, 80, 3, flags=1))
    write("hosts", "hosts", HOSTS)
    write("codeowners", "CODEOWNERS", CODEOWNERS)
    write("kindle_clippings", "My Clippings.txt", CLIPPINGS)
    write("text", "README", README)
    write("text", "CHANGELOG", CHANGELOG)
    vim_swap()


# ---------------------------------------------------------------- web

ROBOTS = """\
# Saltmere Harbour
User-agent: *
Disallow: /admin/
Allow: /admin/tides
Crawl-delay: 2

User-agent: GPTBot
User-agent: CCBot
Disallow: /

Sitemap: https://saltmere.example/sitemap.xml
"""

SECURITY_TXT = """\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Contact: mailto:security@saltmere.example
Contact: https://saltmere.example/security
Expires: 2026-11-05T00:00:00.000Z
Encryption: https://saltmere.example/pgp-key.txt
Preferred-Languages: en, cy
Canonical: https://saltmere.example/.well-known/security.txt
Policy: https://saltmere.example/disclosure
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCgAdFiEEexampleexampleexampleexampleexampleAAoJEJ
-----END PGP SIGNATURE-----
"""

HUMANS = """\
/* TEAM */
Harbour master: Ada Quayside
Site: https://saltmere.example

/* THANKS */
The lighthouse keepers

/* SITE */
Last update: 2025/11/05
Standards: HTML5, CSS3
"""

PAC = """\
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".saltmere.example"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0"))
        return "DIRECT";
    if (shExpMatch(url, "https://tides.*"))
        return "PROXY tides-proxy.saltmere.example:3128; DIRECT";
    return "PROXY proxy.saltmere.example:8080; SOCKS5 socks.saltmere.example:1080";
}
"""

META4 = """\
<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <generator>harbour-mirror/1.0</generator>
  <published>2025-11-05T08:00:00Z</published>
  <file name="tide-atlas-1.0.zip">
    <size>1474560</size>
    <hash type="sha-256">3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea</hash>
    <url location="gb" priority="1">https://mirror1.example.org/atlas/tide-atlas-1.0.zip</url>
    <url location="fr" priority="2">https://mirror2.example.net/atlas/tide-atlas-1.0.zip</url>
  </file>
  <file name="tide-atlas-1.0.pdf">
    <size>204800</size>
    <hash type="sha-1">a9993e364706816aba3e25717850c26c9cd0d89d</hash>
    <url>https://mirror1.example.org/atlas/tide-atlas-1.0.pdf</url>
  </file>
</metalink>
"""

METALINK3 = """\
<?xml version="1.0" encoding="UTF-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/" generator="harbour-mirror/0.9" pubdate="Wed, 05 Nov 2025 08:00:00 GMT">
  <files>
    <file name="charts.tar.gz">
      <size>51200</size>
      <verification>
        <hash type="md5">900150983cd24fb0d6963f7d28e17f72</hash>
      </verification>
      <resources>
        <url type="http">https://mirror1.example.org/charts.tar.gz</url>
        <url type="ftp">ftp://ftp.example.org/charts.tar.gz</url>
      </resources>
    </file>
  </files>
</metalink>
"""

ADBLOCK = """\
[Adblock Plus 2.0]
! Title: Saltmere Harbour filters
! Version: 202511050800
! Last modified: 05 Nov 2025 08:00 UTC
! Expires: 4 days
! Homepage: https://saltmere.example/filters
! License: CC0-1.0
||ads.example.com^
||tracker.example.net^$third-party
/banner/*$image
@@||saltmere.example^$document
saltmere.example##.popup-ad
saltmere.example#@#.newsletter
example.org##+js(nowebrtc)
"""

BOOKMARKS_HTML = """\
<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file. -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ADD_DATE="1762329600" LAST_MODIFIED="1762329600">Harbour</H3>
    <DL><p>
        <DT><A HREF="https://saltmere.example/" ADD_DATE="1762329600">Saltmere Harbour</A>
        <DT><A HREF="https://tides.example.org/saltmere" ADD_DATE="1762333200">Tide tables</A>
    </DL><p>
    <DT><H3 ADD_DATE="1762329600">Weather</H3>
    <DL><p>
        <DT><A HREF="https://weather.example.net/coast" ADD_DATE="1762340000">Coastal forecast</A>
    </DL><p>
</DL><p>
"""


def chrome_bookmarks():
    node = lambda name, url, t: {"date_added": str(t), "guid": "", "id": "1", "name": name, "type": "url", "url": url}
    base = (EPOCH + 11_644_473_600) * 1_000_000
    return json.dumps(
        {
            "checksum": "",
            "roots": {
                "bookmark_bar": {"children": [node("Saltmere Harbour", "https://saltmere.example/", base)], "name": "Bookmarks bar", "type": "folder", "date_added": str(base)},
                "other": {"children": [{"children": [node("Tides", "https://tides.example.org/saltmere", base + 3_600_000_000)], "name": "Harbour", "type": "folder", "date_added": str(base)}], "name": "Other bookmarks", "type": "folder", "date_added": str(base)},
                "synced": {"children": [], "name": "Mobile bookmarks", "type": "folder", "date_added": str(base)},
            },
            "version": 1,
        },
        indent=3,
    )


NETRC = """\
machine gauge.saltmere.example
  login harbour
  password not-a-real-password
machine charts.saltmere.example login cartographer password also-not-real
default login anonymous password guest@
"""

CURLRC = """\
# curl defaults for the harbour scripts
user-agent = "harbour-tools/1.4"
--connect-timeout 10
proxy = "http://proxy.saltmere.example:8080"
user = "harbour:not-a-real-password"
silent
"""

WGETRC = """\
tries = 3
timeout = 30
check_certificate = off
http_proxy = http://proxy.saltmere.example:8080/
http_user = harbour
http_password = not-a-real-password
"""


def cookies():
    import http.cookiejar as cj

    jar = cj.MozillaCookieJar(out("cookie_jar", "cookies.txt"))
    def add(domain, name, value, secure, expires, path="/", rest=None):
        jar.set_cookie(cj.Cookie(0, name, value, None, False, domain, True, domain.startswith("."), path, True, secure, expires, expires is None, None, None, rest or {}))
    add(".saltmere.example", "session", "0000", True, None)
    add(".saltmere.example", "lang", "en", False, EPOCH + 86400 * 365)
    add("tides.example.org", "units", "metric", True, EPOCH + 86400 * 30)
    add(".weather.example.net", "region", "coast", False, EPOCH + 86400 * 7, rest={"HttpOnly": None})
    jar.save(ignore_discard=True, ignore_expires=True)
    # http.cookiejar writes HttpOnly cookies without the `#HttpOnly_` prefix
    # that curl and browsers use; mark the last one the way curl does.
    p = out("cookie_jar", "cookies.txt")
    lines = open(p).read().splitlines()
    lines = [("#HttpOnly_" + l if l.startswith(".weather") else l) for l in lines]
    open(p, "w").write("\n".join(lines) + "\n")


def warc():
    from warcio.statusandheaders import StatusAndHeaders
    from warcio.warcwriter import WARCWriter

    with open(out("warc", "harbour.warc"), "wb") as f:
        w = WARCWriter(f, gzip=False)
        info = w.create_warcinfo_record("harbour.warc", {"software": "warcio (whiff fixtures)", "format": "WARC File Format 1.1", "description": "Saltmere Harbour pages"})
        w.write_record(info)
        for path, body, ctype in [
            ("/", b"<html><title>Saltmere Harbour</title></html>", "text/html; charset=utf-8"),
            ("/tides.json", b'{"high": "06:12"}', "application/json"),
        ]:
            url = "https://saltmere.example" + path
            req = StatusAndHeaders("GET " + path + " HTTP/1.1", [("Host", "saltmere.example")], is_http_request=True)
            w.write_record(w.create_warc_record(url, "request", http_headers=req, payload=io.BytesIO(b"")))
            resp = StatusAndHeaders("200 OK", [("Content-Type", ctype), ("Content-Length", str(len(body)))], protocol="HTTP/1.1")
            w.write_record(w.create_warc_record(url, "response", payload=io.BytesIO(body), http_headers=resp))
        w.write_record(w.create_warc_record("https://saltmere.example/", "metadata", payload=io.BytesIO(b"via: harbour-crawler\n"), warc_content_type="application/warc-fields"))


# --- SWF ------------------------------------------------------------------


def swf_rect(xmin, xmax, ymin, ymax):
    vals = [xmin, xmax, ymin, ymax]
    nbits = max(v.bit_length() for v in vals) + 1
    bits = format(nbits, "05b") + "".join(format(v & ((1 << nbits) - 1), f"0{nbits}b") for v in vals)
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def tag(code, body=b""):
    if len(body) < 0x3F and code not in (87,):
        return struct.pack("<H", code << 6 | len(body)) + body
    return struct.pack("<HI", code << 6 | 0x3F, len(body)) + body


def cstr(s):
    return s.encode() + b"\0"


XMP = (
    '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
    "<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Saltmere Tides</rdf:li></rdf:Alt></dc:title>"
    "<dc:creator><rdf:Seq><rdf:li>Ada Quayside</rdf:li></rdf:Seq></dc:creator>"
    "</rdf:Description></rdf:RDF></x:xmpmeta>"
)


def swf_body(as3=True):
    tags = b""
    attrs = 0x08 if as3 else 0
    tags += tag(69, struct.pack("<I", attrs | 0x10 | 0x01))
    tags += tag(77, cstr(XMP))
    tags += tag(65, struct.pack("<HH", 1000, 60))
    tags += tag(9, bytes([0x10, 0x40, 0x70]))
    ms = EPOCH * 1000
    tags += tag(41, struct.pack("<IIBBIIQ", 3, 6, 4, 6, 23201, 0, ms))
    tags += tag(86, b"\x01\x00" + cstr("Harbour"))
    tags += tag(2, b"\x01\x00" + b"\0" * 12)
    tags += tag(39, b"\x02\x00\x01\x00" + tag(1) + tag(0))
    tags += tag(87, b"\x03\x00\0\0\0\0" + b"tide data")
    tags += tag(56, b"\x01\x00\x02\x00" + cstr("Boat"))
    if as3:
        tags += tag(82, struct.pack("<I", 1) + cstr("saltmere/tides") + b"\x10\x00\x2e\x00")
        tags += tag(76, b"\x02\x00" + b"\x00\x00" + cstr("SaltmereTides") + b"\x02\x00" + cstr("Boat"))
    else:
        tags += tag(12, b"\x00")
    tags += tag(43, cstr("start"))
    tags += tag(1)
    tags += tag(43, cstr("harbour"))
    tags += tag(1)
    tags += tag(0)
    return swf_rect(0, 550 * 20, 0, 400 * 20) + struct.pack("<HH", 24 << 8, 2) + tags


def swf():
    body = swf_body(as3=True)
    write("swf", "tides-as3.swf", b"CWS" + bytes([10]) + struct.pack("<I", 8 + len(body)) + zlib.compress(body, 9))
    body = swf_body(as3=False)
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]
    raw = lzma.compress(body, format=lzma.FORMAT_RAW, filters=filters)
    props = bytes([(2 * 5 + 0) * 9 + 3]) + struct.pack("<I", 1 << 16)
    write("swf", "tides-as2.swf", b"ZWS" + bytes([13]) + struct.pack("<I", 8 + len(body)) + struct.pack("<I", len(raw)) + props + raw)
    # ffmpeg's SWF muxer: an uncompressed file holding a video stream.
    run(
        "ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10:duration=1",
        "-c:v", "flv1", "-fflags", "+bitexact", out("swf", "harbour-clip.swf"),
    )


def web():
    write("robots_txt", "robots.txt", ROBOTS)
    write("robots_txt", "security.txt", SECURITY_TXT)
    write("robots_txt", "humans.txt", HUMANS)
    write("pac", "proxy.pac", PAC)
    write("metalink", "tide-atlas.meta4", META4)
    write("metalink", "charts.metalink", METALINK3)
    write("adblock_list", "harbour-filters.txt", ADBLOCK)
    write("bookmarks", "bookmarks.html", BOOKMARKS_HTML)
    write("bookmarks", "Bookmarks", chrome_bookmarks())
    write("netrc", "harbour.netrc", NETRC)
    write("netrc", "harbour.curlrc", CURLRC)
    write("netrc", "harbour.wgetrc", WGETRC)
    cookies()
    warc()
    swf()


# ---------------------------------------------------------------- CAD


def dwg_header(version, maint, codepage, thumbnail, r2004=False, security=0):
    h = bytearray(0x100 if r2004 else 0x60)
    h[0:6] = version.encode()
    h[0x0B] = maint
    h[0x0C] = 1
    struct.pack_into("<I", h, 0x0D, 0x1C0 if thumbnail else 0)
    if r2004:
        h[0x11] = 33  # writer (dwg version) byte
        h[0x12] = maint
    struct.pack_into("<H", h, 0x13, codepage)
    if r2004:
        struct.pack_into("<I", h, 0x18, security)
        struct.pack_into("<I", h, 0x20, 0x200)  # summary info
        struct.pack_into("<I", h, 0x24, 0)  # no VBA project
        h[0x28] = 0x80
    return bytes(h) + b"\0" * 0x200


def cad():
    write("dwg", "pier-r2000.dwg", dwg_header("AC1015", 15, 30, True))
    write("dwg", "pier-r2004.dwg", dwg_header("AC1018", 2, 30, False, r2004=True, security=0))
    write("dwg", "pier-r2018.dwg", dwg_header("AC1032", 4, 30, True, r2004=True, security=4))


# ---------------------------------------------------------------- source

MATLAB = """\
function h = tide_height(t, mean_level, amplitude)
% TIDE_HEIGHT  Height of the tide at Saltmere at time t (hours).
%   h = tide_height(t, 2.4, 1.6)
%{
  The M2 constituent only: period 12.42 hours.
%}
import saltmere.constants.*
if nargin < 2
    mean_level = 2.4;
end
h = mean_level + amplitude .* cos(2 * pi * t / 12.42);
end

function plot_day()
% Plot a day of tides.
t = 0:0.25:24;
plot(t, tide_height(t, 2.4, 1.6));
end
"""

OBJC = """\
#import <Foundation/Foundation.h>
#import "Harbour.h"

@implementation Harbour

- (NSString *)name {
    return @"Saltmere";
}

@end
"""


def source():
    write("matlab", "tide_height.m", MATLAB)
    write("objective_c", "Harbour.m", OBJC)


def main():
    global OUT, TMP, STEPS
    OUT = os.path.abspath(sys.argv[1])
    STEPS = sys.argv[2:]
    TMP = os.path.join(OUT, "_work")
    os.makedirs(TMP, exist_ok=True)
    for name, step in [("markup", markup), ("config", config), ("plain", plain), ("web", web), ("cad", cad), ("source", source)]:
        if want(name):
            step()
    shutil.rmtree(TMP, ignore_errors=True)
    print("long-tail fixtures written to", OUT)


if __name__ == "__main__":
    main()
