#!/usr/bin/env bash
# Regenerate the database fixtures under tests/fixtures/<format>/.
#
# Every ACE (2007+) file Jackcess writes is over the 256 KiB fixture limit,
# so the Access 2016 file is kept in the work folder for the oracle only.
#
# Real engines write them, in a Debian container run with podman (image
# `whiff-db`, built from the Containerfile below), for a fictitious harbour
# (Saltmere Harbour): sqlite3 and Python's sqlite3 (plain, UTF-16, WAL and
# journal files), GDAL (GeoPackage, MBTiles, SpatiaLite, a shapefile's DBF),
# the Python `dbf` package (dBASE III with memo, FoxPro, Visual FoxPro),
# Jackcess (Access 2000 and 2016), DuckDB, mdb_load (LMDB), db5.3_load
# (Berkeley DB), ldb (RocksDB), plyvel (LevelDB), Redis, PostgreSQL's
# pg_dump, MariaDB (.frm, .ibd, .MYI, .MAI) and H2. The browser history,
# Anki and Core Data files are made by Python from the applications'
# published schemas, with invented rows.
#
#     scripts/fixtures/db.sh
#
# Containerfile (`podman build -t whiff-db`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         sqlite3 python3 python3-pip gdal-bin mdbtools openjdk-21-jdk-headless lmdb-utils db-util \
#         rocksdb-tools python3-plyvel redis-server postgresql mariadb-server wget ca-certificates
#     RUN pip install --break-system-packages duckdb==1.3.2 dbf==0.99.9
#     RUN mkdir -p /opt/jars && cd /opt/jars && \
#         wget -q https://repo1.maven.org/maven2/com/healthmarketscience/jackcess/jackcess/4.0.5/jackcess-4.0.5.jar && \
#         wget -q https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar && \
#         wget -q https://repo1.maven.org/maven2/commons-logging/commons-logging/1.3.0/commons-logging-1.3.0.jar && \
#         wget -q https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/db-fixtures.XXXXXX")

podman run --rm -i -e TZ=UTC -v "$work:/w" -w /w whiff-db bash -euo pipefail <<'EOF'
mkdir -p out/sqlite out/geopackage out/mbtiles out/sqlite_wal out/sqlite_journal out/dbf out/access out/duckdb out/lmdb out/berkeley_db \
    out/leveldb_table out/redis_rdb out/pg_dump out/mysql_frm out/innodb_tablespace out/myisam_index out/h2

# ------------------------------------------------------------------ SQLite
python3 - <<'PY'
import os, random, shutil, sqlite3
random.seed(7)

def tides(db, n=400):
    db.executescript("""
    CREATE TABLE stations(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, lat REAL, lon REAL, opened DATE);
    CREATE TABLE readings(station INTEGER NOT NULL REFERENCES stations(id), at INTEGER, height_m REAL,
                          PRIMARY KEY(station, at)) WITHOUT ROWID;
    CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, station INTEGER, body TEXT, photo BLOB) STRICT;
    CREATE INDEX readings_at ON readings(at);
    CREATE VIEW latest AS SELECT station, max(at) AS at FROM readings GROUP BY station;
    CREATE TRIGGER notes_touch AFTER INSERT ON notes BEGIN SELECT 1; END;
    CREATE VIRTUAL TABLE notes_fts USING fts5(body);
    """)
    for i, name in enumerate(["Saltmere Quay", "Gull Point", "Old Ferry Slip", "Breakwater End"], 1):
        db.execute("INSERT INTO stations VALUES (?,?,?,?,?)", (i, name, 50.1 + i / 100, -4.2 - i / 100, "2025-09-01"))
    for k in range(n):
        db.execute("INSERT INTO readings VALUES (?,?,?)", (k % 4 + 1, 1756684800 + 900 * k, round(2 + random.random() * 3, 2)))
    for k in range(40):
        db.execute("INSERT INTO notes(station, body, photo) VALUES (?,?,?)",
                   (k % 4 + 1, "Calm water, light swell. " * (k % 30 + 1), bytes(range(256)) * (k % 20)))
    db.execute("INSERT INTO notes_fts SELECT body FROM notes")
    db.commit()

db = sqlite3.connect("out/sqlite/saltmere-tides.sqlite")
db.execute("PRAGMA page_size=1024")
db.execute("PRAGMA user_version=7")
db.execute("PRAGMA application_id=1397518932")
tides(db)
db.close()

db = sqlite3.connect("out/sqlite/saltmere-utf16.db")
db.execute("PRAGMA encoding='UTF-16le'")
db.execute("PRAGMA auto_vacuum=INCREMENTAL")
db.execute("CREATE TABLE \"tide tables\"([Station name] TEXT, \"high water\" TEXT, `low water` TEXT)")
db.execute("INSERT INTO \"tide tables\" VALUES ('Mølle Strand', '06:12', '12:31')")
db.commit()
db.close()

# Browser history, Anki and Core Data: the applications' tables, invented rows.
db = sqlite3.connect("out/sqlite/History")
db.executescript("""
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL,
  typed_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER,
  transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL);
""")
for i in range(1, 21):
    t = (1756728000 + 3600 * i + 11644473600) * 1_000_000
    db.execute("INSERT INTO urls VALUES (?,?,?,1,0,?,0)", (i, f"https://tides.saltmere.example/day/{i}", f"Tides day {i}", t))
    db.execute("INSERT INTO visits VALUES (NULL,?,?,0,1,0,0)", (i, t))
db.commit()
db.close()

db = sqlite3.connect("out/sqlite/places.sqlite")
db.executescript("""
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, title LONGVARCHAR);
""")
for i in range(1, 13):
    t = (1756728000 + 7200 * i) * 1_000_000
    db.execute("INSERT INTO moz_places VALUES (?,?,?,1,?)", (i, f"https://ferry.saltmere.example/{i}", f"Ferry {i}", t))
    db.execute("INSERT INTO moz_historyvisits VALUES (NULL,0,?,?,1)", (i, t))
db.execute("INSERT INTO moz_bookmarks VALUES (1,1,1,0,'Timetable')")
db.commit()
db.close()

db = sqlite3.connect("out/sqlite/collection.anki2")
db.executescript("""
CREATE TABLE col(id integer primary key, crt integer not null, mod integer not null, scm integer not null, ver integer not null,
  dty integer not null, usn integer not null, ls integer not null, conf text not null, models text not null,
  decks text not null, dconf text not null, tags text not null);
CREATE TABLE notes(id integer primary key, guid text not null, mid integer not null, mod integer not null, usn integer not null,
  tags text not null, flds text not null, sfld integer not null, csum integer not null, flags integer not null, data text not null);
CREATE TABLE cards(id integer primary key, nid integer not null, did integer not null, ord integer not null, mod integer not null,
  usn integer not null, type integer not null, queue integer not null, due integer not null, ivl integer not null,
  factor integer not null, reps integer not null, lapses integer not null, left integer not null, odue integer not null,
  odid integer not null, flags integer not null, data text not null);
CREATE TABLE revlog(id integer primary key, cid integer not null, usn integer not null, ease integer not null, ivl integer not null,
  lastIvl integer not null, factor integer not null, time integer not null, type integer not null);
""")
for i in range(1, 31):
    db.execute("INSERT INTO notes VALUES (?,?,1,0,0,'','Knot\x1fBowline',0,0,0,'')", (i, f"g{i}"))
    db.execute("INSERT INTO cards VALUES (?,?,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'')", (i, i))
db.commit()
db.close()

db = sqlite3.connect("out/sqlite/HarbourLog.sqlite")
db.executescript("""
CREATE TABLE ZTIDE(Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZHEIGHT FLOAT, ZTIME TIMESTAMP, ZSTATION VARCHAR);
CREATE TABLE ZVESSEL(Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZNAME VARCHAR);
CREATE TABLE Z_PRIMARYKEY(Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
CREATE TABLE Z_METADATA(Z_VERSION INTEGER PRIMARY KEY, Z_UUID VARCHAR(255), Z_PLIST BLOB);
INSERT INTO Z_PRIMARYKEY VALUES (1,'Tide',0,48),(2,'Vessel',0,3);
INSERT INTO Z_METADATA VALUES (1,'7E1C4C2A-0000-4000-8000-5A17E7E00001',x'62706c6973743030');
""")
db.commit()
db.close()

# A WAL file: written while the database is open, before any checkpoint.
db = sqlite3.connect("wal.db")
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA wal_autocheckpoint=0")
db.execute("CREATE TABLE gauge(at INTEGER, height REAL)")
for k in range(3):
    db.executemany("INSERT INTO gauge VALUES (?,?)", [(1756728000 + 60 * i, 2.5) for i in range(200)])
    db.commit()
shutil.copyfile("wal.db-wal", "out/sqlite_wal/saltmere.db-wal")
db.close()

# A rollback journal, copied in the middle of a transaction.
# A tiny page cache makes SQLite spill, and so sync the journal (writing
# its header), before the commit.
db = sqlite3.connect("journal.db")
db.execute("CREATE TABLE gauge(at INTEGER, height REAL)")
db.executemany("INSERT INTO gauge VALUES (?,?)", [(i, 1.0) for i in range(2000)])
db.commit()
db.execute("PRAGMA cache_size=2")
db.execute("BEGIN")
db.execute("UPDATE gauge SET height = 2.0")
db.execute("DELETE FROM gauge WHERE at % 3 = 0")
shutil.copyfile("journal.db-journal", "out/sqlite_journal/saltmere.db-journal")
db.rollback()
db.close()
PY

# GDAL: a GeoPackage, MBTiles from a small raster, SpatiaLite, a shapefile.
cat >buoys.geojson <<'GJ'
{"type": "FeatureCollection", "features": [
 {"type": "Feature", "properties": {"name": "Gull Point buoy", "depth_m": 12.5},
  "geometry": {"type": "Point", "coordinates": [-4.21, 50.12]}},
 {"type": "Feature", "properties": {"name": "Breakwater buoy", "depth_m": 8.0},
  "geometry": {"type": "Point", "coordinates": [-4.25, 50.14]}}]}
GJ
ogr2ogr -f GPKG out/geopackage/saltmere-buoys.gpkg buoys.geojson -nln buoys
gdal_create -of GTiff -outsize 64 64 -bands 3 -burn 30 -burn 90 -burn 160 -a_srs EPSG:3857 \
    -a_ullr -472000 6470000 -468000 6466000 chart.tif
gdal_translate -q -of MBTILES -co NAME="Saltmere chart" -co DESCRIPTION="Harbour approaches" \
    -co ZOOM_LEVEL_STRATEGY=LOWER chart.tif out/mbtiles/saltmere-chart.mbtiles
ogr2ogr -f SQLite -dsco SPATIALITE=YES -dsco INIT_WITH_EPSG=NO out/sqlite/saltmere-buoys.sl3 buoys.geojson -nln buoys
ogr2ogr -f "ESRI Shapefile" -lco ENCODING=UTF-8 shp buoys.geojson -nln buoys
cp shp/buoys.dbf out/dbf/buoys.dbf

# ------------------------------------------------------------------- DBF
python3 - <<'PY'
import datetime, dbf
for name, kind in [("tides-db3.dbf", "db3"), ("tides-fp.dbf", "fp"), ("tides-vfp.dbf", "vfp")]:
    t = dbf.Table(f"out/dbf/{name}", "station C(20); height N(5,2); measured D; calm L; note M", dbf_type=kind, codepage="cp1252")
    t.open(dbf.READ_WRITE)
    for i in range(12):
        t.append((f"Quay {i}", 2 + i / 10, datetime.date(2025, 9, 1 + i), i % 2 == 0, "Light swell"))
    with t[3] as r:
        dbf.delete(r)
    t.close()
PY
# The memo files stay beside the work files: they are not DBF tables.
mkdir -p memo
mv out/dbf/*.dbt out/dbf/*.fpt memo/

# ----------------------------------------------------------------- Access
cat >Make.java <<'JAVA'
import com.healthmarketscience.jackcess.*;
import java.io.File;
import java.time.LocalDateTime;
public class Make {
    public static void main(String[] a) throws Exception {
        for (String[] f : new String[][] {{"V2000", "out/access/saltmere-2000.mdb"}, {"V2016", "extra/saltmere-2016.accdb"}}) {
            Database db = new DatabaseBuilder(new File(f[1])).setFileFormat(Database.FileFormat.valueOf(f[0])).create();
            Table s = new TableBuilder("Stations").addColumn(new ColumnBuilder("ID", DataType.LONG).setAutoNumber(true))
                .addColumn(new ColumnBuilder("Name", DataType.TEXT).setLength(80))
                .addColumn(new ColumnBuilder("Opened", DataType.SHORT_DATE_TIME))
                .addColumn(new ColumnBuilder("Depth", DataType.DOUBLE)).toTable(db);
            Table r = new TableBuilder("Tide Readings").addColumn(new ColumnBuilder("Station", DataType.LONG))
                .addColumn(new ColumnBuilder("At", DataType.SHORT_DATE_TIME))
                .addColumn(new ColumnBuilder("Height", DataType.DOUBLE))
                .addColumn(new ColumnBuilder("Calm", DataType.BOOLEAN))
                .addColumn(new ColumnBuilder("Note", DataType.MEMO)).toTable(db);
            String[] names = {"Saltmere Quay", "Gull Point", "Old Ferry Slip"};
            for (String n : names) s.addRow(Column.AUTO_NUMBER, n, LocalDateTime.of(2025, 9, 1, 0, 0), 12.5);
            for (int i = 0; i < 120; i++) r.addRow(i % 3 + 1, LocalDateTime.of(2025, 9, 1, 0, 0).plusMinutes(15 * i), 2.0 + i % 7 / 10.0, i % 2 == 0, "swell");
            db.close();
        }
    }
}
JAVA
mkdir -p extra
java -cp '/opt/jars/*' Make.java 2>/dev/null

# ------------------------------------------------------------- key/value
python3 -c "
import duckdb
c = duckdb.connect()
c.execute(\"ATTACH 'out/duckdb/saltmere.duckdb' AS h (BLOCK_SIZE 16384)\")
c.execute('CREATE TABLE h.readings AS SELECT range AS at, 2.0 + (range % 7) / 10 AS height FROM range(500)')
c.execute('CHECKPOINT h')
"
printf 'VERSION=3\nformat=print\ntype=btree\nmapsize=1048576\nHEADER=END\n' >lmdb.txt
for i in $(seq 1 50); do printf ' station-%02d\n Saltmere gauge %d\n' "$i" "$i" >>lmdb.txt; done
printf 'DATA=END\n' >>lmdb.txt
mdb_load -n -f lmdb.txt out/lmdb/saltmere.mdb
mv out/lmdb/saltmere.mdb-lock lmdb.lock
for i in $(seq 1 40); do printf 'station-%02d\nSaltmere gauge %d\n' "$i" "$i"; done >bdb.txt
db5.3_load -T -t btree -f bdb.txt out/berkeley_db/saltmere-btree.db
db5.3_load -T -t hash -f bdb.txt out/berkeley_db/saltmere-hash.db
mkdir -p rocks
for i in $(seq 1 60); do echo "station-$i ==> gauge-$i"; done >rocks.txt
ldb --db=rocks --create_if_missing load <rocks.txt >/dev/null
ldb --db=rocks compact >/dev/null
cp "$(ls rocks/*.sst | head -1)" out/leveldb_table/rocksdb-000001.sst
python3 -c "
import plyvel
db = plyvel.DB('level', create_if_missing=True)
for i in range(300):
    db.put(b'station-%03d' % i, b'Saltmere gauge %d' % i)
db.compact_range()
db.close()
"
cp "$(ls level/*.ldb | head -1)" out/leveldb_table/leveldb-000005.ldb

mkdir -p redis
redis-server --port 0 --unixsocket /w/redis/s --dir /w/redis --save '' --daemonize yes >/dev/null
sleep 1
for i in $(seq 1 25); do redis-cli -s /w/redis/s SET "tide:$i" "$i" >/dev/null; done
redis-cli -s /w/redis/s EXPIRE tide:1 86400 >/dev/null
redis-cli -s /w/redis/s SELECT 2 >/dev/null
redis-cli -s /w/redis/s -n 2 HSET gauge:7 height 2.4 >/dev/null
redis-cli -s /w/redis/s SAVE >/dev/null
redis-cli -s /w/redis/s SHUTDOWN NOSAVE >/dev/null || true
cp redis/dump.rdb out/redis_rdb/saltmere.rdb

# --------------------------------------------------------------- servers
PG=/usr/lib/postgresql/17/bin
su postgres -c "$PG/initdb -D /tmp/pg -A trust" >/dev/null
su postgres -c "$PG/pg_ctl -D /tmp/pg -o '-k /tmp -c listen_addresses=' -l /tmp/pg.log start" >/dev/null
sleep 2
su postgres -c "psql -h /tmp -q -c 'CREATE DATABASE harbour'"
su postgres -c "psql -h /tmp -q -d harbour" <<'SQL'
CREATE SCHEMA tides;
CREATE TABLE tides.stations(id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE tides.readings(station int REFERENCES tides.stations, at timestamptz, height numeric(5,2));
CREATE INDEX ON tides.readings(at);
CREATE VIEW tides.latest AS SELECT station, max(at) FROM tides.readings GROUP BY station;
CREATE FUNCTION tides.metres(f numeric) RETURNS numeric AS 'SELECT f * 0.3048' LANGUAGE sql;
INSERT INTO tides.stations(name) VALUES ('Saltmere Quay'), ('Gull Point');
INSERT INTO tides.readings SELECT 1 + i % 2, '2025-09-01'::timestamptz + i * interval '15 min', 2.4 FROM generate_series(1, 200) i;
SQL
su postgres -c "pg_dump -h /tmp -Fc harbour" >out/pg_dump/harbour.dump
su postgres -c "pg_dump -h /tmp -Fc -Z 0 -t tides.stations harbour" >out/pg_dump/harbour-stations-uncompressed.dump
su postgres -c "$PG/pg_ctl -D /tmp/pg stop" >/dev/null

mariadb-install-db --user=root --datadir=/tmp/my --innodb-page-size=4k >/dev/null 2>&1
mariadbd --user=root --datadir=/tmp/my --innodb-page-size=4k --skip-networking --socket=/tmp/my.sock \
    --pid-file=/tmp/my.pid >/tmp/my.log 2>&1 &
for i in $(seq 1 30); do [ -S /tmp/my.sock ] && break; sleep 1; done
mariadb -S /tmp/my.sock -u root <<'SQL'
CREATE DATABASE harbour;
CREATE TABLE harbour.stations(id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(80) NOT NULL) ENGINE=InnoDB;
CREATE TABLE harbour.readings(station INT, at DATETIME, height DECIMAL(5,2), KEY(at)) ENGINE=MyISAM;
CREATE TABLE harbour.log(at DATETIME, msg TEXT) ENGINE=Aria;
INSERT INTO harbour.stations(name) VALUES ('Saltmere Quay'), ('Gull Point');
INSERT INTO harbour.readings VALUES (1, '2025-09-01 06:12', 4.1), (2, '2025-09-01 12:31', 0.9);
FLUSH TABLES;
SQL
# Copied after the shutdown, when InnoDB has written its pages.
mariadb-admin -S /tmp/my.sock -u root shutdown
wait
cp /tmp/my/harbour/stations.frm /tmp/my/harbour/readings.frm out/mysql_frm/
cp /tmp/my/harbour/stations.ibd out/innodb_tablespace/
cp /tmp/my/harbour/readings.MYI out/myisam_index/
cp /tmp/my/harbour/log.MAI out/myisam_index/

cat >h2.sql <<'SQL'
CREATE TABLE stations(id INT PRIMARY KEY, name VARCHAR(80));
INSERT INTO stations VALUES (1, 'Saltmere Quay'), (2, 'Gull Point');
SQL
java -cp /opt/jars/h2-2.2.224.jar org.h2.tools.RunScript -url jdbc:h2:/w/out/h2/saltmere -script h2.sql
EOF

for d in "$work"/out/*/; do
    name=$(basename "$d")
    mkdir -p "$fx/$name"
    cp "$d"* "$fx/$name/"
done
echo "fixtures written; work files are in $work"
