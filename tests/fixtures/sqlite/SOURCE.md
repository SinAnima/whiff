# Fixtures for `sqlite` (SQLite database)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour): made with Python's sqlite3 module (SQLite 3.46) and GDAL; the browser, Anki and Core Data files follow those applications' published table layouts with invented rows. Regenerate with `scripts/fixtures/db.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-tides.sqlite` | sqlite3: 1 KiB pages, user version, application ID; a WITHOUT ROWID and a STRICT table, an index, view, trigger and FTS5 table, overflowing rows | CC0-1.0 |
| `saltmere-utf16.db` | sqlite3: UTF-16LE text, incremental auto-vacuum, quoted names | CC0-1.0 |
| `History` | sqlite3: Chromium history tables (urls, visits, downloads) | CC0-1.0 |
| `places.sqlite` | sqlite3: Firefox places tables | CC0-1.0 |
| `collection.anki2` | sqlite3: Anki collection tables | CC0-1.0 |
| `HarbourLog.sqlite` | sqlite3: Core Data tables (Z_PRIMARYKEY, Z_METADATA) | CC0-1.0 |
| `saltmere-buoys.sl3` | ogr2ogr -f SQLite -dsco SPATIALITE=YES | CC0-1.0 |
