# Fixtures for `csv_geo` (CSV with coordinates (WKT/lat-lon columns))

Files made for whiff's tests for a fictitious harbour (Saltmere Harbour), CC0-1.0 unless the table says otherwise. Regenerate with `scripts/fixtures/geo.sh`.

| File | Origin | Licence |
|---|---|---|
| `buoys-latlon.csv` | craft_geo.py (latitude / longitude) and ogr2ogr -f CSV -lco GEOMETRY=AS_WKT | CC0-1.0 |
| `harbour-wkt.csv` | craft_geo.py (latitude / longitude) and ogr2ogr -f CSV -lco GEOMETRY=AS_WKT | CC0-1.0 |
