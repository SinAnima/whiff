# Fixtures for `parquet` (Apache Parquet)

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour): tide readings and tiny models with made-up weights. Regenerate with `scripts/fixtures/columnar.sh`.

| File | Origin | Licence |
|---|---|---|
| `readings-pandas-zstd.parquet` | pyarrow 26.0.0 (snappy, row groups of 50) and pandas 3.1.0 (zstd, with index) | CC0-1.0 |
| `readings-snappy.parquet` | pyarrow 26.0.0 (snappy, row groups of 50) and pandas 3.1.0 (zstd, with index) | CC0-1.0 |
