# Fixtures for `f3` (F3 (Future-proof File Format))

Files made for whiff's tests, CC0-1.0: Saltmere Harbour tide readings. Regenerate with `scripts/fixtures/f3.sh`.

| File | Origin | Licence |
|---|---|---|
| `readings.f3` | F3 reference writer (`fff-poc`, commit bd92506), one row group | CC0-1.0 |
| `readings-groups.f3` | F3 reference writer (`fff-poc`, commit bd92506), row-group threshold 100: the one 300-row batch closes a 300-row group, and `finish` closes a second, empty one | CC0-1.0 |
