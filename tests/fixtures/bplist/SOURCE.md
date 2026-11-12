# Fixtures for `bplist` (Apple plist (binary))

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour) with fixed times; names, devices, teams and addresses (`example.org`) are fictitious. Regenerate with `scripts/fixtures/apple.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-prefs.plist` | plutil -convert binary1 | CC0-1.0 |
| `harbour-state.plist` | NSKeyedArchiver (Swift, Foundation) | CC0-1.0 |
| `saltmere-shanty-metadata.plist` | GarageBand `MetaData.plist` keys, written with plistlib (scripts/fixtures/gaps5f.sh) | CC0-1.0 |
