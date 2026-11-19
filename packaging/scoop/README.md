# Scoop manifest

Source of truth for the manifest. On each release the `update-packaging` job
in `.github/workflows/release.yml` fills in the version and hash (with
`scripts/update-packaging.sh`) and pushes `whiff.json` to
[`SinAnima/scoop-bucket`](https://github.com/SinAnima/scoop-bucket).

```powershell
scoop bucket add sinanima https://github.com/SinAnima/scoop-bucket
scoop install whiff
```
