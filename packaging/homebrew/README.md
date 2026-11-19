# Homebrew formula

Source of truth for the formula. On each release the `update-packaging` job
in `.github/workflows/release.yml` fills in the version and checksums (from the
release's `SHA256SUMS`, with `scripts/update-packaging.sh`) and pushes it to
[`SinAnima/homebrew-tap`](https://github.com/SinAnima/homebrew-tap) as
`Formula/whiff.rb`. The copy here keeps the checksums of the last release
it was committed with.

```bash
brew install SinAnima/tap/whiff
```
