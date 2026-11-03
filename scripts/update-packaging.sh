#!/usr/bin/env bash
# After a release: set the version and checksums in the Homebrew formula and
# the Scoop manifest from the release's SHA256SUMS. The release workflow runs
# this and pushes the results to baoulo/homebrew-tap and baoulo/scoop-bucket;
# run it by hand only to recover from a failed release.
#
#   scripts/update-packaging.sh 0.7.0
#   SUMS_FILE=SHA256SUMS scripts/update-packaging.sh 0.7.0   # use a local file
set -euo pipefail

VERSION="${1:?usage: $0 <version>}"
VERSION="${VERSION#v}"
TAG="v${VERSION}"
REPO="baoulo/whiff"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMULA="${ROOT}/packaging/homebrew/whiff.rb"
SCOOP="${ROOT}/packaging/scoop/whiff.json"

sums="$(mktemp)"
trap 'rm -f "${sums}"' EXIT
if [[ -n "${SUMS_FILE:-}" ]]; then
  cp "${SUMS_FILE}" "${sums}"
else
  curl -fsSL "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS" -o "${sums}"
fi

sum_for() {
  local file="whiff-${TAG}-$1"
  local sum
  sum="$(awk -v f="${file}" '$2 == f || $2 == "*" f { print $1 }' "${sums}")"
  if [[ ! "${sum}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: no SHA-256 for ${file} in SHA256SUMS" >&2
    exit 1
  fi
  echo "${sum}"
}

# Homebrew: the line after each platform's `url` is its `sha256`.
tmp="$(mktemp)"
awk -v version="${VERSION}" \
  -v mac_arm="$(sum_for macos-aarch64.tar.gz)" -v mac_intel="$(sum_for macos-x86_64.tar.gz)" \
  -v linux_arm="$(sum_for linux-aarch64.tar.gz)" -v linux_intel="$(sum_for linux-x86_64.tar.gz)" '
  /^  version "/ { print "  version \"" version "\""; next }
  pending != "" { sub(/^ *#? *sha256 .*/, "      sha256 \"" pending "\""); print; pending = ""; next }
  /url .*macos-aarch64/ { pending = mac_arm }
  /url .*macos-x86_64/ { pending = mac_intel }
  /url .*linux-aarch64/ { pending = linux_arm }
  /url .*linux-x86_64/ { pending = linux_intel }
  { print }
' "${FORMULA}" > "${tmp}"
mv "${tmp}" "${FORMULA}"
sed -i.bak '/# Copy to your tap as Formula\/whiff.rb and fill sha256 from Release SHA256SUMS./d' "${FORMULA}"
rm -f "${FORMULA}.bak"

# Scoop: version, URL and hash of the 64-bit build.
win="$(sum_for windows-x86_64.zip)"
sed -i.bak -E \
  -e "s/^  \"version\": \"[^\"]*\"/  \"version\": \"${VERSION}\"/" \
  -e "s#releases/download/v[0-9][^/]*/whiff-v[0-9][^\"]*-windows-x86_64.zip#releases/download/${TAG}/whiff-${TAG}-windows-x86_64.zip#" \
  -e "s/\"hash\": \"[^\"]*\"/\"hash\": \"${win}\"/" \
  "${SCOOP}"
rm -f "${SCOOP}.bak"

echo "Updated for ${TAG}:"
echo "  ${FORMULA#"${ROOT}/"}"
echo "  ${SCOOP#"${ROOT}/"}"
