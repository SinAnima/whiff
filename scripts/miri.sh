#!/usr/bin/env bash
# Miri on the unit tests of the layers below the format parsers: containers
# and codecs (`container`), embedded metadata (`meta`), text (`text`) and
# detection (`detect`).
#
# whiff forbids unsafe code, so what this checks is the unsafe and SIMD code
# of the dependencies those tests reach (memchr, aho-corasick, encoding_rs,
# chardetng, regex, hashbrown, the decompressors) for undefined behaviour.
# Tests that read fixtures from disk or run to a large limit are marked
# `#[cfg_attr(miri, ignore = "…")]`.
#
# Miri interprets for aarch64 Linux on every host (`MIRI_TARGET` overrides).
# On x86_64 the run cannot pass: encoding_rs detects AVX2 through
# core_detect, whose `cpuid` inline assembly Miri cannot execute, and with
# AVX2 enabled at compile time simdutf8 0.1.5 computes its prefetch pointer
# past the end of the input (`add` where `wrapping_add` is needed; harmless
# in practice, but undefined behaviour to Miri).
#
#   scripts/miri.sh                 # the four modules
#   scripts/miri.sh container::zip  # narrower test filters
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  echo "error: Miri needs a nightly toolchain:" >&2
  echo "  rustup toolchain install nightly --component miri,rust-src" >&2
  exit 1
fi
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
if [ ! -x "$NIGHTLY_BIN/cargo-miri" ]; then
  echo "error: Miri is not installed:" >&2
  echo "  rustup component add miri rust-src --toolchain nightly" >&2
  exit 1
fi

if [ $# -eq 0 ]; then
  set -- container:: meta:: text:: detect::
fi

# The nightly cargo goes first on PATH: asdf or other shims would otherwise
# answer for rustc. `formats::` is skipped because filters match anywhere in
# a test's path (`formats::score::text::…` contains `text::`).
PATH="$NIGHTLY_BIN:$PATH" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/miri}" RUSTFLAGS="" \
  "$NIGHTLY_BIN/cargo" miri test --lib --target "${MIRI_TARGET:-aarch64-unknown-linux-gnu}" -- "$@" --skip formats::
