#!/usr/bin/env bash
# Local checks that mirror .github/workflows/ci.yml
# (fmt, clippy, test, docs, coverage, repo checks, each-feature, MSRV, wasm,
# deny/audit, Miri with MIRI=1, fuzz smoke). Optional tools are skipped with
# an install hint.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MSRV="1.89"
SKIPPED=()

run() {
  echo ""
  echo "==> $*"
  "$@"
}

skip() {
  echo ""
  echo "==> $1 (skipped — $2)"
  SKIPPED+=("$1")
}

has_toolchain() {
  rustup toolchain list 2>/dev/null | grep -q "^$1"
}

# --- lint -------------------------------------------------------------------
run cargo fmt --all -- --check
(cd fuzz && run cargo fmt -- --check)
# CI lints with the latest stable, whose clippy has lints an older local
# toolchain lacks: use the newest numbered rustup toolchain for this host
# (LINT_TOOLCHAIN overrides), through its own cargo as for MSRV below.
HOST="$(rustup show 2>/dev/null | awk '/^Default host/ {print $3}')"
LINT_TC="${LINT_TOOLCHAIN:-$(rustup toolchain list 2>/dev/null | awk '{print $1}' |
  grep -E "^1\.[0-9]+(\.[0-9]+)?-${HOST}\$" | sort -V | tail -1 || true)}"
if [ -n "$LINT_TC" ]; then
  LINT_BIN="$(dirname "$(rustup which --toolchain "$LINT_TC" cargo)")"
  echo ""
  echo "==> clippy with $LINT_TC (check it is the latest stable: rustup check)"
  lint() { PATH="$LINT_BIN:$PATH" CARGO_TARGET_DIR=target/lint run "$LINT_BIN/cargo" "$@"; }
else
  lint() { run cargo "$@"; }
fi
lint clippy --all-targets --features dev -- -D warnings
lint clippy --all-targets --no-default-features --features common -- -D warnings

# --- test (`dev` implies `full`: every extractor, the CLI and whiff-dev) -----
run cargo test --features dev
run cargo test --no-default-features --features common --lib --tests
RUSTDOCFLAGS="-D warnings" run cargo doc --no-deps --all-features

# --- coverage ---------------------------------------------------------------
echo ""
echo "==> cargo llvm-cov (CI gate: ≥80% lines)"
if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "error: cargo-llvm-cov is required. Install with:" >&2
  echo "  rustup component add llvm-tools-preview" >&2
  echo "  cargo install cargo-llvm-cov" >&2
  exit 1
fi
if ! cargo llvm-cov --features dev --lcov --output-path lcov.info \
  --ignore-filename-regex 'src/main\.rs|src/bin/' \
  --fail-under-lines 80; then
  echo "error: line coverage is below 80% — CI Coverage will fail." >&2
  exit 1
fi

# --- repo checks: catalogue, dependency budget, plugin boundary --------------
run cargo run -q --features dev --bin whiff-dev -- catalogue --check
run cargo run -q --features dev --bin whiff-dev -- check-deps
run cargo run -q --features dev --bin whiff-dev -- check-boundary

# --- the published crate: Rust only, no development tooling ------------------
# Development may use any tool (scripts/, the fixture generators, fuzz/);
# none of it may reach crates.io. check-deps above covers the dependencies.
echo ""
echo "==> published crate holds no development tooling"
packaged=$(cargo package --list --allow-dirty --locked)
dev_files=$(grep -E '^(scripts|fuzz|tests|benches|baoulo|packaging|\.github)/' <<<"$packaged" || true)
foreign=$(grep -vE '\.(rs|toml|lock|md|txt|tsv|json)$|^(LICENSE[^/]*|Cargo\.toml\.orig|\.cargo_vcs_info\.json|\.gitattributes|\.gitignore)$' <<<"$packaged" || true)
if [ -n "$dev_files$foreign" ]; then
  echo "error: these files would be published:" >&2
  printf '%s\n' "$dev_files" "$foreign" | sed '/^$/d; s/^/  /' >&2
  echo "add them to \`exclude\` in Cargo.toml" >&2
  exit 1
fi

# --- fixtures: what git stores must be what the tests read -------------------
# Line-ending conversion would silently change test inputs (CRLF fixtures).
echo ""
echo "==> fixtures stored byte-exact by git"
changed=()
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  cmp -s <(git show ":$f") "$f" || changed+=("$f")
done < <(git ls-files tests/fixtures)
if [ ${#changed[@]} -gt 0 ]; then
  echo "error: git would store these fixtures differently from the working tree:" >&2
  printf '  %s\n' "${changed[@]}" >&2
  echo "run: git add --renormalize tests/fixtures" >&2
  exit 1
fi

# --- each feature on its own -------------------------------------------------
if cargo hack --version >/dev/null 2>&1; then
  CARGO_TARGET_DIR=target/hack RUSTFLAGS="-D warnings" run cargo hack check --each-feature --no-dev-deps
else
  skip "cargo hack check --each-feature" "install with: cargo install cargo-hack"
fi

# --- MSRV ------------------------------------------------------------------
if has_toolchain "$MSRV"; then
  # Call the toolchain's own cargo: version-manager shims (asdf, mise) on PATH
  # would otherwise intercept `rustc` under `rustup run`.
  MSRV_BIN="$(dirname "$(rustup which --toolchain "$MSRV" cargo)")"
  PATH="$MSRV_BIN:$PATH" CARGO_TARGET_DIR=target/msrv RUSTFLAGS="-D warnings" \
    run "$MSRV_BIN/cargo" check --features full,cli
else
  skip "MSRV $MSRV check" "install with: rustup toolchain install $MSRV --profile minimal"
fi

# --- wasm --------------------------------------------------------------------
# Any rustup toolchain with the target will do; its own cargo is called so a
# version-manager shim on PATH cannot pick a toolchain without it.
WASM_TC=""
for tc in $(rustup toolchain list 2>/dev/null | awk '{print $1}'); do
  if rustup target list --installed --toolchain "$tc" 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    WASM_TC="$tc"
    break
  fi
done
if [ -n "$WASM_TC" ]; then
  WASM_BIN="$(dirname "$(rustup which --toolchain "$WASM_TC" cargo)")"
  PATH="$WASM_BIN:$PATH" CARGO_TARGET_DIR=target/wasm RUSTFLAGS="-D warnings" \
    run "$WASM_BIN/cargo" build --lib --target wasm32-unknown-unknown --no-default-features --features full
else
  skip "wasm32 build" "install with: rustup target add wasm32-unknown-unknown"
fi

# --- licences and advisories --------------------------------------------------
run cargo deny check

if cargo audit --version >/dev/null 2>&1; then
  run cargo audit
else
  skip "cargo audit" "install with: cargo install cargo-audit"
fi

# --- Miri (opt-in locally: about 3 minutes) -------------------------------------
if [ "${MIRI:-0}" = 1 ]; then
  run scripts/miri.sh
else
  skip "Miri" "run with MIRI=1 scripts/ci.sh, or scripts/miri.sh"
fi

# --- fuzz smoke ------------------------------------------------------------------
if has_toolchain nightly && cargo fuzz --version >/dev/null 2>&1; then
  NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
  (cd fuzz && PATH="$NIGHTLY_BIN:$PATH" RUSTFLAGS="" \
    run "$NIGHTLY_BIN/cargo" fuzz run extract -- -max_total_time="${FUZZ_SECONDS:-60}")
else
  skip "fuzz smoke" "install with: rustup toolchain install nightly && cargo install cargo-fuzz"
fi

echo ""
if [ ${#SKIPPED[@]} -eq 0 ]; then
  echo "All CI checks passed."
else
  echo "All CI checks passed, except ${#SKIPPED[@]} skipped (CI still runs them):"
  printf '  - %s\n' "${SKIPPED[@]}"
fi
