#!/usr/bin/env bash
# Drive the full SNARK setup pipeline. Logs to /tmp/openac-setup-all.log and
# emits a one-line marker per phase so we can tail-watch progress.
#
# Order is chosen to fail fast: Show keys (small, ~3 MB each, ~5 min total)
# first, then Prepare keys ordered smallest-to-largest so 1k smoke can run
# while 2k/4k/8k are still going if you want to parallelize later.

set -euo pipefail

cd "$(dirname "$0")"

LOG=/tmp/openac-setup-all.log
> "$LOG"

run() {
  local label="$1"; shift
  echo "[$(date '+%H:%M:%S')] BEGIN $label" | tee -a "$LOG"
  if "$@" >> "$LOG" 2>&1; then
    echo "[$(date '+%H:%M:%S')] OK    $label" | tee -a "$LOG"
  else
    echo "[$(date '+%H:%M:%S')] FAIL  $label" | tee -a "$LOG"
    return 1
  fi
}

# Show keys for all sizes (fast — Show PK is ~3 MB per size).
for s in 1k 2k 4k 8k; do
  run "show setup $s" cargo run --release -- show setup --size "$s"
done

# Prepare keys, ordered smallest to largest.
for s in 1k 2k 4k 8k; do
  run "prepare setup $s" cargo run --release -- prepare setup --size "$s"
done

# Mdoc setup (single-size).
run "mdoc setup" cargo run --release -- mdoc setup

echo "[$(date '+%H:%M:%S')] ALL DONE" | tee -a "$LOG"
ls -lh keys/ | tee -a "$LOG"
