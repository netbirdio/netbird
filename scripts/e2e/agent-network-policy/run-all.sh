#!/usr/bin/env bash
# run-all: every numbered test in order, halts on first FAIL,
# prints a `=== PASS x/y ===` summary. -k keeps state (skips
# 99-cleanup) so you can poke around the persisted policy /
# consumption rows afterwards.

set -uo pipefail

KEEP=0
[ "${1:-}" = "-k" ] && KEEP=1
export NB_KEEP_STATE="$KEEP"

cd "$(dirname "$0")"

scripts=(
    01-tilt-restart.sh
    10-policy-create.sh
    20-policy-rejects-zero-window.sh
    30-consumption-list-empty.sh
    40-grpc-record-and-list.sh
    50-grpc-allow-record-deny.sh
)
[ "$KEEP" -eq 0 ] && scripts+=(99-cleanup.sh)

passed=0
total=${#scripts[@]}

trap '[ "$KEEP" -eq 0 ] && bash ./99-cleanup.sh >/dev/null 2>&1 || true' EXIT

for s in "${scripts[@]}"; do
    echo
    echo "==================== $s ===================="
    if bash "./$s"; then
        passed=$((passed + 1))
    else
        rc=$?
        echo
        echo "=== FAIL $passed/$total ($s exit=$rc) ==="
        exit "$rc"
    fi
done

echo
echo "=== PASS $passed/$total ==="
