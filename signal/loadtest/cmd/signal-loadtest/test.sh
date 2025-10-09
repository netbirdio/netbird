#!/bin/bash
set -e

echo "Building signal-loadtest binary..."
go build -o signal-loadtest

echo ""
echo "=== Test 1: Single message exchange (5 pairs) ==="
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 5 \
  -total-pairs 5 \
  -message-size 50 \
  -log-level info

echo ""
echo "=== Test 2: Continuous exchange (3 pairs, 5 seconds) ==="
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 3 \
  -total-pairs 3 \
  -message-size 100 \
  -exchange-duration 5s \
  -message-interval 200ms \
  -log-level info

echo ""
echo "All tests completed!"
