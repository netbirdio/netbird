#!/bin/bash
# Creates a scoped InfluxDB read-only token for Grafana.
# Clients do not need a token — they push via the ingest server.

BUCKET_ID=$(influx bucket list --org netbird --name metrics --json | grep -oP '"id"\s*:\s*"\K[^"]+' | head -1)
ORG_ID=$(influx org list --name netbird --json | grep -oP '"id"\s*:\s*"\K[^"]+' | head -1)

if [[ -z "$BUCKET_ID" ]] || [[ -z "$ORG_ID" ]]; then
  echo "ERROR: Could not determine bucket or org ID" >&2
  echo "BUCKET_ID=$BUCKET_ID ORG_ID=$ORG_ID" >&2
  exit 1
fi

# Create read-only token for Grafana
READ_TOKEN=$(influx auth create \
  --org netbird \
  --read-bucket "$BUCKET_ID" \
  --description "Grafana read-only token" \
  --json | grep -oP '"token"\s*:\s*"\K[^"]+' | head -1)

echo ""
echo "============================================"
echo "GRAFANA READ-ONLY TOKEN:"
echo "$READ_TOKEN"
echo "============================================"