#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [args...]" >&2
  exit 2
fi

BIN="$1"
shift

# Test binaries live in target/.../deps/; skip OTel wrapper for them.
if [[ "$BIN" == */deps/* ]]; then
  exec "$BIN" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "docker-compose.yml not found at $COMPOSE_FILE" >&2
  exit 1
fi

podman compose -f "$COMPOSE_FILE" up -d

exec sudo systemd-run --scope \
  -E OTEL_SERVICE_NAME=hpc-otel-exporter \
  -E OTEL_METRICS_EXPORTER=otlp \
  -E OTEL_TRACES_EXPORTER=otlp \
  -E OTEL_LOGS_EXPORTER=otlp \
  -E OTEL_EXPORTER_OTLP_PROTOCOL=grpc \
  -E OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317 \
  -E OTEL_METRIC_EXPORT_INTERVAL=5000 \
  "$BIN" "$@"