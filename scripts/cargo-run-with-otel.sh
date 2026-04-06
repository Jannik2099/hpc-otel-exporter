#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [args...]" >&2
  exit 2
fi

BIN="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "docker-compose.yml not found at $COMPOSE_FILE" >&2
  exit 1
fi

podman compose -f "$COMPOSE_FILE" up -d

exec sudo env \
  OTEL_SERVICE_NAME=hpc-otel-exporter \
  OTEL_METRICS_EXPORTER=otlp \
  OTEL_EXPORTER_OTLP_PROTOCOL=grpc \
  OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317 \
  OTEL_METRIC_EXPORT_INTERVAL=5000 \
  "$BIN" "$@"