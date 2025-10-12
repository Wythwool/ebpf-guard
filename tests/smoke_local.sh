#!/usr/bin/env bash
set -euo pipefail
make all
if [[ $EUID -ne 0 ]]; then
  echo "Not root: starting dry-run for 2s"; ./bin/ebpf-guard -dry-run & pid=$!
else
  ./bin/ebpf-guard & pid=$!
fi
sleep 2
curl -fsS http://127.0.0.1:9108/healthz >/dev/null
curl -fsS http://127.0.0.1:9108/metrics | head -n1 >/dev/null
kill $pid || true
echo "OK"
