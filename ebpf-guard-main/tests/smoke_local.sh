#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "skip: requires root" >&2
  exit 0
fi
make all
logfile=$(mktemp)
trap 'rm -f "$logfile"; [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true' EXIT
./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml >"$logfile" 2>&1 &
pid=$!
sleep 6
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if ! grep -q "sensor exec attached" "$logfile"; then
  cat "$logfile"
  exit 1
fi
