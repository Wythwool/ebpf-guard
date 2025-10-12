#!/usr/bin/env bash
set -euo pipefail
make all
if [[ $EUID -ne 0 ]]; then
  echo "Not root: running in dry-run mode (HTTP only)"
  ./bin/ebpf-guard -dry-run -prom -json -rules ./configs/rules.sample.yaml
else
  sudo -E ./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml
fi
