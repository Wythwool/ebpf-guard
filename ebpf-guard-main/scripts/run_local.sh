#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -E "$0" "$@"
fi
make all
./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml "$@"
