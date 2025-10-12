#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y clang llvm make pkg-config libbpf-dev linux-tools-$(uname -r) golang-go bpftool
echo "OK"
