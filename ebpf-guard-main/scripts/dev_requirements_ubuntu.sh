#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y clang llvm bpftool make golang
