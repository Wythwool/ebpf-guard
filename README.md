# ebpf-guard — eBPF runtime detector (exec/open/connect) + rules + Prometheus

## Requirements

* Linux kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`)
* `clang`, `bpftool`, `make`, Go 1.22

## Build and Run

```bash
./scripts/dev_requirements_ubuntu.sh   # one-time setup
make all
sudo ./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml
# without root:
./bin/ebpf-guard -dry-run -prom -json -rules ./configs/rules.sample.yaml
```

Endpoints:

* `GET /healthz`
* `GET /metrics` — Prometheus metrics
* `GET /events` — JSON Lines event stream

## Rule Configuration

See `configs/rules.sample.yaml`.
Supports `comm_re`, `path_re`, `ip_re`, `port_in`, `uid_in`.
Actions: `allow | deny | alert`.
Matching order: **deny → allow → alert**.

## Tests

```bash
make test              # unit tests for rule engine
tests/smoke_local.sh   # build + health check (dry-run mode without root)
```

## Docker

```bash
docker build -t ebpf-guard .
docker run --rm --privileged --pid=host --net=host \
  -v /sys:/sys:ro -v /lib/modules:/lib/modules:ro -v /sys/fs/bpf:/sys/fs/bpf \
  ebpf-guard
```
