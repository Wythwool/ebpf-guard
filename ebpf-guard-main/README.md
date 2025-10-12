ebpf-guard
==========

ebpf-guard is a host agent that watches process execution, file opens, and outbound connections via eBPF CO-RE programs. It applies YAML-defined rules, exports Prometheus metrics, and can stream JSON events for integrations.

Features
--------
* Sensors: `exec`, `open`, and `connect` tracepoints with ring buffer delivery.
* Rule engine with allow/deny/alert/observe actions and regex/UID/port/IP matchers.
* Prometheus `/metrics` and optional JSONL `/events` stream.
* Hot reload of rules with `SIGHUP`.
* Ready-to-use scripts for local development, Docker, systemd, and Kubernetes DaemonSet.

Requirements
------------
* Linux kernel 5.8 or newer with BTF.
* `clang`, `llvm`, `bpftool`, `make`, `go` 1.22.
* Root privileges (or `CAP_BPF` et al.) to attach tracepoints.

Quick start
-----------
```
./scripts/dev_requirements_ubuntu.sh
make all
sudo ./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml
```

`/metrics` exposes counters including `ebpf_guard_events_total`, `ebpf_guard_rule_matches_total`, `ebpf_guard_ringbuf_dropped_total`, `ebpf_guard_attach_errors_total`, and gauge `ebpf_guard_sensors_attached`.

Rules
-----
Rules are provided in YAML; see `configs/rules.sample.yaml`. Each rule contains a `name`, optional `match` filters (`comm_re`, `path_re`, `ip_re`, `port_in`, `uid_in`), an `action` (`allow`, `deny`, `alert`, `observe`), and an optional `reason`.

Docker
------
```
docker build -t ebpf-guard .
docker run --rm -it --privileged \
  -v /sys:/sys -v /proc:/proc -v /lib/modules:/lib/modules \
  -p 9108:9108 ebpf-guard
```

Kubernetes
----------
Apply the DaemonSet from `deploy/k8s/daemonset.yaml`. It runs privileged with necessary mounts and exposes port 9108 on each node.

systemd
-------
Install `deploy/systemd/ebpf-guard.service` and place rules at `/etc/ebpf-guard/rules.yaml`:
```
sudo cp bin/ebpf-guard /usr/local/bin/
sudo mkdir -p /etc/ebpf-guard
sudo cp configs/rules.sample.yaml /etc/ebpf-guard/rules.yaml
sudo cp deploy/systemd/ebpf-guard.service /etc/systemd/system/
sudo systemctl enable --now ebpf-guard
```
