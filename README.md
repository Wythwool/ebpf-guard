# ebpf-guard — eBPF runtime detector (proc/opens/net) + rules + Prometheus

**What:** host/k8s agent that taps exec/open/connect with eBPF, runs simple rules, emits JSON alerts and Prometheus metrics.

**Why:** eBPF is the runtime-security standard. This is a compact, readable MVP that still hits production‑like signals.

## Sensors (MVP)
- **exec**: tracepoint `sched_process_exec` (pid, ppid, comm, filename).
- **open**: tracepoint `sys_enter_openat` (pid, path, flags).
- **connect**: tracepoint `sys_enter_connect` (pid, daddr, dport, family).

## Build (Ubuntu, kernel >= 5.8, clang + bpftool + Go)
```bash
sudo apt-get install -y clang llvm make pkg-config libbpf-dev linux-tools-$(uname -r)
# vmlinux.h for CO-RE:
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

make                         # builds bpf/*.o and agent
sudo ./bin/ebpf-guard --rules ./rules/default_rules.yaml --addr :9100
# metrics -> http://localhost:9100/metrics
```

## Kubernetes (daemonset example)
```bash
# minimal example (privileged). Adapt to your cluster and security policies.
kubectl apply -f deployment/daemonset.yaml
```

## Outputs
- **Prometheus**: `/metrics` — `ebg_events_total{type=...}`, `ebg_alerts_total{rule=...}`.
- **JSON alerts**: to stdout (or `--json-out` file).

## Rules
YAML with small DSL: match by `proc_comm`, `path_re`, `argv_re`, `port_in`, `ip_re`, `uid_in`. See `rules/default_rules.yaml`.