// exec.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_exec SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct exec_evt *e = bpf_ringbuf_reserve(&events_exec, sizeof(*e), 0);
    if (!e) return 0;
    e->ts = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->ppid = bpf_get_current_ppid();
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // filename can be long; tracepoint has pointer in ctx->filename
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void*)ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
