// open.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_open SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_open(struct trace_event_raw_sys_enter *ctx) {
    struct open_evt *e = bpf_ringbuf_reserve(&events_open, sizeof(*e), 0);
    if (!e) return 0;
    e->ts = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->flags = (int)ctx->args[2];
    const char *up = (const char*)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), up);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
