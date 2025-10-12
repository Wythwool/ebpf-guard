// connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_connect SEC(".maps");

static __always_inline __u16 bswap16(__u16 v){ return (v<<8) | (v>>8); }

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx) {
    struct conn_evt *e = bpf_ringbuf_reserve(&events_connect, sizeof(*e), 0);
    if (!e) return 0;

    e->ts  = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const struct sockaddr *us = (const struct sockaddr*)ctx->args[1];
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &us->sa_family);
    e->family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), us);
        e->dport = bswap16(sin.sin_port);
        e->daddr_v4 = (__u32)sin.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), us);
        e->dport = bswap16(sin6.sin6_port);
        __builtin_memcpy(e->daddr_v6, sin6.sin6_addr.s6_addr, 16);
    } else {
        e->dport = 0;
        e->daddr_v4 = 0;
        __builtin_memset(e->daddr_v6, 0, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
