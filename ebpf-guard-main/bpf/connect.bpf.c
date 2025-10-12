#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_connect SEC(".maps");

static __inline __u16 ntohs(__u16 net)
{
    return (__u16)__builtin_bswap16(net);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct conn_evt *evt = bpf_ringbuf_reserve(&events_connect, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    evt->ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    const struct sockaddr *us = (const struct sockaddr *)ctx->args[1];
    __u16 family = 0;
    if (us)
        bpf_probe_read_user(&family, sizeof(family), &us->sa_family);
    evt->family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), us);
        evt->dport = ntohs(sin.sin_port);
        evt->daddr_v4 = sin.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), us);
        evt->dport = ntohs(sin6.sin6_port);
        __builtin_memcpy(evt->daddr_v6, &sin6.sin6_addr, sizeof(evt->daddr_v6));
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
