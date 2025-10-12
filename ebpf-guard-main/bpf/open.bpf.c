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
int handle_open(struct trace_event_raw_sys_enter *ctx)
{
    struct open_evt *evt = bpf_ringbuf_reserve(&events_open, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    const char *pathname = (const char *)ctx->args[1];
    evt->flags = (int)ctx->args[2];
    if (!pathname) {
        pathname = (const char *)ctx->args[2];
        evt->flags = (int)ctx->args[3];
    }
    bpf_probe_read_user_str(evt->path, sizeof(evt->path), pathname);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
