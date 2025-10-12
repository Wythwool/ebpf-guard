#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_exec SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_evt *evt = bpf_ringbuf_reserve(&events_exec, sizeof(*evt), 0);
    if (!evt)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = 0;
    if (task)
        BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

    evt->ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->ppid = ppid;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), (void *)ctx->filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
