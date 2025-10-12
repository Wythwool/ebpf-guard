#ifndef EBPFGUARD_COMMON_H
#define EBPFGUARD_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define PATH_MAX_LEN 512

struct exec_evt {
    __u64 ts;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    char  filename[PATH_MAX_LEN];
};

struct open_evt {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    int   flags;
    char  comm[TASK_COMM_LEN];
    char  path[PATH_MAX_LEN];
};

struct conn_evt {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 dport;
    __u32 daddr_v4;
    unsigned char daddr_v6[16];
    char  comm[TASK_COMM_LEN];
};

#endif
