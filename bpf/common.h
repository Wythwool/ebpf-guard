#pragma once
// only what's needed
#include <linux/types.h>

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  256

struct exec_evt {
    __u64 ts;
    __u32 pid, ppid, uid;
    char  comm[TASK_COMM_LEN];
    char  filename[PATH_MAX_LEN];
};

struct open_evt {
    __u64 ts;
    __u32 pid, uid;
    int   flags;
    char  comm[TASK_COMM_LEN];
    char  path[PATH_MAX_LEN];
};

struct conn_evt {
    __u64 ts;
    __u32 pid, uid;
    __u16 family;
    __u16 dport;
    __u32 daddr_v4;
    char  comm[TASK_COMM_LEN];
};
