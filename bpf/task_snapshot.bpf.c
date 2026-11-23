#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct ghostscan_task_key {
    /* Local tgid plus the PID namespace that assigned it. */
    __u32 pid;
    __u32 pidns_inum;
};

struct ghostscan_task_value {
    char comm[TASK_COMM_LEN];
    __u32 pid;
    __u32 pidns_inum;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ghostscan_task_key);
    __type(value, struct ghostscan_task_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ghostscan_task_pids SEC(".maps");

static __always_inline __u64 task_pid_identity(struct task_struct *task)
{
    struct task_struct *leader = NULL;
    struct pid *pid = NULL;
    struct pid_namespace *pid_ns = NULL;
    struct upid upid = {};
    char *numbers = NULL;
    unsigned int level = 0;
    __u32 pidns_inum = 0;

    BPF_CORE_READ_INTO(&leader, task, group_leader);
    if (!leader) {
        leader = task;
    }

    BPF_CORE_READ_INTO(&pid, leader, thread_pid);
    if (!pid) {
        return 0;
    }

    BPF_CORE_READ_INTO(&level, pid, level);
    if (level > 31) {
        return 0;
    }

    /* struct pid::numbers[level] is the PID as seen in the active namespace. */
    numbers = (char *)pid + bpf_core_field_offset(struct pid, numbers);
    if (bpf_probe_read_kernel(&upid, sizeof(upid),
                              numbers + level * sizeof(struct upid)) < 0) {
        return 0;
    }
    if (upid.nr <= 0 || !upid.ns) {
        return 0;
    }
    pid_ns = upid.ns;

    pidns_inum = BPF_CORE_READ(pid_ns, ns.inum);
    if (!pidns_inum) {
        return 0;
    }

    return ((__u64)pidns_inum << 32) | (__u32)upid.nr;
}

SEC("iter/task")
int ghostscan_iter_task(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    if (!task) {
        return 0;
    }

    __u64 identity = task_pid_identity(task);
    if (!identity) {
        return 0;
    }
    __u32 pid = (__u32)identity;
    __u32 pidns_inum = (__u32)(identity >> 32);

    struct ghostscan_task_value entry = {};
    entry.pid = pid;
    entry.pidns_inum = pidns_inum;
    if (BPF_CORE_READ_STR_INTO(&entry.comm, task, comm) < 0) {
        entry.comm[0] = '\0';
    }

    struct ghostscan_task_key key = {
        .pid = pid,
        .pidns_inum = pidns_inum,
    };
    bpf_map_update_elem(&ghostscan_task_pids, &key, &entry, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
