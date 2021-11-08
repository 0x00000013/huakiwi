#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("kprobe/sys_execve")
int kprobe_execve()
{
    u32 key = 0;
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&kprobe_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}

// SECOND ONE
struct event_t
{
    u32 pid;
    u32 gid;
    char str[80];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx)
{
    struct event_t event;

    event.pid = bpf_get_current_pid_tgid();
    event.gid = bpf_get_current_uid_gid();
    bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// THIRD ONE

const u32 MAX_ARGV = 128;

struct bpf_map_def SEC("maps") argvs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(char[128]),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") envs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(char[128]),
    .max_entries = 256,
};

struct event_execv
{
    u32 pid;
    u32 gid;
    u32 arg_length;
    u32 env_length;
    char cmd[80];
    //todo: time packets in packets out
};

struct execve_args
{
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_event(struct execve_args *ctx)
{
    struct event_execv event;

    event.pid = bpf_get_current_pid_tgid();
    event.gid = bpf_get_current_uid_gid();

    int comm = bpf_get_current_comm(&event.cmd, sizeof(event.cmd));
    if (comm != 0)
    {
        return -1;
    }

    u32 cnt = 0;
    for (u32 i = 0; i < MAX_ARGV; i++) {
        char *first_var;
        char value[300] = "";
        if (!bpf_probe_read(&first_var, sizeof(first_var), &ctx->argv[cnt])) {
            if (bpf_probe_read_str(value, sizeof(value), first_var) > 0)
                bpf_map_update_elem(&argvs, &cnt, &value, BPF_ANY);
            else break;
        } else break;
        cnt++;
    }
    event.arg_length = cnt;

    cnt = 0;
    for (u32 i = 0; i < MAX_ARGV; i++) {
        char *first_var;
        char value[300] = "";
        if (!bpf_probe_read(&first_var, sizeof(first_var), &ctx->envp[cnt])) {
            if (bpf_probe_read_str(value, sizeof(value), first_var) > 0)
                bpf_map_update_elem(&envs, &cnt, &value, BPF_ANY);
            else break;
        } else break;
        cnt++;
    }
    event.env_length = cnt;

    // bpf_probe_read_str(&event.args, sizeof(event.args), first_env_var);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}
