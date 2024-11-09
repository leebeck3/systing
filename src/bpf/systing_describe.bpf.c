#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile struct {
	u32 tgid;
} tool_config = {};

#define MAX_STACK_DEPTH 24
#define SKIP_STACK_DEPTH 3

struct event_key {
	u64 waker_tgidpid;
	u64 wakee_tgidpid;
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct event_key);
	__type(value, u64);
	__uint(max_entries, 10240);
} waker_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct event_key);
	__type(value, u64);
	__uint(max_entries, 10240);
} wakee_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} wake SEC(".maps");

SEC("tp_btf/sched_wakeup")
int handle__sched_wakup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	u64 pid = bpf_get_current_pid_tgid();
	u32 tgid = pid >> 32;
	if (tool_config.tgid &&
	    (task->tgid != tool_config.tgid || tgid != tool_config.tgid))
		return 0;
	struct event_key key = {
		.waker_tgidpid = pid,
		.wakee_tgidpid = (u64)task->tgid << 32 | task->pid,
	};
	u64 *value;

	bpf_get_stack(ctx, &key.kernel_stack, sizeof(key.kernel_stack), SKIP_STACK_DEPTH);
	value = bpf_map_lookup_elem(&waker_events, &key);
	if (!value) {
		u64 zero = 0;

		bpf_map_update_elem(&waker_events, &key, &zero, BPF_ANY);
		value = bpf_map_lookup_elem(&waker_events, &key);
		if (!value)
			return 0;
	}
	__sync_fetch_and_add(value, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
