#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile struct {
	u32 tgid;
} tool_config = {};

struct event_key {
	u64 waker_tgidpid;
	u64 wakee_tgidpid;
	u64 kernel_stackid;
	u64 user_stackid;
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

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 4 * sizeof(u64));
	__uint(max_entries, 10240);
} kernel_stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 8 * sizeof(u64));
	__uint(max_entries, 10240);
} user_stacks SEC(".maps");

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
		.kernel_stackid = bpf_get_stackid(ctx, &kernel_stacks, BPF_F_REUSE_STACKID),
		.user_stackid = bpf_get_stackid(ctx, &user_stacks, BPF_F_REUSE_STACKID|BPF_F_USER_STACK),
	};
	u64 *value;

	value = bpf_map_lookup_elem(&wake, &key);
	if (!value) {
		u64 zero = 0;

		bpf_map_update_elem(&wake, &key, &zero, BPF_ANY);
		value = bpf_map_lookup_elem(&wake, &key);
		if (!value)
			return 0;
	}
	__sync_fetch_and_add(value, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
