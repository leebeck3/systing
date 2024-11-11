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
	__type(value, struct event_key);
	__uint(max_entries, 10240);
} wakee SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} wake SEC(".maps");

static __always_inline
void update_count(struct event_key *key, void *map)
{
	u64 *value;

	value = bpf_map_lookup_elem(map, key);
	if (!value) {
		u64 zero = 0;

		bpf_map_update_elem(map, key, &zero, BPF_ANY);
		value = bpf_map_lookup_elem(map, key);
		if (!value)
			return;
	}
	__sync_fetch_and_add(value, 1);
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	u64 pid = bpf_get_current_pid_tgid();
	u64 sleeper = (u64)task->tgid << 32 | task->pid;
	struct event_key *value;

	value = bpf_map_lookup_elem(&wakee, &sleeper);
	if (!value)
		return 0;

	value->waker_tgidpid = pid;
	value->wakee_tgidpid = sleeper;
	update_count(value, &wakee_events);
	bpf_map_delete_elem(&wakee, &sleeper);

	struct event_key key = {
		.waker_tgidpid = pid,
		.wakee_tgidpid = sleeper,
	};

	bpf_get_stack(ctx, &key.kernel_stack, sizeof(key.kernel_stack), SKIP_STACK_DEPTH);
	update_count(&key, &waker_events);
	return 0;
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/*
	 * TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	u64 key = (u64)prev->tgid << 32 | prev->pid;

	if (tool_config.tgid && prev->tgid != tool_config.tgid)
		return 0;

	struct event_key event = {};
	bpf_get_stack(ctx, &event.kernel_stack, sizeof(event.kernel_stack), SKIP_STACK_DEPTH);
	bpf_map_update_elem(&wakee, &key, &event, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
