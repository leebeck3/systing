#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2

/*
 * Used specifically to make sure we don't accidentally record stats for a value
 * we didn't catch at sched_waking time.
 */
#define TASK_WAKING 4567

#define TASK_STATE_MASK 3

#define TASK_COMM_LEN 16

const volatile struct {
	gid_t tgid;
	u32 filter_cgroup;
	u32 aggregate;
} tool_config = {};

enum stat_type {
	STAT_SLEEP_TIME,
	STAT_PREEMPT_TIME,
	STAT_RUN_TIME,
	STAT_WAIT_TIME,
	STAT_QUEUE_TIME,
	STAT_IRQ_TIME,
	STAT_SOFTIRQ_TIME,
	STAT_WAKING_TIME,
	STAT_MAX,
};

struct task_state_value {
	u64 ts;
	u32 state;
	bool preempt;
};

struct task_stat {
	u8 comm[TASK_COMM_LEN];
	u64 cgid;
	u64 sleep_time;
	u64 preempt_time;
	u64 run_time;
	u64 wait_time;
	u64 queue_time;
	u64 irq_time;
	u64 softirq_time;
	u64 waking_time;
};

struct preempt_event {
	u8 comm[TASK_COMM_LEN];
	u64 tgidpid;
	u64 preempt_tgidpid;
	u64 cgid;
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct preempt_event`
 */
struct preempt_event _event = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_state_value);
	__uint(max_entries, 10240);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_stat);
	__uint(max_entries, 10240);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 10240);
} ignore_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 10240);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} irq_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024 /* 10Mib */);
} events SEC(".maps");

static __always_inline
u64 task_cg_id(struct task_struct *task)
{
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;
	return cgrp->kn->id;
}

static __always_inline
u64 task_key(struct task_struct *task)
{
	return (u64)task->tgid << 32 | task->pid;
}

static __always_inline
u64 task_stat_key(struct task_struct *task)
{
	if (tool_config.aggregate)
		return (u64)task->tgid << 32 | task->tgid;
	return task_key(task);
}

static __always_inline
int trace_enqueue(struct task_struct *tsk, u32 state, bool preempt)
{
	u64 key = task_key(tsk);
	u32 tgid = tsk->tgid;
	struct task_state_value value;

	if (bpf_map_lookup_elem(&ignore_pids, &tgid))
		return 0;
	if (tool_config.tgid && tsk->tgid != tool_config.tgid)
		return 0;
	if (tsk->tgid == 0)
		return 0;
	if (tool_config.filter_cgroup) {
		u64 cgid = task_cg_id(tsk);
		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
			return 0;
	}
	value.ts = bpf_ktime_get_ns();
	value.state = state;
	value.preempt = preempt;
	bpf_map_update_elem(&start, &key, &value, BPF_ANY);
	return 0;
}

static struct task_stat zero_stat = {};

static __always_inline
void update_counter(struct task_struct *task, u64 delta, enum stat_type type)
{
	u64 key = task_stat_key(task);
	struct task_stat *stat;

	stat = bpf_map_lookup_elem(&stats, &key);
	if (!stat) {
		bpf_map_update_elem(&stats, &key, &zero_stat, BPF_ANY);

		stat = bpf_map_lookup_elem(&stats, &key);
		if (!stat)
			return;
		stat->cgid = task_cg_id(task);

		/*
		 * If we aggregate stats just leave the comm blank so that we
		 * pull the comm of the leader process and not whichever thread
		 * happens to get caught first.
		 */
		if (!tool_config.aggregate)
			bpf_probe_read_kernel_str(stat->comm, sizeof(stat->comm),
						  task->comm);
	}

	switch (type) {
	case STAT_SLEEP_TIME:
		__sync_fetch_and_add(&stat->sleep_time, delta);
		break;
	case STAT_PREEMPT_TIME:
		__sync_fetch_and_add(&stat->preempt_time, delta);
		break;
	case STAT_RUN_TIME:
		__sync_fetch_and_add(&stat->run_time, delta);
		break;
	case STAT_WAIT_TIME:
		__sync_fetch_and_add(&stat->wait_time, delta);
		break;
	case STAT_QUEUE_TIME:
		__sync_fetch_and_add(&stat->queue_time, delta);
		break;
	case STAT_IRQ_TIME:
		__sync_fetch_and_add(&stat->irq_time, delta);
		break;
	case STAT_SOFTIRQ_TIME:
		__sync_fetch_and_add(&stat->softirq_time, delta);
		break;
	case STAT_WAKING_TIME:
		__sync_fetch_and_add(&stat->waking_time, delta);
		break;
	default:
		break;
	}
}


static __always_inline
int trace_irq_enter(void)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();
	u64 key = task_key(tsk);
	u64 start;
	u32 tgid = tsk->tgid;

	if (bpf_map_lookup_elem(&ignore_pids, &tgid))
		return 0;
	if (tool_config.tgid && tsk->tgid != tool_config.tgid)
		return 0;
	if (tsk->tgid == 0)
		return 0;
	if (tool_config.filter_cgroup) {
		u64 cgid = task_cg_id(tsk);
		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
			return 0;
	}
	start = bpf_ktime_get_ns();
	bpf_map_update_elem(&irq_events, &key, &start, BPF_ANY);
	return 0;
}

static __always_inline
int trace_irq_exit(bool softirq)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();
	struct task_stat *stat;
	u64 *start_ns;
	u64 key = task_key(tsk);
	u64 delta;

	start_ns = bpf_map_lookup_elem(&irq_events, &key);
	if (!start_ns)
		return 0;
	delta = bpf_ktime_get_ns() - *start_ns;
	update_counter(tsk, delta, softirq ? STAT_SOFTIRQ_TIME : STAT_IRQ_TIME);
	bpf_map_delete_elem(&irq_events, &key);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	u64 key = task_key(task);
	struct task_state_value *value;

	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = bpf_ktime_get_ns() - value->ts;
		switch (value->state) {
		case TASK_WAKING:
			update_counter(task, delta, STAT_WAKING_TIME);
			break;
		default:
			break;
		}
	}
	return trace_enqueue(task, TASK_RUNNING, false);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (void *)ctx[0];
	return trace_enqueue(task, TASK_RUNNING, false);
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/*
	 * TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	int prev_state = prev->__state & TASK_STATE_MASK;
	int next_state = next->__state & TASK_STATE_MASK;
	u64 key = task_key(prev);
	u64 ts = bpf_ktime_get_ns();
	struct task_state_value *value;

	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = ts - value->ts;
		update_counter(prev, delta, STAT_RUN_TIME);
	}
	trace_enqueue(prev, prev_state, prev_state == TASK_RUNNING);

	/* Don't record preempt events for idle threads. */
	if (prev_state == TASK_RUNNING && next->tgid != 0 && prev->tgid != 0) {
		struct preempt_event *e;

		e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->tgidpid = task_key(prev);
			e->cgid = task_cg_id(next);
			e->preempt_tgidpid = task_key(next);
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
						  next->comm);
			bpf_ringbuf_submit(e, 0);
		}
	}

	key = task_key(next);
	value = bpf_map_lookup_elem(&start, &key);
	if (value && value->state == TASK_RUNNING) {
		u64 delta = ts - value->ts;
		if (value->preempt)
			update_counter(next, delta, STAT_PREEMPT_TIME);
		else
			update_counter(next, delta, STAT_QUEUE_TIME);
	}
	trace_enqueue(next, next_state, false);
	return 0;
}

SEC("tp_btf/sched_waking")
int handle__sched_waking(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	u64 key = task_key(task);
	struct task_state_value *value;

	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = bpf_ktime_get_ns() - value->ts;
		switch (value->state) {
		case TASK_INTERRUPTIBLE:
			update_counter(task, delta, STAT_SLEEP_TIME);
			break;
		case TASK_UNINTERRUPTIBLE:
			update_counter(task, delta, STAT_WAIT_TIME);
			break;
		default:
			break;
		}
	}
	return trace_enqueue(task, TASK_WAKING, false);
}

SEC("tp_btf/irq_handler_entry")
int handle__irq_handler_entry(u64 *ctx)
{
	/* TP_PROTO(int irq, struct irqaction *action) */
	return trace_irq_enter();
}

SEC("tp_btf/irq_handler_exit")
int handle__irq_handler_exit(u64 *ctx)
{
	/* TP_PROTO(int irq, struct irqaction *action, int ret) */
	return trace_irq_exit(false);
}

SEC("tp_btf/softirq_entry")
int handle__softirq_entry(u64 *ctx)
{
	/* TP_PROTO(unsigned int vec_nr) */
	return trace_irq_enter();
}

SEC("tp_btf/softirq_exit")
int handle__softirq_exit(u64 *ctx)
{
	/* TP_PROTO(unsigned int vec_nr) */
	return trace_irq_exit(true);
}

char LICENSE[] SEC("license") = "GPL";
