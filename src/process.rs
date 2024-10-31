use std::ffi::CStr;

use crate::systing;
use chrono::{DateTime, Local};
use strum_macros::EnumIter;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
}

#[derive(EnumIter, Debug)]
pub enum ProcessStat {
    RunTime,
    SleepTime,
    WaitTime,
    PreemptTime,
    QueueTime,
    IrqTime,
    SoftirqTime,
}

#[derive(EnumIter, Debug)]
pub enum TotalProcessStat {
    TotalRunTime,
    TotalSleepTime,
    TotalWaitTime,
    TotalPreemptTime,
    TotalQueueTime,
    TotalIrqTime,
    TotalSoftirqTime,
}

pub struct PreemptEvent {
    pub preempt_pid: u32,
    pub preempt_tgid: u32,
    pub cgid: u64,
    pub comm: String,
    pub count: u64,
}

pub struct Process {
    pub pid: u32,
    pub comm: String,
    pub cgid: u64,
    pub stat: systing::types::task_stat,
    pub threads: Vec<Process>,
    pub preempt_events: Vec<PreemptEvent>,
    total_runtime: u64,
    total_sleep_time: u64,
    total_wait_time: u64,
    total_preempt_time: u64,
    total_queue_time: u64,
    total_irq_time: u64,
    total_softirq_time: u64,
    time: u64,
    potential_runtime: u64,
    total_time: u64,
    total_potential_runtime: u64,
}

pub struct Run {
    pub start_time: DateTime<Local>,
    pub processes: Vec<Process>,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        Process {
            pid,
            comm: pid_comm(pid),
            cgid: 0,
            stat: systing::types::task_stat::default(),
            threads: Vec::new(),
            preempt_events: Vec::new(),
            total_runtime: 0,
            total_sleep_time: 0,
            total_wait_time: 0,
            total_preempt_time: 0,
            total_queue_time: 0,
            total_irq_time: 0,
            total_softirq_time: 0,
            time: 0,
            potential_runtime: 0,
            total_time: 0,
            total_potential_runtime: 0,
        }
    }

    pub fn with_event(pid: u32, stat: systing::types::task_stat) -> Self {
        // Sometimes the counters can get messed up between runs because we sync_add update in
        // between adding and dropping the value.
        let mytime = stat
            .run_time
            .wrapping_add(stat.preempt_time)
            .wrapping_add(stat.queue_time)
            .wrapping_add(stat.irq_time)
            .wrapping_add(stat.softirq_time)
            .wrapping_add(stat.sleep_time)
            .wrapping_add(stat.wait_time);
        let mypotential_runtime = stat
            .run_time
            .wrapping_add(stat.preempt_time)
            .wrapping_add(stat.queue_time)
            .wrapping_add(stat.irq_time)
            .wrapping_add(stat.softirq_time);
        Process {
            pid,
            comm: Process::get_comm(pid, stat),
            cgid: stat.cgid,
            stat,
            threads: Vec::new(),
            preempt_events: Vec::new(),
            time: mytime,
            potential_runtime: mypotential_runtime,
            total_time: mytime,
            total_potential_runtime: mypotential_runtime,
            total_runtime: stat.run_time,
            total_sleep_time: stat.sleep_time,
            total_wait_time: stat.wait_time,
            total_preempt_time: stat.preempt_time,
            total_queue_time: stat.queue_time,
            total_irq_time: stat.irq_time,
            total_softirq_time: stat.softirq_time,
        }
    }

    pub fn process_time(&self) -> u64 {
        match self.time {
            0 => 1,
            _ => self.time,
        }
    }

    pub fn potential_runtime(&self) -> u64 {
        match self.potential_runtime {
            0 => 1,
            _ => self.potential_runtime,
        }
    }

    pub fn total_time(&self) -> u64 {
        match self.total_time {
            0 => 1,
            _ => self.total_time,
        }
    }

    pub fn total_potential_runtime(&self) -> u64 {
        match self.total_potential_runtime {
            0 => 1,
            _ => self.total_potential_runtime,
        }
    }

    pub fn add_thread(&mut self, thread: Process) {
        self.total_time = self.total_time.wrapping_add(thread.time);
        self.total_potential_runtime = self
            .total_potential_runtime
            .wrapping_add(thread.potential_runtime);
        self.total_runtime = self.total_runtime.wrapping_add(thread.stat.run_time);
        self.total_sleep_time = self.total_sleep_time.wrapping_add(thread.stat.sleep_time);
        self.total_wait_time = self.total_wait_time.wrapping_add(thread.stat.wait_time);
        self.total_preempt_time = self
            .total_preempt_time
            .wrapping_add(thread.stat.preempt_time);
        self.total_queue_time = self.total_queue_time.wrapping_add(thread.stat.queue_time);
        self.total_irq_time = self.total_irq_time.wrapping_add(thread.stat.irq_time);
        self.total_softirq_time = self
            .total_softirq_time
            .wrapping_add(thread.stat.softirq_time);
        self.threads.push(thread);
    }

    pub fn add_preempt_event(&mut self, event: &systing::types::preempt_event) {
        let pid = event.tgidpid as u32;
        if pid == self.pid {
            self.add_preempt_event_to_self(event);
        } else {
            for thread in self.threads.iter_mut() {
                if thread.pid == pid {
                    thread.add_preempt_event_to_self(event);
                    return;
                }
            }
        }
    }

    pub fn stat_str(&self, stat: ProcessStat) -> String {
        match stat {
            ProcessStat::RunTime => format!(
                "Run Time: {}({}% total time, {}% runtime)",
                self.stat.run_time,
                self.stat.run_time * 100 / self.process_time(),
                self.stat.run_time * 100 / self.potential_runtime()
            ),
            ProcessStat::SleepTime => format!(
                "Sleep Time: {}({}%)",
                self.stat.sleep_time,
                self.stat.sleep_time * 100 / self.process_time()
            ),
            ProcessStat::WaitTime => format!(
                "Wait Time: {}({}%)",
                self.stat.wait_time,
                self.stat.wait_time * 100 / self.process_time()
            ),
            ProcessStat::PreemptTime => format!(
                "Preempt Time: {}({}% total time, {}% runtime)",
                self.stat.preempt_time,
                self.stat.preempt_time * 100 / self.process_time(),
                self.stat.preempt_time * 100 / self.potential_runtime()
            ),
            ProcessStat::QueueTime => format!(
                "Queue Time: {}({}% total time, {}% runtime)",
                self.stat.queue_time,
                self.stat.queue_time * 100 / self.process_time(),
                self.stat.queue_time * 100 / self.potential_runtime()
            ),
            ProcessStat::IrqTime => format!(
                "IRQ Time: {}({}% total time, {}% runtime)",
                self.stat.irq_time,
                self.stat.irq_time * 100 / self.process_time(),
                self.stat.irq_time * 100 / self.potential_runtime()
            ),
            ProcessStat::SoftirqTime => format!(
                "SoftIRQ Time: {}({}% total time, {}% runtime)",
                self.stat.softirq_time,
                self.stat.softirq_time * 100 / self.process_time(),
                self.stat.softirq_time * 100 / self.potential_runtime()
            ),
        }
    }

    pub fn total_stat_str(&self, stat: TotalProcessStat) -> String {
        match stat {
            TotalProcessStat::TotalRunTime => format!(
                "Total Run Time: {}({}% total time, {}% runtime)",
                self.total_runtime,
                self.total_runtime * 100 / self.total_time(),
                self.total_runtime * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalSleepTime => format!(
                "Total Sleep Time: {}({}%)",
                self.total_sleep_time,
                self.total_sleep_time * 100 / self.total_time()
            ),
            TotalProcessStat::TotalWaitTime => format!(
                "Total Wait Time: {}({}%)",
                self.total_wait_time,
                self.total_wait_time * 100 / self.total_time()
            ),
            TotalProcessStat::TotalPreemptTime => format!(
                "Total Preempt Time: {}({}% total time, {}% runtime)",
                self.total_preempt_time,
                self.total_preempt_time * 100 / self.total_time(),
                self.total_preempt_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalQueueTime => format!(
                "Total Queue Time: {}({}% total time, {}% runtime)",
                self.total_queue_time,
                self.total_queue_time * 100 / self.total_time(),
                self.total_queue_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalIrqTime => format!(
                "Total IRQ Time: {}({}% total time, {}% runtime)",
                self.total_irq_time,
                self.total_irq_time * 100 / self.total_time(),
                self.total_irq_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalSoftirqTime => format!(
                "Total SoftIRQ Time: {}({}% total time, {}% runtime)",
                self.total_softirq_time,
                self.total_softirq_time * 100 / self.total_time(),
                self.total_softirq_time * 100 / self.total_potential_runtime()
            ),
        }
    }

    fn get_comm(pid: u32, stat: systing::types::task_stat) -> String {
        let comm_cstr = CStr::from_bytes_until_nul(&stat.comm).unwrap();
        if comm_cstr.to_bytes().starts_with(&[0]) {
            return pid_comm(pid);
        }
        comm_cstr.to_string_lossy().to_string()
    }

    fn add_preempt_event_to_self(&mut self, event: &systing::types::preempt_event) {
        for e in self.preempt_events.iter_mut() {
            let pid = event.preempt_tgidpid as u32;
            if e.preempt_pid == pid {
                e.count += 1;
                return;
            }
        }
        self.preempt_events.push(PreemptEvent::new(event));
    }
}

impl PreemptEvent {
    pub fn new(event: &systing::types::preempt_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.comm).unwrap();
        let commstr;
        if comm_cstr.to_bytes().starts_with(&[0]) {
            commstr = pid_comm(event.preempt_tgidpid as u32);
        } else {
            commstr = comm_cstr.to_string_lossy().to_string();
        }
        PreemptEvent {
            preempt_pid: event.preempt_tgidpid as u32,
            preempt_tgid: (event.preempt_tgidpid >> 32) as u32,
            cgid: event.cgid,
            comm: commstr,
            count: 1,
        }
    }
}
