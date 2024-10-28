use std::ffi::CStr;

use crate::systing;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
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
    pub stat: systing::types::task_stat,
    pub threads: Vec<Process>,
    pub preempt_events: Vec<PreemptEvent>,
}

impl Process {
    pub fn new(pid: u32, stat: systing::types::task_stat) -> Self {
        Process {
            pid,
            comm: Process::get_comm(pid, stat),
            stat,
            threads: Vec::new(),
            preempt_events: Vec::new(),
        }
    }

    pub fn add_thread(&mut self, thread: Process) {
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
