use std::mem::MaybeUninit;
use std::thread;
use std::time::Duration;

use crate::kallsyms::Kallsyms;
use crate::DescribeOpts;
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::MapCore;
use plain::Plain;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

unsafe impl Plain for systing::types::event_key {}

enum EventTypes {
    Waker,
    Wakee,
}

struct StackHist {
    waker: u64,
    wakee: u64,
    count: u64,
    stack: Vec<u64>,
    event_type: EventTypes,
}

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
}

impl StackHist {
    pub fn new(num: u64, stk: Vec<u64>, t: EventTypes) -> Self {
        StackHist {
            waker: 0,
            wakee: 0,
            count: num,
            stack: stk,
            event_type: t,
        }
    }

    pub fn print(&self, kallsyms: &Kallsyms) {
        match self.event_type {
            EventTypes::Waker => println!("Waker event count: {}", self.count),
            EventTypes::Wakee => println!("Wakee event count: {}", self.count),
        }
        for addr in &self.stack {
            if *addr == 0 {
                break;
            }
            println!(
                "  0x{:x} {}",
                addr,
                kallsyms.resolve(*addr).unwrap_or(&"unknown".to_string())
            );
        }
        println!();
    }
}

pub fn describe(opts: DescribeOpts) -> Result<()> {
    let kallsyms = Kallsyms::new();
    let mut skel_builder = systing::SystingDescribeSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    thread::sleep(Duration::from_secs(10));

    let mut stack_hists = Vec::new();
    for rawkey in skel.maps.waker_events.keys() {
        let mut key: systing::types::event_key = systing::types::event_key::default();
        plain::copy_from_bytes(&mut key, rawkey.as_slice()).unwrap();
        let rawvalue = skel
            .maps
            .waker_events
            .lookup(&rawkey, libbpf_rs::MapFlags::ANY)
            .expect("Failed to lookup event")
            .expect("Failed to get value");
        let stack_count = u64::from_ne_bytes(rawvalue[0..8].try_into().unwrap());

        let stack: Vec<u64> = key.kernel_stack.to_vec();
        stack_hists.push(StackHist::new(stack_count, stack, EventTypes::Waker));
    }

    stack_hists.sort_by(|a, b| b.count.cmp(&a.count));
    for stack_hist in stack_hists {
        println!("Event count: {}", stack_hist.count);
        stack_hist.print(&kallsyms);
    }
    Ok(())
}
