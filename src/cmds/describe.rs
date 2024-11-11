use std::collections::HashMap;
use std::hash::Hash;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::kallsyms::Kallsyms;
use crate::DescribeOpts;
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

unsafe impl Plain for systing::types::wake_event {}

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct WakeEventKey {
    waker: u64,
    wakee: u64,
    waker_kernel_stack: Vec<u64>,
    wakee_kernel_stack: Vec<u64>,
    waker_user_stack: Vec<u64>,
    wakee_user_stack: Vec<u64>,
}

struct WakeEventValue {
    count: u64,
    duration_us: u64,
}

struct WakeEvent {
    key: WakeEventKey,
    value: WakeEventValue,
}

impl WakeEventKey {
    pub fn new(event: systing::types::wake_event) -> Self {
        WakeEventKey {
            waker: event.waker_tgidpid,
            wakee: event.wakee_tgidpid,
            waker_kernel_stack: event.waker_kernel_stack.to_vec(),
            wakee_kernel_stack: event.wakee_kernel_stack.to_vec(),
            waker_user_stack: event.waker_user_stack.to_vec(),
            wakee_user_stack: event.wakee_user_stack.to_vec(),
        }
    }
}

impl WakeEvent {
    pub fn print(&self, kallsyms: &Kallsyms) {
        println!(
            "  Waker: tgid {} pid {} comm {}",
            self.key.waker >> 32,
            self.key.waker as u32,
            pid_comm(self.key.waker as u32)
        );
        println!(
            "  Wakee: tgid {} pid {} comm {}",
            self.key.wakee >> 32,
            self.key.wakee as u32,
            pid_comm(self.key.wakee as u32)
        );
        println!(
            "  Count: {}, Duration: {}",
            self.value.count, self.value.duration_us
        );
        println!("  Waker kernel stack:");
        for addr in &self.key.waker_kernel_stack {
            if *addr == 0 {
                break;
            }
            println!(
                "  0x{:x} {}",
                addr,
                kallsyms.resolve(*addr).unwrap_or(&"unknown".to_string())
            );
        }
        println!("  Wakee kernel stack:");
        for addr in &self.key.wakee_kernel_stack {
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

    let events = Arc::new(Mutex::new(HashMap::<WakeEventKey, WakeEventValue>::new()));
    let events_clone = events.clone();
    let thread_done = Arc::new(AtomicBool::new(false));
    let thread_done_clone = thread_done.clone();
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::wake_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            let key = WakeEventKey::new(event);
            let mut myevents = events_clone.lock().unwrap();
            match myevents.get_mut(&key) {
                Some(ref mut value) => {
                    value.count += 1;
                    value.duration_us += event.sleep_time_us;
                }
                None => {
                    myevents.insert(
                        key,
                        WakeEventValue {
                            count: 0,
                            duration_us: 0,
                        },
                    );
                }
            };
            0
        })
        .expect("Failed to add ring buffer");
    let ring = builder.build().expect("Failed to build ring buffer");

    let t = thread::spawn(move || {
        loop {
            let res = ring.poll(Duration::from_millis(100));
            if res.is_err() {
                break;
            }
            if thread_done_clone.load(Ordering::Relaxed) {
                break;
            }
        }
        0
    });

    thread::sleep(Duration::from_secs(10));
    thread_done.store(true, Ordering::Relaxed);
    t.join().expect("Failed to join thread");

    let events_hash = std::mem::take(&mut *events.lock().unwrap());
    let mut events_vec: Vec<WakeEvent> = events_hash
        .into_iter()
        .map(|(key, value)| WakeEvent { key, value })
        .collect();
    events_vec.sort_by_key(|k| (k.value.duration_us, k.value.count));
    for event in events_vec {
        event.print(&kallsyms);
    }
    Ok(())
}
