use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use chrono::Local;
use clap::Parser;
use ctrlc;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;
use strum::IntoEnumIterator;

mod systing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/systing.skel.rs"
    ));
}

mod process;
mod tree_view;
use process::{Process, ProcessStat, Run, TotalProcessStat};
use systing::*;

unsafe impl Plain for systing::types::task_stat {}
unsafe impl Plain for systing::types::preempt_event {}

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "0")]
    pid: u32,
    #[arg(short, long, default_value = "")]
    cgroup: String,
    #[arg(short, long)]
    summary: bool,
    #[arg(short, long)]
    tui: bool,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long, default_value = "1")]
    loops: u64,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn dump_all_results(runs: Vec<Run>) -> Result<()> {
    for run in runs {
        println!("Run started at {}", run.start_time.format("%Y-%m-%d %H:%M:%S"));
        for process in run.processes.iter() {
            print!("{} pid {} cgid {}", process.comm, process.pid, process.cgid);
            for stat in ProcessStat::iter() {
                print!(" {}", process.stat_str(stat));
            }

            println!("");

            for pevent in process.preempt_events.iter() {
                println!(
                    "  Preempted by {} pid {} tgid {} cgid {} times {}",
                    pevent.comm, pevent.preempt_pid, pevent.preempt_tgid, pevent.cgid, pevent.count
                );
            }
            for thread in process.threads.iter() {
                print!("\t{} pid {} cgid {}", thread.comm, thread.pid, thread.cgid);

                for stat in ProcessStat::iter() {
                    print!(" {}", thread.stat_str(stat));
                }
                println!("");
                for pevent in thread.preempt_events.iter() {
                    println!(
                        "\t  Preempted by {} pid {} tgid {} cgid {} times {}",
                        pevent.comm,
                        pevent.preempt_pid,
                        pevent.preempt_tgid,
                        pevent.cgid,
                        pevent.count
                    );
                }
            }
        }
    }
    Ok(())
}

fn summarize_results(runs: Vec<Run>) -> Result<()> {
    for run in runs {
        println!("Run started at {}", run.start_time.format("%Y-%m-%d %H:%M:%S"));
        for process in run.processes.iter() {
            let total_threads = process.threads.len();
            let mut pevents = Vec::new();

            for thread in process.threads.iter() {
                pevents.extend(&thread.preempt_events);
            }
            pevents.extend(&process.preempt_events);

            print!(
                "{} pid {} cgid {} threads {}",
                process.comm, process.pid, process.cgid, total_threads
            );
            for stat in TotalProcessStat::iter() {
                print!(" {}", process.total_stat_str(stat));
            }
            println!("");
            pevents.sort_by(|a, b| b.count.cmp(&a.count));
            for pevent in pevents.iter() {
                println!(
                    "\tPreempted by {} pid {} tgid {} times {}",
                    pevent.comm, pevent.preempt_pid, pevent.preempt_tgid, pevent.count
                );
            }
        }
    }
    Ok(())
}

fn collect_results(
    skel: &SystingSkel,
    preempt_events: Vec<systing::types::preempt_event>,
) -> Result<Run> {
    let mut processes = HashMap::new();
    let mut threads: HashMap<u32, Vec<Process>> = HashMap::new();
    for rawkey in skel.maps.stats.keys() {
        let mut key: u64 = 0;
        plain::copy_from_bytes(&mut key, &rawkey).expect("Data buffer was too short");
        let pid = key as u32;
        let tgid: u32 = (key >> 32) as u32;
        let rawvalue: Vec<u8> = skel
            .maps
            .stats
            .lookup_and_delete(&rawkey)
            .expect("Failed to get value")
            .expect("No value found");
        let mut value: systing::types::task_stat = systing::types::task_stat::default();
        plain::copy_from_bytes(&mut value, rawvalue.as_slice()).expect("Data buffer was too short");

        if pid == tgid {
            // This is the tg leader, insert it and carry on.
            let mut process = Process::new(pid, value);

            // If we found threads before we found the process we need to add them to our process
            // now.
            match threads.remove(&pid) {
                Some(mut thread_vec) => loop {
                    match thread_vec.pop() {
                        Some(thread) => {
                            process.add_thread(thread);
                        }
                        None => break,
                    }
                },
                None => {}
            }
            processes.insert(pid, process);
        } else {
            let process = Process::new(pid, value);
            match processes.get_mut(&tgid) {
                Some(leader) => {
                    leader.add_thread(process);
                }
                None => match threads.get_mut(&tgid) {
                    Some(thread_vec) => {
                        thread_vec.push(process);
                    }
                    None => {
                        let mut thread_vec: Vec<Process> = Vec::new();
                        thread_vec.push(process);
                        threads.insert(tgid, thread_vec);
                    }
                },
            }
        }
    }

    // Now we need to go through the preempt events and add them to the process or thread.
    for event in preempt_events.iter() {
        let tgid: u32 = (event.tgidpid >> 32) as u32;
        match processes.get_mut(&tgid) {
            Some(process) => {
                process.add_preempt_event(event);
            }
            None => {}
        }
    }

    let mut process_vec: Vec<Process> = processes.into_iter().map(|(_, v)| v).collect();
    process_vec.sort_by(|a, b| {
        let mut a_total = a.stat.run_time + a.stat.preempt_time + a.stat.queue_time;
        let mut b_total = b.stat.run_time + b.stat.preempt_time + b.stat.queue_time;

        for thread in a.threads.iter() {
            a_total += thread.stat.run_time + thread.stat.preempt_time + thread.stat.queue_time;
        }

        for thread in b.threads.iter() {
            b_total += thread.stat.run_time + thread.stat.preempt_time + thread.stat.queue_time;
        }
        b_total.cmp(&a_total)
    });

    for process in process_vec.iter_mut() {
        process.threads.sort_by(|a, b| {
            let a_total = a.stat.run_time + a.stat.preempt_time + a.stat.queue_time;
            let b_total = b.stat.run_time + b.stat.preempt_time + b.stat.queue_time;
            b_total.cmp(&a_total)
        });
        process.preempt_events.sort_by(|a, b| b.count.cmp(&a.count));
        for thread in process.threads.iter_mut() {
            thread.preempt_events.sort_by(|a, b| b.count.cmp(&a.count));
        }
    }

    Ok(Run {
        processes: process_vec,
        start_time: Local::now(),
    })
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = SystingSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }
    bump_memlock_rlimit()?;

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;

    if opts.cgroup != "" {
        let metadata = std::fs::metadata(&opts.cgroup)?;
        open_skel.maps.rodata_data.tool_config.cgroupid = metadata.ino();
    }

    let mut skel = open_skel.load()?;

    {
        let pid = (std::process::id() as u32).to_ne_bytes();
        let val = (1 as u8).to_ne_bytes();
        skel.maps
            .ignore_pids
            .update(&pid, &val, libbpf_rs::MapFlags::ANY)?;
    }

    skel.attach()?;

    // Start the ring buffer, start a thread to poll for the events and add them to the
    // preempt_events vector.
    let preempt_events = Arc::new(Mutex::new(Vec::new()));
    let preempt_clone = Arc::clone(&preempt_events);
    let thread_done = Arc::new(Mutex::new(false));
    let thread_done_clone = Arc::clone(&thread_done);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::preempt_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            preempt_clone.lock().unwrap().push(event);
            0
        })
        .expect("Failed to add ring buffer");
    let ring = builder.build().expect("Failed to build ring buffer");

    let t = thread::spawn(move || -> i32 {
        loop {
            let res = ring.poll(Duration::from_millis(100));
            if res.is_err() {
                break;
            }
            if *thread_done_clone.lock().unwrap() {
                break;
            }
        }
        0
    });

    let mut runs: Vec<Run> = Vec::new();
    for _ in 0..opts.loops {
        // Wait for the duration to expire or for a Ctrl-C signal.
        if opts.duration > 0 {
            thread::sleep(Duration::from_secs(opts.duration));
        } else {
            let (tx, rx) = channel();
            ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
                .expect("Error setting Ctrl-C handler");
            println!("Press Ctrl-C to stop");
            rx.recv().expect("Could not receive signal on channel.");
        }
        let pevents_vec = std::mem::take(&mut *preempt_events.lock().unwrap());
        let run = collect_results(&skel, pevents_vec)?;
        runs.push(run);
    }

    *thread_done.lock().unwrap() = true;
    t.join().expect("Failed to join thread");

    if opts.tui {
        tree_view::launch_tui(runs);
    } else if opts.summary {
        summarize_results(runs)?;
    } else {
        dump_all_results(runs)?;
    }
    Ok(())
}
