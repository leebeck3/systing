use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::str;
use std::sync::mpsc::channel;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use ctrlc;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use plain::Plain;

mod systing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/systing.skel.rs"
    ));
}

use systing::*;

unsafe impl Plain for systing::types::task_stat {}

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

struct Process {
    pid: u32,
    stat: systing::types::task_stat,
    threads: Vec<Process>,
}

fn process_comm(process: &Process) -> Result<String> {
    let comm = str::from_utf8(&process.stat.comm).unwrap().to_string();
    if !comm.starts_with('\0') {
        return Ok(comm);
    }
    let path = format!("/proc/{}/comm", process.pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return Ok("<unknown>".to_string());
    }
    Ok(comm.unwrap().trim().to_string())
}

fn dump_all_results(process_vec: Vec<Process>) -> Result<()> {
    for process in process_vec.iter() {
        let comm = process_comm(process)?;
        let total_time: u64 = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.sleep_time
            + process.stat.wait_time
            + 1;

        println!(
            "{} pid {} runtime {}({}%) sleeptime {}({}%) waittime {}({}%) preempttime {}({}%) queuetime {}({}%)",
            comm.trim(),
            process.pid,
            process.stat.run_time,
            process.stat.run_time * 100 / total_time,
            process.stat.sleep_time,
            process.stat.sleep_time * 100 / total_time,
            process.stat.wait_time,
            process.stat.wait_time * 100 / total_time,
            process.stat.preempt_time,
            process.stat.preempt_time * 100 / total_time,
            process.stat.queue_time,
            process.stat.queue_time * 100 / total_time
        );
        for thread in process.threads.iter() {
            let total_time: u64 = thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.sleep_time
                + thread.stat.wait_time
                + 1;
            println!(
                "\t{} pid {} runtime {}({}%) sleeptime {}({}%) waittime {}({}%) preempttime {}({}%) queuetime {}({}%)",
                comm.trim(),
                thread.pid,
                thread.stat.run_time,
                thread.stat.run_time * 100 / total_time,
                thread.stat.sleep_time,
                thread.stat.sleep_time * 100 / total_time,
                thread.stat.wait_time,
                thread.stat.wait_time * 100 / total_time,
                thread.stat.preempt_time,
                thread.stat.preempt_time * 100 / total_time,
                thread.stat.queue_time,
                thread.stat.queue_time * 100 / total_time
            );
        }
    }
    Ok(())
}

fn summarize_results(process_vec: Vec<Process>) -> Result<()> {
    for process in process_vec.iter() {
        let mut total_time: u64 = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.sleep_time
            + process.stat.wait_time;
        let total_threads = process.threads.len();
        let mut total_runtime = process.stat.run_time;
        let mut total_sleep = process.stat.sleep_time;
        let mut total_wait = process.stat.wait_time;
        let mut total_preempt = process.stat.preempt_time;
        let mut total_queue = process.stat.queue_time;
        for thread in process.threads.iter() {
            total_time += thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.sleep_time
                + thread.stat.wait_time;
            total_runtime += thread.stat.run_time;
            total_sleep += thread.stat.sleep_time;
            total_wait += thread.stat.wait_time;
            total_preempt += thread.stat.preempt_time;
            total_queue += thread.stat.queue_time;
        }
        println!(
            "{} pid {} threads {} runtime {}({}%) sleeptime {}({}%) waittime {}({}%) preempttime {}({}%) queuetime {}({}%)",
            process_comm(process)?,
            process.pid,
            total_threads,
            total_runtime,
            total_runtime * 100 / total_time,
            total_sleep,
            total_sleep * 100 / total_time,
            total_wait,
            total_wait * 100 / total_time,
            total_preempt,
            total_preempt * 100 / total_time,
            total_queue,
            total_queue * 100 / total_time
        );
    }
    Ok(())
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

    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");

    println!("Press Ctrl-C to stop");
    rx.recv().expect("Could not receive signal on channel.");

    let mut processes = HashMap::new();
    for rawkey in skel.maps.stats.keys() {
        let mut key: u64 = 0;
        plain::copy_from_bytes(&mut key, &rawkey).expect("Data buffer was too short");
        let pid = key as u32;
        let tgid: u32 = (key >> 32) as u32;
        let rawvalue: Vec<u8> = skel
            .maps
            .stats
            .lookup(&rawkey, libbpf_rs::MapFlags::ANY)
            .expect("Failed to get value")
            .expect("No value found");
        let mut value: systing::types::task_stat = systing::types::task_stat::default();
        plain::copy_from_bytes(&mut value, rawvalue.as_slice()).expect("Data buffer was too short");

        if pid == tgid && processes.contains_key(&pid) {
            // We found a thread before the process, so we need to update the process.
            let process: &mut Process = processes.get_mut(&pid).unwrap();
            process.stat = value;
            continue;
        } else if pid == tgid {
            // This is the tg leader, insert it and carry on.
            let process = Process {
                pid,
                stat: value,
                threads: Vec::new(),
            };

            processes.insert(pid, process);
            continue;
        } else if !processes.contains_key(&tgid) {
            // We found a thread before the process, so we need to create a blank process to update
            // later.
            let process = Process {
                pid: tgid,
                stat: systing::types::task_stat::default(),
                threads: Vec::new(),
            };

            processes.insert(tgid, process);
        }
        let process = Process {
            pid,
            stat: value,
            threads: Vec::new(),
        };
        let leader = processes.get_mut(&tgid).unwrap();
        leader.threads.push(process);
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
    }

    if opts.summary {
        summarize_results(process_vec)?;
    } else {
        dump_all_results(process_vec)?;
    }
    Ok(())
}
