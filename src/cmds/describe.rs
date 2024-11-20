use std::collections::HashMap;
use std::hash::Hash;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::DescribeOpts;
use anyhow::Result;
use blazesym::symbolize::{CodeInfo, Input, Kernel, Process, Source, Sym, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use plain::Plain;
use petgraph::graphmap::DiGraphMap;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

unsafe impl Plain for systing::types::wake_event {}

const ADDR_WIDTH: usize = 16;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return format!("Pid: {}", pid).to_string();
    }
    comm.unwrap().trim().to_string()
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct WakeEventKey {
    waker: u64,
    wakee: u64,
    waker_kernel_stack: Vec<Addr>,
    wakee_kernel_stack: Vec<Addr>,
    waker_user_stack: Vec<Addr>,
    wakee_user_stack: Vec<Addr>,
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
        // The waker can be the kernel, to avoid the overhead of memsetting the whole stack we use
        // a magic number for the first element so we can just zero out the stack.
        let waker_stack = match event.waker_user_stack[0] {
            1234 => vec![],
            _ => event
                .waker_user_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
        };

        WakeEventKey {
            waker: event.waker_tgidpid,
            wakee: event.wakee_tgidpid,
            waker_kernel_stack: event
                .waker_kernel_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
            wakee_kernel_stack: event
                .wakee_kernel_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
            waker_user_stack: waker_stack,
            wakee_user_stack: event
                .wakee_user_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
        }
    }
}

struct ProcessEvents {
    duration_us: u64,
    events: HashMap<WakeEventKey, WakeEventValue>,
}

impl ProcessEvents {
    pub fn new() -> Self {
        ProcessEvents {
            duration_us: 0,
            events: HashMap::new(),
        }
    }

    pub fn add_event(&mut self, event: systing::types::wake_event) {
        let key = WakeEventKey::new(event);
        self.duration_us += event.sleep_time_us;
        match self.events.get_mut(&key) {
            Some(ref mut value) => {
                value.count += 1;
                value.duration_us += event.sleep_time_us;
            }
            None => {
                self.events.insert(
                    key,
                    WakeEventValue {
                        count: 1,
                        duration_us: event.sleep_time_us,
                    },
                );
            }
        };
    }
}

fn print_frame(name: &str, addr_info: Option<(Addr, Addr, usize)>, code_info: &Option<CodeInfo>) {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        println!(
            "  {input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
    } else {
        // Otherwise we are dealing with an inlined call.
        println!(
            "  {:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
    }
}

fn print_symbols<'a, I>(syms: I)
where
    I: IntoIterator<Item = (Addr, Symbolized<'a>)>,
{
    for (input_addr, sym) in syms {
        match sym {
            Symbolized::Sym(Sym {
                addr,
                name,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(&name, Some((input_addr, addr, offset)), &code_info);
                for inline in inlined {
                    print_frame(&inline.name, None, &inline.code_info);
                }
            }
            Symbolized::Unknown(e) => {
                println!("  {input_addr:#0width$x}: <{e}>", width = ADDR_WIDTH)
            }
        }
    }
}

impl WakeEvent {
    pub fn print(
        &self,
        symbolizer: &Symbolizer,
        waker_src: &Source,
        wakee_src: &Source,
        kernel_src: &Source,
    ) {
        println!(
            "  Waker: tgid {} pid {} comm {}",
            self.key.waker >> 32,
            self.key.waker as u32,
            pid_comm(self.key.waker as u32)
        );
        println!(
            "  Count: {}, Duration: {}",
            self.value.count, self.value.duration_us
        );
        println!("  Waker kernel stack:");
        match symbolizer.symbolize(kernel_src, Input::AbsAddr(&self.key.waker_kernel_stack)) {
            Ok(syms) => print_symbols(self.key.waker_kernel_stack.iter().copied().zip(syms)),
            Err(e) => eprintln!("Failed to symbolize waker kernel stack: {}", e),
        };

        if !self.key.waker_user_stack.is_empty() {
            println!("  Waker user stack:");
            match symbolizer.symbolize(waker_src, Input::AbsAddr(&self.key.waker_user_stack)) {
                Ok(syms) => print_symbols(self.key.waker_user_stack.iter().copied().zip(syms)),
                Err(e) => eprintln!("Failed to symbolize waker user stack: {}", e),
            };
        }

        println!("  Wakee kernel stack:");
        match symbolizer.symbolize(kernel_src, Input::AbsAddr(&self.key.wakee_kernel_stack)) {
            Ok(syms) => print_symbols(self.key.wakee_kernel_stack.iter().copied().zip(syms)),
            Err(e) => eprintln!("Failed to symbolize wakee kernel stack: {}", e),
        };
        if !self.key.wakee_user_stack.is_empty() {
            println!("  Wakee user stack:");
            match symbolizer.symbolize(wakee_src, Input::AbsAddr(&self.key.wakee_user_stack)) {
                Ok(syms) => print_symbols(self.key.wakee_user_stack.iter().copied().zip(syms)),
                Err(e) => eprintln!("Failed to symbolize wakee user stack: {}", e),
            };
        }
        println!();
    }
}

pub fn describe(opts: DescribeOpts) -> Result<()> {
    let mut skel_builder = systing::SystingDescribeSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let events = Arc::new(Mutex::new(HashMap::<u64, ProcessEvents>::new()));
    let events_clone = events.clone();
    let thread_done = Arc::new(AtomicBool::new(false));
    let thread_done_clone = thread_done.clone();
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::wake_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            let pidtgid = event.wakee_tgidpid;
            let mut myevents = events_clone.lock().unwrap();
            match myevents.get_mut(&pidtgid) {
                Some(ref mut process_events) => {
                    process_events.add_event(event);
                }
                None => {
                    let mut process_events = ProcessEvents::new();
                    process_events.add_event(event);
                    myevents.insert(pidtgid, process_events);
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

    if opts.duration > 0 {
        thread::sleep(Duration::from_secs(opts.duration));
    } else {
        let (tx, rx) = channel();
        ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");
        println!("Press Ctrl-C to stop");
        rx.recv().expect("Could not receive signal on channel.");
    }

    thread_done.store(true, Ordering::Relaxed);
    t.join().expect("Failed to join thread");

    let mut process_events_vec: Vec<ProcessEvents> = Vec::new();
    let mut graph = DiGraphMap::new();
    {
        let events_hash = std::mem::take(&mut *events.lock().unwrap());
        for (pidtgid, process_events) in events_hash {
            let mut edges = HashMap::<u64, u64>::new();
            for (key, value) in process_events.events.iter() {
                if edges.contains_key(&key.waker) {
                    *edges.get_mut(&key.waker).unwrap() += value.duration_us;
                } else {
                    edges.insert(key.waker, value.duration_us);
                }
            }
            for edge in edges {
                graph.add_edge(edge.0, pidtgid, edge.1);
            }
            process_events_vec.push(process_events);
        }
    }
    process_events_vec.sort_by_key(|k| k.duration_us);

    for (waker, wakee, duration) in graph.all_edges() {
        println!(
            "Waker: tgid {} pid {} comm {} -> Wakee: tgid {} pid {} comm {} Duration: {}",
            waker >> 32,
            waker as u32,
            pid_comm(waker as u32),
            wakee >> 32,
            wakee as u32,
            pid_comm(wakee as u32),
            duration
        );
    }

    for process_events in process_events_vec {
        let mut events_vec: Vec<WakeEvent> = process_events
            .events
            .into_iter()
            .map(|(key, value)| WakeEvent { key, value })
            .collect();
        events_vec.sort_by_key(|k| (k.value.duration_us, k.value.count));
        let mut src_cache = HashMap::<u32, Source>::new();
        let symbolizer = Symbolizer::new();
        let kernel_src = Source::Kernel(Kernel::default());
        let mut first = true;
        for event in events_vec {
            let waker_tgid = (event.key.waker >> 32) as u32;
            let wakee_tgid = (event.key.wakee >> 32) as u32;

            if first {
                println!(
                    "Process: tgid {} pid {} comm {}",
                    wakee_tgid,
                    event.key.wakee as u32,
                    pid_comm(event.key.wakee as u32)
                );
                first = false;
            }

            if !src_cache.contains_key(&waker_tgid) {
                src_cache.insert(
                    waker_tgid,
                    Source::Process(Process::new(Pid::from(waker_tgid))),
                );
            }
            if !src_cache.contains_key(&wakee_tgid) {
                src_cache.insert(
                    wakee_tgid,
                    Source::Process(Process::new(Pid::from(wakee_tgid))),
                );
            }
            let waker_src = src_cache.get(&waker_tgid).unwrap();
            let wakee_src = src_cache.get(&wakee_tgid).unwrap();
            event.print(&symbolizer, waker_src, wakee_src, &kernel_src);
        }
    }
    Ok(())
}
