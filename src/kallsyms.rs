use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::collections::BTreeMap;
use std::u64;

pub struct Kallsyms {
    map: BTreeMap<u64, String>,
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

impl Kallsyms {
    pub fn new() -> Self {
        let mut map = BTreeMap::new();
        if let Ok(lines) = read_lines("/proc/kallsyms") {
            for line in lines {
                if let Ok(ip) = line {
                    let mut parts = ip.split_whitespace();
                    let addr = u64::from_str_radix(parts.next().unwrap(), 16).unwrap();
                    let _ = parts.next().unwrap();
                    let mut name: String = parts.next().unwrap().to_string();
                    match parts.next() {
                        Some(module) => name = format!("{} {}", name, module),
                        _ => (),
                    };
                    map.insert(addr, name);
                }
            }
        }
        Self { map }
    }

    pub fn resolve(&self, addr: u64) -> Option<&String> {
        self.map.range(..=addr).next_back().map(|(_, name)| name)
    }
}
