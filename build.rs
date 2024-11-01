use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/systing.bpf.c";

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"),
    );

    let vmlinux_path = out_dir.join("vmlinux.h");
    let skel_path = out_dir.join("systing.skel.rs");

    let bpftool_output = std::process::Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("Failed to execute bpftool");

    std::fs::write(&vmlinux_path, bpftool_output.stdout).expect("Failed to write vmlinux.h");

    let include_arg = format!("-I{}", out_dir.display());
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([OsStr::new(&include_arg)])
        .build_and_generate(&skel_path)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
