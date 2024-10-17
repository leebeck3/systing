use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/systing.bpf.c";

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("systing.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-Ivmlinux.h"),
        ])
        .build_and_generate(&out_dir)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
