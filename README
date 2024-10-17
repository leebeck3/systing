To build run

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build
```

To run you can trace a cgroup, a process and it's threads, or just the whole
system.

```
target/debug/systing -c <path to cgroup>
target/debug/systing -p <pid>
target/debug/systing
```
