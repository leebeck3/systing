To build, ensure you have installed bpftool. This only builds on linux

To run you can trace a cgroup, a process and it's threads, or just the whole
system.

```
target/debug/systing -c <path to cgroup>
target/debug/systing -p <pid>
target/debug/systing
```
