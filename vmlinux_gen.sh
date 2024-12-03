#!/bin/bash
#prolly needs sudo
apt install bpftool
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
