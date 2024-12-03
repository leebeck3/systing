#!/bin/bash
#prolly needs sudo
#could also use the bpf packages for the .h files in src/bpf/*bpf.c
apt install bpftool
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
