To build, ensure you have installed bpftool. This only builds on linux

## Profile

This tool can trace a cgroup, a process and it's threads, or just the whole
system to generate a view of the time spent by the process.  This is useful for
determining where you should focus performance investigations.  It measures
actual real time spent by the application waiting for events to happen (network
traffic, polling, futexes, etc), time spent waiting on IO, time spent waiting to
get on the CPU, how much time is spent being interrupted by IRQs, and how much
time is being spent being kicked off the CPU by other processes.

To run this tool you can use it the following ways

```
target/debug/systing profile -c <path to cgroup>
target/debug/systing profile -p <pid>
target/debug/systing profile
```

You can also specify a duration to record

```
target/debug/systing profile -c <path to cgroup> -d 10
```

If you have a long running process you can compare slices of runs by specifying
an interval

```
target/debug/systing profile -c <path to cgroup> -d 10 -i 5
```

This will collect 10 seconds of data, 5 times, and group the output by the
collection periods.  There are several options for outputs

- `--aggregate` - This will aggregate the collection of the data into a single
  entry per TGID.  This is useful for large applications that have many threads.
- `--summary` - This will output a summary of the data collected.  This is
  useful for quick overviews of the data.
- `--tui` - This will output the data in a TUI format.  This is useful for
  interactive exploration of the data.

## Describe

This tool can be used to figure out what a process and it's threads are doing in
relation to each other and their usage pattern.  It tracks kernel and userspace
stack traces of wakers and wakees, and tracks the time spent asleep for each
operation.  This is useful for determining what exactly the process is doing and
what resources each thread depends on for their operation.  It is also helpful
to determine dependency chains between the different threads.
