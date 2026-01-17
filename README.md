# unixpcap

Capture UNIX socket traffic in pcap format.

# Use

```
./unixpcap
```

## Prerequisites

- **TODO**

Necessary kernel options

- **TODO**

Necessrry rights

- **TODO**


# Local build


Build prerequisites

- clang (for building EBPF programs)
- **TODO**


# Development

- Install build prerequisites.
- Install libbpftool-dev if you want code completion for BPF programs
- `vmlinux.h` has been generated using `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- **TODO**
