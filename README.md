# unixpcap

Capture UNIX socket traffic in pcapng (pcap) format using eBPF.


# Features

- Capture of datagram traffic of UNIX sockets
- Leverages eBPF for efficient capture
- Uses name resolution blocks for resolving socket paths

**TODO list**:

- Support stream,seqpacket sockets
- Proper iovec gather capture
- reliable kernel config detection, ifdefs, fallbacks
- revisit zero-copy possibilities
- github actions with binary release
- redirection to stdout
- verbose mode
- filter by path or TID/PID
- capture name of the process associated with the socket
- avoid repeated metadata on eBPF side (paths, names)
- possibility to capture on receiving side
- possibility to trace occupancy, extraction-latency of receive buffers

# Installation

## GitHub Releases

**TODO**

## Package Managers

Unixpcap is not currently packaged in any distributions.

## Local Build

### Build Prerequisites

- LLVM toolchain - for building eBPF programs
- `libbpftool-dev` - for building eBPF programs


# Usage

```
unixpcap <NAME>
```

**Arguments:**

- `<NAME>`  Pcap file into which store the captured packets.

**Options:**

-  `-h`, `--help`     Print help
-  `-V`, `--version`  Print version

## Runtime Prerequisites

Kernel

- 5.10+ kernel
- Enabled `CONFIG_BPF` - for BPF support
- Enabled `CONFIG_DEBUG_INFO_BTF` - for BPF CO-RE support 

Userspace

- sufficient user rights to run eBPF programs (e.g. root access)

# Development

- Install build prerequisites.
- Install libbpftool-dev if you want code completion for BPF programs
- `vmlinux.h` has been generated using `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- **TODO**
