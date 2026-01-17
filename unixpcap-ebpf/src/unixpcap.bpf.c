// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

SEC("fexit/unix_dgram_recvmsg")
int
BPF_PROG(unixpcap_unix_dgram_recvmsg, struct socket *sk, struct msghdr *hdr, size_t size,
         int flags, int ret) {
	bpf_printk("Received dgram size: %d",(int)size);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
