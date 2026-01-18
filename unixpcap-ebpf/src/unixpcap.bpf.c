// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Capture packet header
struct packet_hdr_t {
    // packet capture timestamp in nanoseconds
    uint64_t timestamp;
    // thread ID of the receiver
    uint32_t tid;
    // data length
    uint32_t data_len;
};

// Support up to 32KB packets, subtract header to make packets aligned
#define MAX_MSG_SIZE (32 * 1024 - sizeof(struct packet_hdr_t))

// Captured packet
struct packet {
    struct packet_hdr_t hdr;
    uint8_t data[MAX_MSG_SIZE];
};

// Packet capture context across fentry-fexit
// Captures the payload
// This is necessary because fexit gets access to already consumed
// iovecs in msghdr.
struct packet_ctx_t {
    // Payload
    const void *data;
    size_t len;
};

// Ring buffer for captured packets sent to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // size of ring buffer, page-aligned
    __uint(max_entries, 256 * 4096);
} captured_packets SEC(".maps");

// Per-cpu packet scratch space
// Verifiers does not let me to copy arbitrary-side msg to ring buffer
// in zero copy.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct packet));
} scratch_map SEC(".maps");

// Per-thread storage for msghdr as it appear at the fentry
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32)); // thread ID
    __uint(value_size, sizeof(struct packet_ctx_t));
} ctx_map SEC(".maps");

// Capture data pointers to the about-to-be-sent data into ctx_map.
// Real call modieis msghdr in place, destroying the original values.
// Leaves the real data capture to fexit after it is known if the data was sent.
SEC("fentry/unix_dgram_sendmsg")
int
BPF_PROG(unixpcap_dgram_save_context, struct socket *sock, struct msghdr *msg,
         size_t len) {
    u32 tid = bpf_get_current_pid_tgid();

    struct packet_ctx_t state = {};

    struct iov_iter *iter = &msg->msg_iter;
    unsigned int type = BPF_CORE_READ(iter, iter_type);
    if (type == ITER_UBUF) {
        state.data = BPF_CORE_READ(iter, __ubuf_iovec).iov_base;
        state.len = BPF_CORE_READ(iter, __ubuf_iovec).iov_len;
    } else if (type == ITER_IOVEC) {
        // IMPROVE support multiple scattered iovecs,
        // this handles just the first one.
        const struct iovec *iov = BPF_CORE_READ(iter, __iov);
        state.data = BPF_CORE_READ(iov, iov_base);
        state.len = BPF_CORE_READ(iov, iov_len);
    } else {
        // IMPROVE handle other types
        return 0;
    }

    bpf_map_update_elem(&ctx_map, &tid, &state, BPF_ANY);
    return 0;
}

// Fetch the stored context from fentry and capture the sent data into the
// ring buffer.
SEC("fexit/unix_dgram_sendmsg")
int
BPF_PROG(unixpcap_unix_dgram_capture, struct socket *sock, struct msghdr *msg,
         size_t len, int ret) {
    u32 tid = bpf_get_current_pid_tgid();
    struct packet_ctx_t *state;
    // Retrieve saved context
    state = bpf_map_lookup_elem(&ctx_map, &tid);
    if (!state)
        return 0;

    if (!state->data)
        goto cleanup;
    if (!state->len)
        goto cleanup;

    // Only capture successful sends
    if (ret < 0) {
        goto cleanup;
    }

    // Truncate very large packets
    int sent = ret;
    if (sent > MAX_MSG_SIZE) {
        sent = MAX_MSG_SIZE;
    }

    u32 zero = 0;
    struct packet *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) // should not happen, make verifier happy
        goto cleanup;

    // Bail on scattered msgs until improved
    if (len != state->len) {
        goto cleanup;
    }

    // Copy data to scratch (with verifier checks)
    if (len > 0) {
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        bpf_probe_read_user(scratch->data, len, state->data);
    }

    // Fill header
    scratch->hdr.data_len = (uint32_t)len;
    scratch->hdr.tid = (uint32_t)tid;
    // IMPROVE there are new variants (coarse, boot) in newer kernels.
    scratch->hdr.timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_output(&captured_packets, scratch, sizeof(scratch->hdr) + len,
                       0);
cleanup:
    bpf_map_delete_elem(&ctx_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
