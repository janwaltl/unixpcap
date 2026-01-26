// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Header of captured packet
struct packet_hdr_t {
    // packet capture timestamp in nanoseconds
    uint64_t timestamp;
    // thread ID of the receiver
    uint32_t tid;
    // original packet length
    uint16_t orig_data_len;
    // length of src_socket string in the captured packet
    uint16_t src_path_len;
    // length of dst_socket string in the captured packet
    uint16_t dst_path_len;
    // captured packet length
    uint16_t data_len;
    // padding
    uint32_t reserved;
};

#define MAX_MSG_SIZE (31 * 1024)
// Maximum socket path
#define MAX_SOCK_PATH (255)

#define MAX_PACKET_SIZE                                                        \
    (sizeof(struct packet_hdr_t) + MAX_SOCK_PATH + MAX_SOCK_PATH + MAX_MSG_SIZE)

// Packet capture context across fentry-fexit
//
// Captures the pointers to about-to-be-sent payload which is necessary because
// fexit gets access to already consumed iovecs in msghdr.
struct packet_ctx_t {
    const void *data;
    size_t len;
};

// Ring buffer for captured packets sent to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // total size of ring buffer, must be page-aligned
    __uint(max_entries, 256 * 4096);
} captured_packets SEC(".maps");

// Per-cpu packet scratch buffer.
//
// Verifier does not let me to copy arbitrary-side msg to ring buffer in zero
// copy.
//
// IMPROVE Find a zero-copy solution.
//
// Enough to save the largest packet.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_PACKET_SIZE);
} scratch_map SEC(".maps");

// Per-thread fentry-fexit context storage for msghdr as it appear at the
// fentry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32)); // thread ID
    __uint(value_size, sizeof(struct packet_ctx_t));
} ctx_map SEC(".maps");

// Capture data pointers to the about-to-be-sent data into ctx_map.
//
// Real call modifies msghdr in place, destroying the original values.
//
// Leaves the real data capture to fexit, there it is known whether the data was
// sent or not.
SEC("fentry/unix_dgram_sendmsg")
int
BPF_PROG(unixpcap_dgram_save_context, struct socket *sock, struct msghdr *msg,
         size_t len) {
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

    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ctx_map, &tid, &state, BPF_ANY);
    return 0;
}

// Capture the sent packets into the ring buffer.
//
// Fetch the stored context from fentry and capture the packet with its
// metadata into the ring buffer.
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

    if (!state->data || !state->len)
        goto cleanup;

    // Only capture successful sends
    if (ret < 0) {
        goto cleanup;
    }

    u32 zero = 0;
    void *const scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    size_t n_written = 0;
    if (!scratch) // should not happen, make verifier happy
        goto cleanup;

    // Bail on scattered msgs until improved
    if (len != state->len) {
        goto cleanup;
    }

    struct packet_hdr_t *hdr = (struct packet_hdr_t *)(scratch + n_written);
    n_written = sizeof(*hdr);

    // Capture source path
    struct unix_sock *usk = (struct unix_sock *)sock->sk;
    struct unix_address *uaddr = BPF_CORE_READ(usk, addr);
    long src_len = 0;
    if (uaddr) {
        src_len =
            bpf_probe_read_kernel_str(scratch + n_written, MAX_SOCK_PATH,
                                      BPF_CORE_READ(&uaddr->name[0], sun_path));
        if (src_len <= 0) {
            src_len = 0;
        }
        n_written += src_len;
    }

    long dst_len = 0;
    // Capture dst path
    if (BPF_CORE_READ(msg, msg_name)) {
        struct sockaddr_un *addr = BPF_CORE_READ(msg, msg_name);
        // Unconnected sendto case
        dst_len = bpf_probe_read_kernel_str(scratch + n_written, MAX_SOCK_PATH,
                                            BPF_CORE_READ(addr, sun_path));
        if (dst_len <= 0) {
            dst_len = 0;
        }
        n_written += dst_len;
    } else {
        // Connected case
        struct sock *peer_sk = BPF_CORE_READ(usk, peer);
        if (peer_sk) {
            struct socket *peer_socket = BPF_CORE_READ(peer_sk, sk_socket);
            struct file *peer_file = BPF_CORE_READ(peer_socket, file);
            struct inode *peer_inode_struct = BPF_CORE_READ(peer_file, f_inode);
            struct unix_sock *peer_usk = (struct unix_sock *)peer_sk;
            struct unix_address *peer_uaddr = BPF_CORE_READ(peer_usk, addr);
            if (peer_uaddr) {
                dst_len = bpf_probe_read_kernel_str(
                    scratch + n_written, MAX_SOCK_PATH,
                    BPF_CORE_READ(&peer_uaddr->name[0], sun_path));
                if (dst_len <= 0) {
                    dst_len = 0;
                }
                n_written += dst_len;
            }
        }
    }

    // Capture data to scratch buffer (with verifier checks)
    size_t captured_len = len;
    if (captured_len >= 0) {
        if (captured_len > MAX_MSG_SIZE) {
            captured_len = MAX_MSG_SIZE;
        }
        bpf_probe_read_user(scratch + n_written, captured_len, state->data);
        n_written += captured_len;
    }

    // Fill packet header
    hdr->orig_data_len = (uint32_t)len;
    hdr->tid = (uint32_t)tid;
    // IMPROVE there are new variants (coarse, boot) in newer kernels.
    hdr->timestamp = bpf_ktime_get_ns();
    hdr->src_path_len = src_len;
    hdr->dst_path_len = dst_len;
    hdr->data_len = captured_len;

    bpf_ringbuf_output(&captured_packets, scratch, n_written, 0);
cleanup:
    bpf_map_delete_elem(&ctx_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
