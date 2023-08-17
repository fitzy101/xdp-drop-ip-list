#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>

#include "xdp-drop-ip-list.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct target_key);
    __type(value, bool);
    __uint(max_entries, 256);
} targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct target_key);
    __type(value, long);
    __uint(max_entries, 256);
} dropped SEC(".maps");

void incr_dropped(struct target_key *key) {
    long *value = bpf_map_lookup_elem(&dropped, key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        long newval = 1;
        bpf_map_update_elem(&dropped, key, &newval, BPF_NOEXIST);
    }
}

bool handle_ipv4(struct iphdr *iph) {
    bool drop = false;

    // Uncomment for debugging.
    // bpf_printk("iph->saddr: %u, iph->daddr: %u\n", iph->saddr, iph->daddr);

    struct target_key key = {
        .addr_family = AF_INET,
        .srcip = { 0 },
    };
    memcpy(&key.srcip[0], &iph->saddr, sizeof(key.srcip[0]));

    bool *should_drop = bpf_map_lookup_elem(&targets, &key);
    if (should_drop && *should_drop == true) {
        drop = true;
        incr_dropped(&key);
    }

    return drop;
}

bool handle_ipv6(struct ipv6hdr *ipv6h) {
    bool drop = false;

    // Uncomment for debugging.
    // bpf_printk("ipv6h->saddr: %x %x %x %x\n",
    //         ipv6h->saddr.in6_u.u6_addr32[0],
    //         ipv6h->saddr.in6_u.u6_addr32[1],
    //         ipv6h->saddr.in6_u.u6_addr32[2],
    //         ipv6h->saddr.in6_u.u6_addr32[3]);

    struct target_key key = {
        .addr_family = AF_INET6,
        .srcip = { 0 },
    };
    memcpy(&key.srcip, &ipv6h->saddr.s6_addr32, sizeof(key.srcip));

    bool *should_drop = bpf_map_lookup_elem(&targets, &key);
    if (should_drop && *should_drop == true) {
        drop = true;
        incr_dropped(&key);
    }

    return drop;
}

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx) {
    struct ethhdr *eth;
    __u64 curr_offset = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    eth = data;
    curr_offset += sizeof(struct ethhdr);
    __u16 hproto = eth->h_proto;

    size_t headroom = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + headroom > data_end) {
        // whatever you are, let the kernel handle it
        return XDP_PASS;
    }

    struct iphdr *iph;
    struct ipv6hdr *ipv6h;
    bool drop = false;

    switch (htons(hproto)) {
        case ETH_P_IP:
            if (data + curr_offset + sizeof(struct iphdr) > data_end) {
                /* invalid */
                drop = true;
                break;
            }

            iph = data + curr_offset;
            curr_offset += sizeof(struct iphdr);

            drop = handle_ipv4(iph);
            break;
        case ETH_P_IPV6:
            if (data + curr_offset + sizeof(struct ipv6hdr) > data_end) {
                /* invalid */
                drop = true;
                break;
            }

            ipv6h = data + curr_offset;
            curr_offset += sizeof(struct ipv6hdr);
            drop = handle_ipv6(ipv6h);
            break;
    }

    return drop == true ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
