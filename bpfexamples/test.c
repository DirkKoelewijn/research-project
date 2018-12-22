#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>
#include <linux/ip.h>

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Parse the ethernet header
    struct ethhdr *eth = data;

    // Get ethernet header offset and return if not enough data
    uint16_t eth_proto;
    uint64_t offset = sizeof(*eth);

    if (data + offset  > data_end)
        return XDP_PASS;

    eth_proto = eth->h_proto;

    // Check if next protocol matches IPv4
    if (eth_proto == htons(ETH_P_IP)){
        struct iphdr *ip = data + offset;

        // Increase offset and check if complete
        offset = offset + sizeof(*ip);
        if (data + offset > data_end)
            return XDP_PASS;

        bpf_trace_printk("\nip4.dst %u\nip4.src %u\nip4.pro %u\n", htonl(ip->saddr), htonl(ip->daddr), ip->protocol);
    }
    return XDP_PASS;
}