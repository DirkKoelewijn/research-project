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

         // Check if sufficient data
        if (data + offset + sizeof(*ip) > data_end)
            return XDP_PASS;

        // Increase offset according to header itself
        offset = offset + (ip->ihl*4);


    }
    return XDP_PASS;
}