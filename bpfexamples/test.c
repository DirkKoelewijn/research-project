#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>

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
        return XDP_DROP;

    eth_proto = eth->h_proto;


    return XDP_DROP;
}