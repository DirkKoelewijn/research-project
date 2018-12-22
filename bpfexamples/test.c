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
    uint64_t eth_off = sizeof(*eth);

    if (data + eth_off  > data_end)
        return XDP_PASS;

    eth_proto = eth->h_proto;

    bpf_trace_printk("\neth.dst %llu\neth.src %llu\neth.pro %u\n", eth->h_dest, eth->h_source, eth_proto);
    return XDP_PASS;
}