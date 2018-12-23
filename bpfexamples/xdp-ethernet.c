#define KBUILD_MODNAME "RESEARCH_PROJECT"
#include <linux/if_ether.h>

int xdp_filter(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    uint16_t h_proto;
    uint64_t offset = 0;

    offset = sizeof(*eth);

    if (data + offset  > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    bpf_trace_printk("%u", h_proto);

	return XDP_DROP;
}
