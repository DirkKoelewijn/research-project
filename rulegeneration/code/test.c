#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>
#include <linux/ip.h>


int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    uint64_t length = data_end - data;

    // Current offset
    uint64_t offset = 0;

    // Structs of headers used in rules
    struct ethhdr   *eth   = NULL;
    struct iphdr    *ip    = NULL;

    // OSI 2
    uint16_t proto3 = -1;
    // Ethernet
    if (data + offset + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data + offset;
    offset += sizeof(*eth);
    proto3 = htons(eth->h_proto);

    // OSI 3
    uint16_t proto4 = -1;
    if (proto3 == ETH_P_IP) {
    	// IPv4
    	if (data + offset + sizeof(*ip) > data_end)
    	    goto Rules;

    	ip = data + offset;
    	offset += ip->ihl*4;
    	proto4 = ip->protocol;
    }
    else {
    	goto Rules;
    }

    Rules:
    if (ip != NULL && ((ip->saddr == 1477051956) || (ip->saddr == 308428311))) return XDP_DROP;

    return XDP_PASS;
}