#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Current offset
    uint64_t offset = 0;

    // Structs of headers used in rules
    struct ethhdr   *eth   = NULL;
    struct iphdr    *ip    = NULL;
    struct ipv6hdr  *ip6   = NULL;
    struct tcphdr   *tcp   = NULL;
    
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
    else if (proto3 == ETH_P_IPV6) {
    	// IPv6
    	if (data + offset + sizeof(*ip6) > data_end)
    	    goto Rules;
    	
    	ip6 = data + offset;
    	offset += sizeof(*ip6);
    	proto4 = ip6->nexthdr;
    }
    else {
    	goto Rules;
    }
    
    // OSI 4
    uint16_t proto5 = -1;
    if (proto4 == 6 && (proto3 == ETH_P_IP || proto3 == ETH_P_IPV6)) {
    	// TCP
    	if (data + offset + sizeof(*tcp) > data_end)
    	    goto Rules;

    	tcp = data + offset;
    	offset += sizeof(*tcp);
    }
    else {
    	goto Rules;
    }
    
    Rules:
    if (tcp != NULL){
        bpf_trace_printk("TCP src: %u PSH: %u ACK: %u\n",htons(tcp->source), tcp->psh, tcp->ack);
    }

    return XDP_PASS;
}