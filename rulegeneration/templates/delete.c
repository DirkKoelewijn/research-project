#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/igmp.h>

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
    struct arphdr   *arp   = NULL;
    struct tcphdr   *tcp   = NULL;
    struct udphdr   *udp   = NULL;
    struct icmphdr  *icmp  = NULL;
    struct icmp6hdr *icmp6 = NULL;
    struct igmphdr  *igmp  = NULL;

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
    else if (proto3 == ETH_P_ARP) {
    	// ARP
    	if (data + offset + sizeof(*arp) > data_end)
    	    goto Rules;

    	arp = data + offset;
    	offset += sizeof(*arp);
    }
    else {
    	goto Rules;
    }

    // OSI 4
    if (proto4 == 6 && (proto3 == ETH_P_IP || proto3 == ETH_P_IPV6)) {
    	// TCP
    	if (data + offset + sizeof(*tcp) > data_end)
    	    goto Rules;

    	tcp = data + offset;
    	offset += sizeof(*tcp);
    }
    else if (proto4 == 17 && (proto3 == ETH_P_IP || proto3 == ETH_P_IPV6)) {
    	// UDP
    	if (data + offset + sizeof(*udp) > data_end)
    	    goto Rules;

    	udp = data + offset;
    	offset += sizeof(*udp);
    }
    else if (proto4 == 1 && (proto3 == ETH_P_IP)) {
    	// ICMP
    	if (data + offset + sizeof(*icmp) > data_end)
    	    goto Rules;

    	icmp = data + offset;
    	offset += sizeof(*icmp);
    }
    else if (proto4 == 1 && (proto3 == ETH_P_IPV6)) {
    	// ICMPv6
    	if (data + offset + sizeof(*icmp6) > data_end)
    	    goto Rules;

    	icmp6 = data + offset;
    	offset += sizeof(*icmp6);
    }
    else if (proto4 == 2 && (proto3 == ETH_P_IP || proto3 == ETH_P_IPV6)) {
    	// IGMP
    	if (data + offset + sizeof(*igmp) > data_end)
    	    goto Rules;

    	igmp = data + offset;
    	offset += sizeof(*igmp);
    }
    else {
    	goto Rules;
    }

    Rules:
    if (tcp != NULL)
        bpf_trace_printk("%u\n", tcp->fin);

    return XDP_PASS;
}