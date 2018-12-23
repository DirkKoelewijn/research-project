#define KBUILD_MODNAME "module"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/igmp.h>
#include <linux/if_arp.h>

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Possible headers
    struct ethhdr   *eth   = NULL;
    struct iphdr    *ip    = NULL;
    struct ipv6hdr  *ip6   = NULL;
    struct udphdr   *udp   = NULL;
    struct tcphdr   *tcp   = NULL;
    struct icmphdr  *icmp  = NULL;
    struct icmp6hdr *icmp6 = NULL;
    struct igmphdr  *igmp  = NULL;
    struct arphdr   *arp   = NULL;

    // Current offset
    uint64_t offset = 0;

    // OSI 2: Data Link layer
    // Ethernet
    uint16_t proto3;
    if (data + offset + sizeof(*eth)  > data_end){
        return XDP_PASS;            // Return if ethernet not available
    } else {
        eth = data + offset;
        offset += sizeof(*eth);
        proto3 = htons(eth->h_proto);
    }

    // OSI 3: Network layer
    // IPv4
    uint8_t proto4;     // Proto: 6 TCP, 17 UDP, 1 ICMP, 2 IGMP
    if (proto3 == ETH_P_IP){
        // Return for insufficient data
        if (data + offset + sizeof(*ip) > data_end)
            goto Rules;

        ip = data + offset;
        offset += (ip->ihl*4);
        proto4 = ip->protocol;
    }
    // IPv6
    else if (proto3 == ETH_P_IPV6){
        // Return for insufficient data
        if (data + offset + sizeof(*ip6) > data_end)
            goto Rules;

        ip6 = data + offset;
        offset += sizeof(*ip6);
    }
    // ARP
    else if (proto3 == ETH_P_ARP){
         if (data + offset + sizeof(*arp) > data_end)
            goto Rules;

        arp = data + offset;
        offset += sizeof(*arp);
    }

    // OSI 4: Transport layer
    // ICMP (1, IPv4)
    if (proto4 == 1 && proto3 == ETH_P_IP){
        if (data + offset + sizeof(*icmp) > data_end)
            goto Rules;

        icmp = data + offset;
        offset += sizeof(*icmp);
    }
    // ICMPv6 (1, IPv6)
    else if (proto4 == 1 && proto3 == ETH_P_IPV6) {
        if (data + offset + sizeof(*icmp6) > data_end)
            goto Rules;

        icmp6 = data + offset;
        offset += sizeof(*icmp6);
    }
    // IGMP (2)
    else if (proto4 == 2){
        if (data + offset + sizeof(*igmp) > data_end)
            goto Rules;

        igmp = data + offset;
        offset += sizeof(*igmp);
    }
    // TCP (6)
    else if (proto4 == 6){
        if (data + offset + sizeof(*tcp) > data_end)
            goto Rules;

        tcp = data + offset;
        offset += sizeof(*tcp);
    }
    // UDP
    else if (proto4 == 17){
        if (data + offset + sizeof(*udp) > data_end)
            goto Rules;

        udp = data + offset;
        offset += sizeof(*udp);
    }

    Rules:
    bpf_trace_printk("TCP == NULL: %d\n", (tcp == NULL));
    return XDP_PASS;
}