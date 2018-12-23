#define KBUILD_MODNAME "module"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Possible headers
    struct ethhdr *eth = NULL;
    struct iphdr  *ip  = NULL;
    struct ip6hdr *ip6 = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;

    // Current offset
    uint64_t offset = 0;

    // OSI 2: Ethernet
    if (data + offset + sizeof(*eth)  > data_end){
        return XDP_PASS;            // Return if ethernet not available
        // TODO Go to rules with other layers?
    } else {
        eth = data + offset;
        offset += sizeof(*eth);
    }

//
//    // Check if next protocol matches IPv4
//    if (eth->h_proto == htons(ETH_P_IP)){
//        ip = data + offset;
//
//        // Check if sufficient data
//        if (data + offset + sizeof(*ip) > data_end)
//            ip = NULL;
//
//        // Increase offset according to header itself
//        offset += (ip->ihl*4);
//    }
//
//    // Check if next protocol matches TCP
//        if (ip->protocol == 6){
//            struct tcphdr *tcp = data + offset;
//
//           // Check if sufficient data
//            if (data + offset + sizeof(*tcp) > data_end)
//                return XDP_PASS;
//
//            // Increase offset according to header itself
//            offset = offset + (tcp->doff*4);
//
//            if (tcp->ack == 1){
//                bpf_trace_printk("ACK dropped\n");
//                return XDP_DROP;
//            }
//        }
    return XDP_PASS;
}