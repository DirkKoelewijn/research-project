#include <bcc/proto.h>

int filter(struct __sk_buff *skb) {

    u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

	// Drop non-IPv4 packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	bpf_trace_printk("\n"
    "--Ethernet--\n"
    "type %lu\n"
    "src  %llu\n"
    "dst  %llu\n", (unsigned long) ethernet->type, (unsigned long long) ethernet->src, (unsigned long long) ethernet->dst);

    // Get IPv4 info
	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

	bpf_trace_printk("\n"
    "--IPv4--\n"
    "nextp %u\n"
    "src   %u\n"
    "dst   %u\n", (unsigned char) ip->nextp, (unsigned int) ip->src, (unsigned int) ip->dst);


//
//	//keep the packet and send it to userspace retruning -1
//	KEEP:
//	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}