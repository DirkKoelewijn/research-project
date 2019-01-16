#define KBUILD_MODNAME "module"
$INCLUDES

$FUNCTIONS

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    uint64_t length = data_end - data;

    // Current offset
    uint64_t offset = 0;

    // Structs of headers used in rules
    $STRUCTS
    $CODE
    Rules:
    if (ip != NULL){
        // Drop all packets not to self
        // Condition: IPv4[dst] != 192.168.0.0/16
        if (htonl(ip->daddr) >> 16 != 49320) {
            bpf_trace_printk("$INV$\n");
            return $MATCH;
        }
    }
    $RULES

    // No match
    if (ip != NULL) {
        if (ip->ttl == $ATTACK_MARKER) bpf_trace_printk("$FN$\n");
        else if (ip->ttl == $NORMAL_MARKER) bpf_trace_printk("$TN$\n");
        else bpf_trace_printk("$UN$\n");
    }
    return $NO_MATCH;

    // Match
    Match:
    if (ip != NULL){
        if (ip->ttl == $ATTACK_MARKER) bpf_trace_printk("$TP$\n");
        else if (ip->ttl == $NORMAL_MARKER) bpf_trace_printk("$FP$\n");
        else bpf_trace_printk("$UP$\n");
    }
    return $MATCH;

    bpf_trace_printk("$UN$\n");
    return $NO_MATCH;
}
