if (tcp->ack == 1){
    bpf_trace_printk("ACK dropped\n");
    return $MATCH;
}