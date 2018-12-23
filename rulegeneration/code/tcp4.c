// Check if next protocol matches TCP
if (ip->protocol == 6){
    struct tcphdr *tcp = data + offset;

   // Check if sufficient data
    if (data + offset + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Increase offset according to header itself
    offset = offset + (tcp->doff*4);

    $CODE
}