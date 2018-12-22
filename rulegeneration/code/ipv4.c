// Check if next protocol matches IPv4
if (eth_proto == htons(ETH_P_IP)){
    struct iphdr *ip = data + offset;

     // Check if sufficient data
    if (data + offset + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Increase offset according to header itself
    offset = offset + (ip->ihl*4);

    $CODE
}