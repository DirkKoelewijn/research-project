// Check if next protocol matches IPv4
if (eth_proto == htons(ETH_P_IP)){
    struct iphdr *ip = data + offset;

    // Increase offset and check if complete
    offset = offset + sizeof(*ip);
    if (data + offset > data_end)
        return $NO_MATCH;

    $CODE
}