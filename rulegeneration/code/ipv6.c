// Check if next protocol matches IPv6
if (eth_proto == htons(ETH_P_IPV6)){
    struct ipv6hdr *ip6 = data + offset;

    // Increase offset and check if complete
    offset = offset + sizeof(*ip6);
    if (data + offset > data_end)
        return $NO_MATCH;

    $CODE
}