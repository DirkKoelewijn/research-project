// Check if next protocol matches UDP
if (ip->protocol == 17){
    struct udphdr *udp = data + offset;

    // Increase offset and check if complete
    offset = offset + sizeof(*udp);
    if (data + offset > data_end)
        return $NO_MATCH;

    $CODE
}