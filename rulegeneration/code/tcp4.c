// Check if next protocol matches TCP
if (ip->protocol == 6){
    struct tcphdr *tcp = data + offset;

    // Increase offset and check if complete
    offset = offset + sizeof(*tcp);
    if (data + offset > data_end)
        return $NO_MATCH;

    $CODE
}