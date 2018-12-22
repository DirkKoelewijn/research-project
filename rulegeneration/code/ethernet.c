// Load pointers to data and end of data
void* data_end = (void*)(long)ctx->data_end;
void* data = (void*)(long)ctx->data;

// Parse the ethernet header
struct ethhdr *eth = data;

// Get ethernet header offset and return if not enough data
uint16_t eth_proto;
uint64_t eth_off = sizeof(*eth);

if (data + eth_off  > data_end)
    return $NO_MATCH;

eth_proto = eth->h_proto;

$CODE