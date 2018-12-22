#define KBUILD_MODNAME "$MODULE_NAME"
#include <linux/if_ether.h>
$INCLUDES
$FUNCTIONS

int $PROG_NAME(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Parse the ethernet header
    struct ethhdr *eth = data;

    // Get ethernet header offset and return if not enough data
    uint64_t eth_off = sizeof(*eth);
    if (data + eth_off  > data_end)
        return $NO_MATCH;

    $CODE
    return $NO_MATCH;
}