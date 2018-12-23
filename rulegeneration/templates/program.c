#define KBUILD_MODNAME "module"
$INCLUDES

int xdp_filter(struct xdp_md *ctx) {
    // Load pointers to data and end of data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Current offset
    uint64_t offset = 0;

    // Structs of headers used in rules
    $STRUCTS
    $CODE
    $LBL_RULES:
    $RULES

    return $NO_MATCH;
}
