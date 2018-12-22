#define KBUILD_MODNAME "$MODULE_NAME"
$INCLUDES

int $PROG_NAME(struct xdp_md *ctx) {
    $CODE
    return $NO_MATCH;
}