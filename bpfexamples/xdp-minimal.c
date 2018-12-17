#define KBUILD_MODNAME "dkoelewijn"

int xdp_prog1(struct xdp_md *ctx) {
    bpf_trace_printk("Packet dropped\n");
    return XDP_DROP;
}