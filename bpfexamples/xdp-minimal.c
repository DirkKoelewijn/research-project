#define KBUILD_MODNAME "RESEARCH_PROJECT"

int xdp_filter(struct xdp_md *ctx) {
	return XDP_DROP;
}
