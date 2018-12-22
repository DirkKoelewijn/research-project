import Modules


class Program:
    MOD = "$MODULE_NAME"
    PROG = "$PROG_NAME"
    CODE = "$CODE"
    POS = "$MATCH"
    NEG = "$NO_MATCH"

    def __init__(self, module: 'Modules.Module'):
        self.__module = module
        self.__blacklist = True

    def is_blacklist(self):
        return self.__blacklist

    def set_blacklist(self, blacklist: bool):
        self.__blacklist = blacklist

    def code(self, mod_name: str, pro_name: str, code: str = "") -> str:
        result = "\n".join(self.__module.get_final_template()) \
            .replace(Program.MOD, mod_name) \
            .replace(Program.PROG, pro_name) \
            .replace(Program.CODE, code)

        if self.__blacklist:
            result = result.replace(Program.POS, "XDP_DROP").replace(Program.NEG, "XDP_PASS")
        else:
            result = result.replace(Program.POS, "XDP_PASS").replace(Program.NEG, "XDP_DROP")

        return result


if __name__ == "__main__":
    print(Program(Modules.IPv4).code("module", "xdp_filter",
                                     'bpf_trace_printk("\\nip4.dst %u\\nip4.src %u\\nip4.pro %u\\n", '
                                     'htonl(ip->saddr), htonl(ip->daddr), ip->protocol);'))
