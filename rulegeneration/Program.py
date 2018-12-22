import Modules
from util import file_str


class Program:
    MOD = "$MODULE_NAME"
    PROG = "$PROG_NAME"
    CODE = "$CODE"
    POS = "$MATCH"
    NEG = "$NO_MATCH"

    def __init__(self, module: 'Modules.Module', black_list=True):
        self.__module = module
        self.__blacklist = black_list

    def is_blacklist(self):
        return self.__blacklist

    def set_blacklist(self, blacklist: bool):
        self.__blacklist = blacklist

    def code(self, mod_name: str, pro_name: str, code: str = "") -> str:
        template = self.__module.get_final_template()
        code = code.splitlines(False)

        # Fix indentation of inserted code
        # TODO To utility function?
        code_index = -1
        code_indent = ''
        for i, line in enumerate(template):
            if "$CODE" in line:
                code_indent = line[:line.index("$CODE")]
                code_index = i
                break

        filled_template = template[:code_index] + [code_indent + c for c in code] + template[code_index + 1:]

        result = "\n".join(filled_template) \
            .replace(Program.MOD, mod_name) \
            .replace(Program.PROG, pro_name)

        if self.__blacklist:
            result = result.replace(Program.POS, "XDP_DROP").replace(Program.NEG, "XDP_PASS")
        else:
            result = result.replace(Program.POS, "XDP_PASS").replace(Program.NEG, "XDP_DROP")

        return result


if __name__ == "__main__":
    print(Program(Modules.TCPv4).code("module", "xdp_filter", file_str('code/custom_code.c')))
