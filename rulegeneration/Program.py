from rulegeneration import util


class Program:
    MOD = "$MODULE_NAME"
    PROG = "$PROG_NAME"
    INCL = "$INCLUDES"
    FUNC = "$FUNCTIONS"
    CODE = "$CODE"
    POS = "$MATCH"
    NEG = "$NO_MATCH"

    def __init__(self):
        self.__program_skeleton = util.file_str('code/default.c')
        self.__blacklist = True

    def is_blacklist(self):
        return self.__blacklist

    def set_blacklist(self, blacklist: bool):
        self.__blacklist = blacklist

    def code(self, mod_name: str, pro_name: str) -> str:
        includes = ""
        functions = ""
        code = ""

        result = self.__program_skeleton.replace(Program.MOD, mod_name) \
            .replace(Program.PROG, pro_name) \
            .replace(Program.INCL, includes) \
            .replace(Program.FUNC, functions) \
            .replace(Program.CODE, code)

        if self.__blacklist:
            result = result.replace(Program.POS, "XDP_DROP").replace(Program.NEG, "XDP_PASS")
        else:
            result = result.replace(Program.POS, "XDP_PASS").replace(Program.NEG, "XDP_DROP")

        return result


print(Program().code("module", "xdp_filter"))
