from Modules import *
from util import file_str


class Program:
    """
    Class to generate BPF programs that can access packet fields
    """
    MOD = "$MODULE_NAME"
    DEFAULT_MOD = "DDoSMitigation"
    PROG = "$PROG_NAME"
    DEFAULT_PROG = "xdp_filter"
    CODE = "$CODE"
    POS = "$MATCH"
    NEG = "$NO_MATCH"

    @staticmethod
    def generate(module: Module, code: str = "", blacklist=True, mod_name=DEFAULT_MOD, prog_name=DEFAULT_PROG):
        """
        Generates a program with the initial code for the modules and the access code given as a parameter

        :param module: Module to load in
        :param code: Code to access the module fields
        :param blacklist: If true, the program will allow all packets, unless $MATCH is returned. If false, the program
                          will block all packets except if #MATCH is returned.
        :param mod_name: Name of the module
        :param prog_name: Name of the program
        :return:
        """
        template = module.get_final_template()
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
            .replace(Program.PROG, prog_name)

        if blacklist:
            result = result.replace(Program.POS, "XDP_DROP").replace(Program.NEG, "XDP_PASS")
        else:
            result = result.replace(Program.POS, "XDP_PASS").replace(Program.NEG, "XDP_DROP")

        return result


if __name__ == "__main__":
    print(Program.generate(TCPv4, file_str('code/custom_code.c')))
