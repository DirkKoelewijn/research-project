from util import *


# TODO DOCUMENT
class Module:

    def __init__(self, includes: {str} = None, code: str = '', dependency: 'Module' = None):
        # Set dependency
        self.dependency = dependency

        # Set includes
        if includes is None:
            includes = set()
        if dependency is None:
            self.includes = includes
        else:
            self.includes = (includes | dependency.includes)

        self.code = code.splitlines()

    def get_code_template(self):
        # Return plain code if no dependency
        if self.dependency is None:
            return self.code

        # With a dependency, it's template is the start of the result
        result = self.dependency.get_code_template()

        # Find the indentation of the $CODE
        indentation = ''
        i_code = -1
        for i, line in enumerate(result):
            if "$CODE" in line:
                indentation = line[:line.index("$CODE")]
                i_code = i
                break

        if i_code == -1:
            raise AssertionError("Template code of dependency should contain $CODE")

        # Indent the code
        own_code = self.code.copy()
        for i, line in enumerate(self.code):
            own_code[i] = indentation + line

        # Replace the line with $CODE with our code
        return result[:i_code] + own_code + result[i_code + 1:]

    def get_final_template(self):
        template = self.get_code_template()

        # Create list
        includes = list(self.includes)
        for i, include in enumerate(includes):
            includes[i] = '#include <%s>' % include

        # Find includes in template
        for i, line in enumerate(template):
            if "$INCLUDE" in line:
                return template[:i] + includes + template[i + 1:]

        raise AssertionError("Template code should contain $INCLUDE")


Program = Module(
    None,
    file_str('code/default.c'),
    None)

Ethernet = Module(
    {'linux/if_ether.h'},
    file_str('code/ethernet.c'),
    Program)

IPv4 = Module(
    {'linux/ip.h'},
    file_str('code/ipv4.c'),
    Ethernet
)

IPv6 = Module(
    {'linux/ipv6.h'},
    file_str('code/ipv6.c'),
    Ethernet
)

UDPv4 = Module(
    {'linux/udp.h'},
    file_str('code/udp4.c'),
    IPv4
)
