from util import *


class Module:
    """
    The module class is used to generate preparing code for accessing headers of several internet protocols in a
    modular way.

    Each module other than the basic program module depends on other, lower OSI layer level modules. For instance,
    TCP can depend on IPv4 or IPv6. IPv4 and IPv6 depend on Ethernet, which depends on the basic program.

    Each module consists of:
     * a set of required C libraries
     * code to load the header into a C struct
     * a module that it depends on (except for the basic BPF program)
    """

    def __init__(self, reference: str, includes: {str} = None, code: str = '', dependency: 'Module' = None):
        """
        Initializes a Module

        :param includes: Names of C headers to include (e.g: {'linux/if_ether.h'})
        :param code: The code in one string, including line endings
        :param dependency: Optional. The highest module that it depends on
        """
        # Set reference
        self.reference = reference

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
        """
        Returns the code template of the module (including that of depending modules), without replacing the $INCLUDE.

        :return: Code template of modules
        """
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
        """
        Returns the final code template in which the $INCLUDE is also replaced.

        :return: Final code template
        """
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
    '',
    None,
    file_str('code/default.c'),
    None)

Ethernet = Module(
    'eth',
    {'linux/if_ether.h'},
    file_str('code/ethernet.c'),
    Program)

IPv4 = Module(
    'ip',
    {'linux/ip.h'},
    file_str('code/ipv4.c'),
    Ethernet
)

IPv6 = Module(
    'ip6',
    {'linux/ipv6.h'},
    file_str('code/ipv6.c'),
    Ethernet
)

UDPv4 = Module(
    'udp',
    {'linux/udp.h'},
    file_str('code/udp4.c'),
    IPv4
)

TCPv4 = Module(
    'tcp',
    {'linux/tcp.h'},
    file_str('code/tcp4.c'),
    IPv4
)
