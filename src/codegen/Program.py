import Util
from codegen import Rules, Protocols


class Program:
    """
    Class to generate BPF programs from conditions
    """
    Template = Util.file_str('templates/program.c')
    OutputFolder = 'code/'

    @staticmethod
    def __get_functions(rules: [Rules.Rule]):
        """
        Returns all functions that are required by rules

        :param rules: Rules
        :return: All required functions
        """
        functions = set()
        for c in rules:
            functions = functions | c.functions()
        return list(functions)

    @staticmethod
    def __get_dependencies(rules: [Rules.Rule]):
        """
        Returns all protocols that are required by rules

        :param rules: Rules
        :return: All used protocols
        """
        res = {}
        for deps in [r.dependencies() for r in rules]:
            for k, v in deps.items():
                if k not in res:
                    res[k] = []
                res[k].extend(v)

        for k, v in res.items():
            res[k] = list(set(v))

        return res

    @staticmethod
    def generate(*rules: Rules.Rule, file: str = None, blacklist=True):
        """
        Generates a BPF program from a list of conditions.

        If blacklisting is used, the program will drop all packets
        that match to one or more conditions. Otherwise, the program
        will drop all packets that do not match a condition.

        :param file: File to save the code to
        :param rules: List of rules
        :param blacklist: Whether to use blacklisting (Defaults to true)
        :return: Full R code of BPF program
        """
        # Extract dependencies from rules
        dependencies = Program.__get_dependencies(rules)

        # Generate code template based on dependencies
        result = Program.__generate_template(dependencies)

        # Get and insert functions
        functions = Program.__get_functions(rules)
        func_code = '\n'.join([str(func) for func in functions])
        result = Util.code_insert(result, '$FUNCTIONS', func_code, True)

        # Generate and insert condition code
        rule_code = '\n'.join([r.code() for r in rules])
        result = Util.code_insert(result, '$RULES', rule_code, True)

        # Replace match markers with correct value
        result = result.replace('$NO_MATCH', 'XDP_PASS' if blacklist else 'XDP_DROP').replace(
            '$MATCH', 'XDP_DROP' if blacklist else 'XDP_PASS')

        # Output if requested
        if file is not None:
            with open(Program.OutputFolder + file, 'w') as file:
                file.write(result)

        return result

    @staticmethod
    def __get_protocols(deps):
        """
        Gets all protocols from a set of dependencies

        :param deps: Dict with dependencies grouped by osi layer
        :return: Set of all protocols
        """
        return set([p for l in deps.values() for p in l])

    @staticmethod
    def __include_code(deps):
        """
        Returns code containing all required include statements

        :param deps: Dict with dependencies grouped by osi layer
        :return: Code fragment with include statements
        """
        return '\n'.join(['#include <%s>' % i for p in Program.__get_protocols(deps) for i in p.includes])

    @staticmethod
    def __struct_code(deps):
        """
        Returns code containing all required struct definitions

        :param deps: Dict with dependencies grouped by osi layer
        :return: Code fragment with struct definitions
        """
        return '\n'.join(
            ['struct %-8s *%-5s = NULL;' % (p.struct_type, p.struct_name) for p in Program.__get_protocols(deps)])

    @staticmethod
    def __generate_template(deps):
        """
        Generates the template code to which the rules can be added

        :param deps: Dict with dependencies grouped by osi layer
        :return: Code template in which rules can be added
        """
        # Load general template
        result = Program.Template

        # Insert include and struct code
        result = Util.code_insert(result, '$INCLUDES', Program.__include_code(deps))
        result = Util.code_insert(result, '$STRUCTS', Program.__struct_code(deps))

        # Loop all dependencies by layer
        for osi_layer in range(min(deps.keys()), max(deps.keys()) + 1):
            layer_protocols = deps[osi_layer]

            # Start layer code with comment and define next protocol
            layer_code = "\n// OSI %d\n" % osi_layer
            layer_code += "uint16_t proto%s = -1;\n" % (osi_layer + 1)

            # Add loading of protocols
            if osi_layer == min(deps.keys()):
                # Lowest layer (Ethernet) only has one protocol and does not need a 'switch'
                layer_code += layer_protocols[0].load_code()
            else:
                # Higher layer protocols should check if the packet uses this protocol
                if_template = "if (proto%d == %s%s) {\n\t$CODE\n}\nelse "

                # Loop all layers to create the correct condition and load code
                for p in layer_protocols:

                    # Make sure that only matching lower protocols are matched
                    and_clause = ''
                    if p.osi - 1 > Protocols.Ethernet.osi:
                        and_clause = ' && (' + ' || '.join(
                            ['proto%s == %s' % (p.osi - 1, dep.protocol_id) for dep in p.lower_protocols]) + ")"

                    # Apply clause and code
                    p_if = if_template % (p.osi, p.protocol_id, and_clause)
                    layer_code += Util.code_insert(p_if, '$CODE', p.load_code())

                # Finish layer with: if no protocol matched, go to rules directly
                layer_code += "{\n\tgoto Rules;\n}"

            # Insert the code of the layer and go to the next
            result = Util.code_insert(result, '$CODE', layer_code, False)

        # Return the result with the $CODE marker
        return result.replace("$CODE", "")
