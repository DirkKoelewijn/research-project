import Conditions
import Protocols
import Util


# TODO Clean up
# TODO Doc
class Program:
    Template = Util.file_str('templates/program.c')

    @staticmethod
    def generate(rules: [Conditions.Condition], blacklist=True):
        # Extract dependencies from rules
        dependencies = Program.__get_dependencies(rules)

        # Generate code template based on dependencies
        result = Program.generate_template(dependencies)

        # Get and insert functions
        functions = Program.__get_functions(rules)
        func_code = '\n'.join([str(func) for func in functions])
        result = Util.code_insert(result, '$FUNCTIONS', func_code, True)

        # Generate and insert rule code
        rule_code = '\n'.join([rule.code() for rule in rules])
        result = Util.code_insert(result, '$RULES', rule_code, True)

        # Replace match markers with correct value
        result = result.replace('$NO_MATCH', 'XDP_PASS' if blacklist else 'XDP_DROP').replace(
            '$MATCH', 'XDP_DROP' if blacklist else 'XDP_PASS')
        return result

    @staticmethod
    def __get_functions(rules: [Conditions.Condition]):
        functions = set()
        for r in rules:
            functions = functions | r.functions()
        return list(functions)

    @staticmethod
    def __get_dependencies(rules: [Conditions.Condition]):
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
    def __get_protocols(deps):
        return [p for l in deps.values() for p in l]

    @staticmethod
    def __include_code(deps):
        return ['#include <%s>' % i for p in Program.__get_protocols(deps) for i in p.includes]

    @staticmethod
    def __struct_code(deps):
        return ['struct %-8s *%-5s = NULL;' % (p.struct_type, p.struct_name) for p in Program.__get_protocols(deps)]

    @staticmethod
    def generate_template(deps):
        # Load general template
        result = Program.Template

        # Insert include and struct code
        result = Util.code_insert(result, '$INCLUDES', '\n'.join(Program.__include_code(deps)))
        result = Util.code_insert(result, '$STRUCTS', '\n'.join(Program.__struct_code(deps)))

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


if __name__ == '__main__':
    app_data = Conditions.Condition.parse(Protocols.IPv4['src'] == '1.2.3.4')
    x = Program.generate([app_data])
    print(x)
