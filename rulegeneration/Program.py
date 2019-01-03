import Protocols
import Rules
from Util import file_str, code_insert

PROGRAM_TEMPLATE = file_str('templates/program.c')

RULE_TEMPLATE = file_str('templates/rule.c')


# TODO Clean up
# TODO Doc
class Program:

    @staticmethod
    def generate(rules: [Rules.Rule], blacklist=True):
        # Extract dependencies from rules
        dependencies = Program.__get_dependencies(rules)

        # Generate code template based on dependencies
        result = Program.generate_template(dependencies)

        # Get and insert functions
        functions = Program.__get_functions(rules)
        func_code = '\n'.join([str(func) for func in functions])
        result = code_insert(result, '$FUNCTIONS', func_code, True)

        # Generate and insert rule code
        # TODO Move template to Rules.py
        rule_code = '\n'.join([RULE_TEMPLATE % (rule.initial_condition(), rule.code()) for rule in rules])
        result = code_insert(result, '$RULES', rule_code, True)

        if blacklist:
            result = result.replace('$NO_MATCH', 'XDP_PASS').replace('$MATCH', 'XDP_DROP')
        else:
            result = result.replace('$MATCH', 'XDP_PASS').replace('$NO_MATCH', 'XDP_DROP')

        return result

    @staticmethod
    def __get_functions(rules: [Rules.Rule]):
        functions = set()
        for r in rules:
            functions = functions | r.functions()
        return list(functions)

    @staticmethod
    def __get_dependencies(rules: [Rules.Rule]):
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
        result = PROGRAM_TEMPLATE

        # Insert include and struct code
        result = code_insert(result, '$INCLUDES', '\n'.join(Program.__include_code(deps)))
        result = code_insert(result, '$STRUCTS', '\n'.join(Program.__struct_code(deps)))

        # Loop all dependencies by layer
        for osi_layer in range(min(deps.keys()), max(deps.keys()) + 1):
            layer_protocols = deps[osi_layer]

            # Start layer code with comment and define next protocol
            layer_code = "\n// OSI %d\n" % osi_layer
            # FIXME 2-1-19 protoX variable generated regardless of whether a next layer exists
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
                    layer_code += code_insert(p_if, '$CODE', p.load_code())

                # Finish layer with: if no protocol matched, go to rules directly
                layer_code += "{\n\tgoto Rules;\n}"

            # Insert the code of the layer and go to the next
            result = code_insert(result, '$CODE', layer_code, False)

        # Return the result with the $CODE marker
        return result.replace("$CODE", "")
