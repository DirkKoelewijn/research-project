from time import time

from bcc import BPF

import Rules
import Util
from Fingerprints import Fingerprint
from Protocols import TCP, UDP, IPv4, Ethernet
from RuleParsing import RuleParser


class Program:
    """
    Class to model BPF programs and generate them from rules
    """

    Device = "enp0s25"
    Function = 'xdp_filter'
    Template = Util.file_str('templates/program.c')
    FingerprintFolder = 'fingerprints/'
    OutputFolder = 'programs/'
    SaveFolder = 'results/'
    MaxPropCount = 1000
    AttackMarker = '10'
    NormalMarker = '20'

    def __init__(self, fingerprint, name=None, match_all_but=0, original=None, func=Function, dev=Device):
        """
        Initializes a program

        :param fingerprint: fingerprint of the program
        :param name: Optional. Name or identifier of the program
        :param func: Optional. Function name of the program
        :param dev: Optional. Device the program should run on
        """
        self.name = name
        self.__fingerprint = fingerprint

        if original is None:
            original = fingerprint
        self.__original = original

        if match_all_but <= 0:
            self.__code = Program.generate_code(RuleParser.parse(fingerprint), match_all_but=0)
        else:
            self.__code = Program.generate_code(*RuleParser.parse(fingerprint, False), match_all_but=match_all_but)

        # Find protocol
        protocol = fingerprint['protocol']
        if protocol == 'TCP':
            p = TCP
        elif protocol == 'UDP':
            p = UDP
        else:
            raise AssertionError('Protocol not yet supported by Program.generate()')

        # Parse sizes
        self.__src_ips = Fingerprint.prop_size(fingerprint[IPv4['src']])
        self.__src_ports = Fingerprint.prop_size(fingerprint[p['src']])
        self.__dst_ports = Fingerprint.prop_size(fingerprint[p['dst']])
        self.__o_src_ips = Fingerprint.prop_size(original[IPv4['src']])
        self.__o_src_ports = Fingerprint.prop_size(original[p['src']])
        self.__o_dst_ports = Fingerprint.prop_size(original[p['dst']])
        self.__bpf = None
        self.__func = func
        self.__dev = dev

    def __str__(self):
        return self.__code

    def start(self):
        """
        Compiles the BPF program and attaches it to the kernel
        Can only be used when python has sudo permission
        """
        self.__bpf = BPF(text=self.__code)
        fn = self.__bpf.load_func(self.__func, BPF.XDP)
        self.__bpf.attach_xdp(self.__dev, fn, 0)

    def stop(self):
        """
        Stops (detaches) a running BPF program from the kernel
        """
        self.__bpf.remove_xdp(self.__dev, 0)

    def test_run(self, t, save=False, return_csv_data=False, verbose=True):
        """
        Activates the program for <time> seconds
        :param verbose: Whether to print output
        :param t: Time to activate in seconds
        :param save: Whether to save the test result
        :param return_csv_data: If true, this will return the CSV data instead of the result data
        :return: Test results
        """
        result = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0, 'UP': 0, 'UN': 0, 'INV': 0}

        try:
            if verbose:
                print('Loading program', flush=True)
            self.start()
            if verbose:
                print('Attached program', flush=True)

            # Measure
            keywords = dict([('$%s$' % k, k) for k in result.keys()])

            start = time()
            while time() - start < t:
                line = str(self.__bpf.trace_readline(nonblocking=True))
                if line == 'b\'\'':
                    continue
                for k in keywords:
                    if k in line:
                        result[keywords[k]] += 1
                        continue

        finally:
            self.stop()
            if verbose:
                print('Detached program', flush=True)

            if save:
                self.save_test_run(result)
            if return_csv_data:
                return self.csv_data(result)
            return result

    def csv_data(self, results):
        """
        Returns the CSV data for a set of results

        :param results: Results of a run
        :return:
        """
        return [
            self.name,
            self.__fingerprint['protocol'],
            self.__o_src_ips,
            self.__o_src_ports,
            self.__o_dst_ports,
            self.__src_ips,
            self.__src_ports,
            self.__dst_ports,
            results['TP'],
            results['FP'],
            results['UP'],
            results['TN'],
            results['FN'],
            results['UN']
        ]

    def save_test_run(self, results):
        """
        Saves the result of the test run to a CSV

        :param results: Results of a run
        """
        data = self.csv_data(results)

        with open(Program.SaveFolder + self.name + '.csv', 'w') as file:
            file.write(','.join([str(d) for d in data]))

    def save(self, folder=None):
        """
        Saves the program to the file <name>.c

        :param folder: Specified folder or Program.OutputFolder
        """
        if folder is None:
            folder = Program.OutputFolder

        with open(folder + self.name + '.c', 'w') as file:
            file.write(self.__code)

    @staticmethod
    def load(f_name, folder=None, match_all_but=0):
        """
        Loads a program from a fingerprint

        :param f_name: Name of the fingerprint (excluding .json)
        :param folder: Specified folder or Program.OutputFolder
        :param match_all_but: Match all but X rules to drop
        :return: Loaded program
        """
        if folder is None:
            folder = Program.FingerprintFolder

        f = Fingerprint.parse(folder + f_name + '.json')
        return Program.generate(f, f_name, match_all_but=match_all_but)

    @staticmethod
    def secure_div(a, b):
        """
        Performs a secure a / b, returning a '-' if b is zero
        :param a: First number
        :param b: Second number
        :return: Result of division or '-' if a ZeroDivisionError occurred
        """
        try:
            return a / b
        except ZeroDivisionError:
            return '-'

    @staticmethod
    def print_analysis(analysis: dict, simple=False):
        """
        Prints the analysis to stdout
        :param analysis: Analysis data like generated by start()
        :param simple: Optional. If true, only a simple matrix of the analysis is printed
        """
        if not simple:
            print('\n--- ANALYSIS RESULTS ---\n')
            info_line = '%-20s : %-10d'
            all_packets = sum(analysis.values())
            print(info_line % ('Packets captured:', all_packets))
            classified_packets = sum([v for k, v in analysis.items() if not k.startswith('U') and k is not 'INV'])
            print(info_line % ('  classified:', classified_packets))
            invalid_packets = analysis['INV']
            print(info_line % ('  unclassified:', all_packets - classified_packets - invalid_packets))
            print(info_line % ('  other destination*', invalid_packets))
            print('\n* some attack captures contain non-attack data. '
                  'This non-attack data has an external IP address and is dropped on receival.')

            tpr = Program.secure_div(analysis['TP'], analysis['TP'] + analysis['FN'])
            tnr = Program.secure_div(analysis['TN'], analysis['TN'] + analysis['FP'])
            ppv = Program.secure_div(analysis['TP'], analysis['TP'] + analysis['FP'])
            npv = Program.secure_div(analysis['TN'], analysis['TN'] + analysis['FN'])
            accuracy = Program.secure_div(analysis['TP'] + analysis['TN'], classified_packets)

            table_line = '%-20s | %-20s | %-20s | %-20s'

            print()
            print(table_line % ('', 'Attack', 'Normal', 'Predictive value'))
            print(table_line % ('-' * 20, '-' * 20, '-' * 20, '-' * 20))
            print(table_line % ('Dropped', analysis['TP'], analysis['FP'], ppv))
            print(table_line % ('Passed', analysis['FN'], analysis['TN'], npv))
            print(table_line % ('True rate', tpr, tnr, ''))
            print()

            print('Accuracy: ', accuracy)
            print('\n--- END OF ANALYSIS ---\n')
        else:
            table_line = '%-10d %-10d %-10d'
            print(table_line % (analysis['TP'], analysis['FP'], analysis['UP']))
            print(table_line % (analysis['FN'], analysis['TN'], analysis['UN']))

    @staticmethod
    def generate(fingerprint, name='unknown', match_all_but=0):
        """
        Generates a program from a fingerprint

        :param match_all_but: Match all but X rules to drop
        :param fingerprint: Fingerprint
        :param name: Optional. Name of the program.
        :return: New program
        """
        return Program(fingerprint, name, match_all_but=match_all_but)

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
    def generate_code(*rules: Rules.Rule, file: str = None, match_all_but=0, blacklist=True):
        """
        Generates a BPF program from a list of conditions.

        If blacklisting is used, the program will drop all packets
        that match to one or more conditions. Otherwise, the program
        will drop all packets that do not match a condition.

        :param file: File to save the code to
        :param rules: List of rules
        :param blacklist: Whether to use blacklisting (Defaults to true)
        :return: Full C code of BPF program
        """
        # Check property count
        prop_count = sum([len(r) for r in rules])
        if prop_count > Program.MaxPropCount:
            raise AssertionError(
                "The number of properties in all rules together is limited to %s (Properties in these rules: %s)" % (
                    Program.MaxPropCount, prop_count))

        # Extract dependencies from rules
        dependencies = Program.__get_dependencies(rules)

        # TODO Check for mandatory IPv4 presence

        # Generate code template based on dependencies
        result = Program.__generate_template(dependencies)

        # Get and insert functions
        functions = Program.__get_functions(rules)
        func_code = '\n'.join([str(func) for func in functions])
        result = Util.code_insert(result, '$FUNCTIONS$', func_code, True)

        # Generate and insert condition code
        rule_code = '\n'.join([r.code() for r in rules])
        result = Util.code_insert(result, '$RULES$', rule_code, True)

        # Replace match markers with correct value
        result = result.replace('$NO_MATCH$', 'XDP_PASS' if blacklist else 'XDP_DROP').replace(
            '$MATCH$', 'XDP_DROP' if blacklist else 'XDP_PASS')

        # Replace attack and normal traffic markers with correct values
        result = result.replace('$ATTACK_MARKER$', Program.AttackMarker).replace('$NORMAL_MARKER$',
                                                                                 Program.NormalMarker)

        # Replace match count
        result = result.replace('$MATCHED$', str(len(rules) - match_all_but))

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
        result = Util.code_insert(result, '$INCLUDES$', Program.__include_code(deps))
        result = Util.code_insert(result, '$STRUCTS$', Program.__struct_code(deps))

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
                if_template = "if (proto%d == %s%s) {\n\t$CODE$\n}\nelse "

                # Loop all layers to create the correct condition and load code
                for p in layer_protocols:

                    # Make sure that only matching lower protocols are matched
                    and_clause = ''
                    if p.osi - 1 > Ethernet.osi:
                        and_clause = ' && (' + ' || '.join(
                            ['proto%s == %s' % (p.osi - 1, dep.protocol_id) for dep in p.lower_protocols]) + ")"

                    # Apply clause and code
                    p_if = if_template % (p.osi, p.protocol_id, and_clause)
                    layer_code += Util.code_insert(p_if, '$CODE$', p.load_code())

                # Finish layer with: if no protocol matched, go to rules directly
                layer_code += "{\n\tgoto Rules;\n}"

            # Insert the code of the layer and go to the next
            result = Util.code_insert(result, '$CODE$', layer_code, False)

        # Return the result with the $CODE marker
        return result.replace("$CODE$", "")


if __name__ == '__main__':
    program = Program.load('1a2e433cfed7bde38732f0892fbbff27')
    print(program.test_run(5))
