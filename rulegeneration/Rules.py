# TODO Add support for generated comment?
# Add names to functions would be required in this case
from Protocols import *


class Rule:
    BinaryComparators = ['&&', '||']
    NumericalComparators = ['==', '!=', '<', '<=', '>=', '>']

    def __init__(self, left, comp, right):
        if type(left) == Rule == type(right) and comp in Rule.BinaryComparators:
            self.end_node = False
            self.left = left
            self.comp = comp
            self.right = right
        elif isinstance(left, Properties.Property) and comp in Rule.NumericalComparators and (
                isinstance(right, int) or isinstance(right, str)):
            # Property [!<>=]= value
            self.end_node = True
            self.left = left
            self.comp = comp
            self.right = str(right)
        else:
            raise AssertionError('Rule expects (Property, Numerical Comparator, int | str) or '
                                 '(Rule, Binary Comparator, Rule)')

    @staticmethod
    def parse(*tuples: tuple, use_and=True):
        if len(tuples) == 0:
            raise AssertionError('Supply at least one condition')

        rules = [Rule(*t) for t in tuples]

        result = rules[0]
        for r in rules[1:]:
            result = result & r if use_and else result | r

        return result

    def __and__(self, other):
        return Rule(self, '&&', other)

    def __or__(self, other):
        return Rule(self, '||', other)

    def __str__(self):
        return self.code()

    def code(self):
        if self.end_node:
            return '(%s)' % self.left.compare_code(self.comp, self.right)
        else:
            return '(%s %s %s)' % (self.left, self.comp, self.right)

    def requirements(self):
        if self.end_node:
            return {self.left.proto}
        else:
            # noinspection PyUnresolvedReferences
            return self.left.requirements() | self.right.requirements()

    def dependencies(self):
        protocols = set(self.requirements())
        for p in self.requirements():
            protocols = protocols | p.get_lower_protocols()
        res = {}
        for p in protocols:
            if p.osi not in res:
                res[p.osi] = []
            res[p.osi].append(p)
        return dict(sorted(res.items()))

    def functions(self):
        if self.end_node:
            if self.left.function is not None:
                return {self.left.function}
            else:
                return set()
        else:
            # noinspection PyUnresolvedReferences
            return self.left.functions() | self.right.functions()

    def initial_condition(self):
        return ' && '.join(['%s != NULL' % p.struct_name for p in self.requirements()])


if __name__ == '__main__':
    rule = Rule.parse(IPv4['src'] == '1.2.3.4', UDP['src'] <= 123, use_and=False)
    print(rule)
