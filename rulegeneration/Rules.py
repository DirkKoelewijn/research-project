from Properties import *


# TODO Add support for generated comment?
# Add names to functions would be required in this case
class Rule:
    def __init__(self, left, comp, right):
        if type(left) == Rule == type(right) and isinstance(comp, Comparator) and comp.is_binary():
            self.end_node = False
            self.left = left
            self.comp = comp
            self.right = right
        elif isinstance(left, Property) and isinstance(comp, Comparator) and comp.is_numeric and (
                isinstance(right, int) or isinstance(right, str)):
            # Property [!<>=]= value
            self.end_node = True
            self.left = left
            self.comp = comp
            self.right = str(right)
        else:
            raise AssertionError('Rule expects (Property, Comparator(num), int | str) or (Rule, Comparator(bin), '
                                 'Rule)')

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


class Comparator:

    def __init__(self, string, binary=False):
        self.string = string
        self.binary = binary

    def is_binary(self):
        return self.binary

    def is_numeric(self):
        return not self.binary

    def __str__(self):
        return self.string


Comparator.AND = Comparator('&&', True)
Comparator.OR = Comparator('||', True)
Comparator.EQ = Comparator('==')
Comparator.NEQ = Comparator('!=')
Comparator.LT = Comparator('<')
Comparator.LTE = Comparator('<=')
Comparator.GT = Comparator('>')
Comparator.GTE = Comparator('>=')

if __name__ == '__main__':
    a = Rule(IP_SRC, Comparator.EQ, '140.82.118.4')
    b = Rule(TCP_SRC, Comparator.GTE, '1024')
    c = Rule(a, Comparator.AND, b)
    print(c.requirements())
    print(c.initial_condition())
    print(c.dependencies())
    print(c.functions())
    print(c)
