from Protocols import *


class Rule:
    def __init__(self, left, comp, right):
        if type(left) == Rule == type(right) and isinstance(comp, BinaryComparator):
            self.end_node = False
            self.left = left
            self.comp = comp
            self.right = right
        elif isinstance(left, Property) and isinstance(comp, NumericalComparator) and (
                isinstance(right, int) or isinstance(right, str)):
            # Property [!<>=]= value
            self.end_node = True
            self.left = left
            self.comp = comp
            self.right = right
        else:
            raise AssertionError('Rule expects (Property, NumericalComparator, int | str) or (Rule, BinaryComparator, '
                                 'Rule)')

    def __str__(self):
        if self.end_node:
            return '(%s %s %s)' % (self.left, self.comp, self.left.str_func(self.right))
        else:
            return '(%s %s %s)' % (self.left, self.comp, self.right)


class Property:
    def __init__(self, proto: Protocol, name: str, str_func=None):
        self.proto = proto
        self.name = name
        if str_func is None:
            str_func = lambda string: int(string)
        self.str_func = str_func

    def __str__(self):
        return '%s->%s' % (self.proto.struct_name, self.name)


ETH_SRC = Property(Ethernet, 'h_source')
ETH_DST = Property(Ethernet, 'h_dest')


class BinaryComparator:
    def __init__(self, code: str):
        self.code = code

    def __str__(self):
        return self.code


AND = BinaryComparator('&&')
OR = BinaryComparator('||')


class NumericalComparator:
    def __init__(self, code: str):
        self.code = code

    def __str__(self):
        return self.code


EQ = NumericalComparator('==')
NEQ = NumericalComparator('!=')
LT = NumericalComparator('<')
LTE = NumericalComparator('<=')
GTE = NumericalComparator('>=')
GT = NumericalComparator('>')

if __name__ == '__main__':
    a = Rule(Property(Ethernet, 'src'), EQ, '12')
    b = Rule(Property(Ethernet, 'dst'), EQ, 2)
    c = Rule(a, AND, b)
    print(c)
