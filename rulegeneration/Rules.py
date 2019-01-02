from Protocols import *


class Rule:
    def __init__(self, left, comp, right):
        if type(left) == Rule == type(right) and isinstance(comp, BinaryComparator):
            self.rule_type = True
            self.left = left
            self.comp = comp
            self.right = right
        elif isinstance(left, Property) and isinstance(comp, NumericalComparator) and isinstance(right, int):
            # Property [!<>=]= value
            self.rule_type = False
            self.left = left
            self.comp = comp
            self.right = right
        else:
            raise AssertionError('Rule expects (Property, NumericalComparator, int) or (Rule, BinaryComparator, Rule)')

    def __str__(self):
        if self.rule_type:
            return '(%s %s %s)' % (self.left, self.comp, self.right)
        else:
            return '(%s %s %s)' % (self.left, self.comp, self.right)


class Property:
    def __init__(self, proto: Protocol, name: str):
        self.proto = proto
        self.name = name

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
    a = Rule(Property(Ethernet, 'src'), EQ, 1)
    b = Rule(Property(Ethernet, 'dst'), EQ, 2)
    c = Rule(a, AND, b)
    print(c)
