import Properties
import Util


class Condition:
    """
    Class to model conditions for filtering network packets
    """
    BinaryComparators = ['&&', '||']
    NumericalComparators = ['==', '!=', '<', '<=', '>=', '>']
    Template = Util.file_str('templates/condition.c')

    def __init__(self, left, comp, right):
        """
        Constructs a condition from the left and right property and a comparator

        :param left: Property or rule
        :param comp: Numerical comparator if left is property, binary comparator otherwise
        :param right: Value as string/int if left is property, rule otherwise
        """
        if type(left) == Condition == type(right) and comp in Condition.BinaryComparators:
            self.end_node = False
            self.left = left
            self.comp = comp
            self.right = right
        elif isinstance(left, Properties.Property) and comp in Condition.NumericalComparators and (
                isinstance(right, int) or isinstance(right, str)):
            # Property [!<>=]= value
            self.end_node = True
            self.left = left
            self.comp = comp
            self.right = str(right)
        else:
            raise AssertionError('Condition expects (Property, Numerical Comparator, int | str) or '
                                 '(Condition, Binary Comparator, Condition)')

    @staticmethod
    def parse(*tuples: tuple, use_and=True):
        """
        Parse a condition from tuples containing left, right and comparator part

        :param tuples: Condition tuples
        :param use_and: To use and when combining rules. Will use or if false.
        :return: Parsed condition
        """
        if len(tuples) == 0:
            raise AssertionError('Supply at least one condition')

        rules = [Condition(*t) for t in tuples]

        result = rules[0]
        for r in rules[1:]:
            result = result & r if use_and else result | r

        return result

    def __and__(self, other):
        return Condition(self, '&&', other)

    def __or__(self, other):
        return Condition(self, '||', other)

    def __str__(self):
        return self.condition()

    def condition(self):
        """
        Generates the condition for the rule (excluding check for correct packet protocol)

        :return: Condition code
        """
        if self.end_node:
            return '%s' % self.left.compare_code(self.comp, self.right)
        else:
            return '(%s %s %s)' % (self.left, self.comp, self.right)

    def requirements(self):
        """
        Returns the protocols this condition uses and therefore requires to be present in a packet before applying
        :return: Required protocols
        """
        if self.end_node:
            return {self.left.proto}
        else:
            # noinspection PyUnresolvedReferences
            return self.left.requirements() | self.right.requirements()

    def dependencies(self):
        """
        Returns the protocols that need to be loaded for this condition, grouped by OSI layer
        :return: Protocols grouped by OSI layer in dict
        """
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
        """
        Returns all functions that this condition requires to be executed
        :return: Required functions
        """
        if self.end_node:
            if self.left.function is not None:
                return {self.left.function}
            else:
                return set()
        else:
            # noinspection PyUnresolvedReferences
            return self.left.functions() | self.right.functions()

    def initial_condition(self):
        """
        Generates the initial condition that checks whether the packet uses the correct protocols
        :return: Initial condition code
        """
        return ' && '.join(['%s != NULL' % p.struct_name for p in self.requirements()])

    def code(self):
        """
        Returns the total code by applying the initial condition, the comment and the condition to the template
        :return: Condition code
        """
        # Enforce brackets around condition
        condition = self.condition() if self.condition().startswith('(') else '(%s)' % self.condition()

        return Condition.Template % (self.initial_condition(), self.comment(), condition)

    def comment(self):
        """
        Generates the comment for this condition, which contains the condition in (more) readable language
        :return: Comment
        """
        if self.end_node:
            return '%s %s %s' % (self.left.name(), self.comp, self.right)
        else:
            # noinspection PyUnresolvedReferences
            return '(%s %s %s)' % (self.left.comment(), self.comp, self.right.comment())
