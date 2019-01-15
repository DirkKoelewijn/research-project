import Properties
import Util
from Conditions import Condition


class Rule:
    """
    Class to model rules for filtering network packets
    """
    BinaryComparators = ['&&', '||']
    NumericalComparators = ['==', '!=', '<', '<=', '>=', '>']
    Template = Util.file_str('templates/rule.c')

    def __init__(self, left, comp=None, right=None):
        """
        Constructs a rule from:
        * a condition
        * a property, numerical comparator and value (string or int)
        * rule, binary comparator and rule

        :param left: Condition, property or rule
        :param comp: Optional. Numerical comparator if left is property, binary comparator if left is rule
        :param right: Optional. Value if left is property, rule if left is rule
        """
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
        elif isinstance(left, Condition):
            r0 = Rule(left.left) if isinstance(left.left, Condition) else left.left
            r1 = Rule(left.right) if isinstance(left.right, Condition) else left.right
            self.__init__(r0, left.comp, r1)
        elif isinstance(left, Rule):
            self.__init__(left.left, left.comp, left.right)
        else:
            raise AssertionError('Rule expects (Property, Numerical Comparator, int | str) or '
                                 '(Rule, Binary Comparator, Rule)')

    @staticmethod
    def all(item, *items):
        """
        Combines conditions or rules into one rule with and (all should be true)
        :param item: First condition or rule
        :param items: Other conditions or rules
        :return: Combined rule
        """
        items = list(items)

        if len(items) == 0:
            return Rule(item)
        elif len(items) == 1:
            return Rule(item) & Rule(items[0])
        else:
            all_items = [item] + items
            split = len(all_items) // 2
            return Rule.all(*all_items[:split]) & Rule.all(*all_items[split:])

    @staticmethod
    def one(item, *items):
        """
        Combines conditions or rules into one rule with or (one should be true)
        :param item: First condition or rule
        :param items: Other conditions or rules
        :return: Combined rule
        """
        items = list(items)

        if len(items) == 0:
            return Rule(item)
        elif len(items) == 1:
            return Rule(item) | Rule(items[0])
        else:
            all_items = [item] + items
            split = len(all_items) // 2
            return Rule.one(*all_items[:split]) | Rule.one(*all_items[split:])

    def __and__(self, other):
        return Rule(self, '&&', other)

    def __or__(self, other):
        return Rule(self, '||', other)

    def __str__(self):
        return self.condition()

    def __len__(self):
        if self.end_node:
            return 1
        else:
            # noinspection PyTypeChecker
            return len(self.left) + len(self.right)

    def condition(self):
        """
        Generates the condition for the rule (excluding check for correct packet protocol)

        :return: Rule code
        """
        if self.end_node:
            return '%s' % self.left.compare_code(self.comp, self.right)
        else:
            return '(%s %s %s)' % (self.left, self.comp, self.right)

    def requirements(self):
        """
        Returns the protocols this rule uses and therefore requires to be present in a packet before applying
        :return: Required protocols
        """
        if self.end_node:
            return {self.left.proto}
        else:
            # noinspection PyUnresolvedReferences
            return self.left.requirements() | self.right.requirements()

    def dependencies(self):
        """
        Returns the protocols that need to be loaded for this rule, grouped by OSI layer
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
        Returns all functions that this rule requires to be executed
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
        :return: Rule code
        """
        # Enforce brackets around condition
        condition = self.condition() if self.condition().startswith('(') else '(%s)' % self.condition()

        return Rule.Template % (self.initial_condition(), self.comment(), condition)

    def comment(self):
        """
        Generates the comment for this rule, which contains the rule in (more) readable language
        :return: Comment
        """
        if self.end_node:
            return '%s %s %s' % (self.left.name(), self.comp, self.right)
        else:
            # noinspection PyUnresolvedReferences
            return '(%s %s %s)' % (self.left.comment(), self.comp, self.right.comment())
