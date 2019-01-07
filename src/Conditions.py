class Condition:
    """
    Helper class to enable smooth rule typing
    """

    def __init__(self, left, comp, right):
        """
        Constructs a condition

        :param left: Left part of the condition
        :param comp: Comparator
        :param right: Right part of the condition
        """
        self.left = left
        self.comp = comp
        self.right = right

    def __and__(self, other):
        return Condition(self, '&&', other)

    def __or__(self, other):
        return Condition(self, '||', other)
