from abc import ABC, abstractmethod

import Functions


class Property(ABC):
    """
    Class to model a property of a network packet
    """
    function = None

    def __init__(self, proto, var: str, name=None):
        self.proto = proto
        self.var = var
        self.__name = var if name is None else name

    def name(self):
        return '%s[%s]' % (self.proto.name, self.__name)

    @abstractmethod
    def compare_code(self, comparer, value: str):
        """
        Generates the condition to compare the property
        :param comparer: Comparator to use (e.g: EQ(==), LTE(<=))
        :param value: The value to compare the value of the property to
        :return: Single line of code to be used in the condition
        """
        raise NotImplementedError

    def __str__(self):
        return "%s->%s" % (self.proto.struct_name, self.var)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self, '==', other

    def __ne__(self, other):
        return self, '!=', other

    def __lt__(self, other):
        return self, '<', other

    def __le__(self, other):
        return self, '<=', other

    def __ge__(self, other):
        return self, '>=', other

    def __gt__(self, other):
        return self, '>', other


class Singular(Property):
    """
    Class to model a property with a normal comparison that is not attached to a Protocol.
    The property value will be compared to the value without any conversion.
    """

    def compare_code(self, comparer, value: str):
        return "%s %s %s" % (self, comparer, value)

    def __str__(self):
        return self.var


class Normal(Property):
    """
    Class to model a property with a normal comparison. The property
    value will be compared to the value without any conversion.
    """

    def compare_code(self, comparer, value: str):
        return "%s %s %s" % (self, comparer, value)


class Htons(Property):
    """
    Class to model a property where the bytes of the property value should be reversed before comparison.
    """

    def compare_code(self, comparer, value: str):
        return "htons(%s) %s %s" % (self, comparer, value)


class MAC(Property):
    """
    Class to model a property holding a MAC address. Specify the value as 'XX:XX:XX:XX:XX:XX' (X = hexadecimal).
    """
    function = Functions.CompareMAC

    def compare_code(self, comparer, value: str):
        chars = [str(int(char, 16)) for char in value.split(':')]
        code = "%s(%s, %s) %s 0" % (self.function.name, self, ", ".join(chars), comparer)
        return code


class IpProperty(Property):
    """
    Class to model a property that holds an IP address. Specify the value as "R.R.R.R" (R = 0 <= value < 256).
    """

    def compare_code(self, comparer, value: str):
        val = 0
        for v in reversed(value.split('.')):
            val = val << 8
            val += int(v)
        return "%s %s %s" % (self, comparer, val)
