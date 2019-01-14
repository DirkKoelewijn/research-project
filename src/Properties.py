from abc import ABC, abstractmethod

import Functions
from Conditions import Condition


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

    def __hash__(self):
        return self.name().__hash__()

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
        return Condition(self, '==', other)

    def __ne__(self, other):
        return Condition(self, '!=', other)

    def __lt__(self, other):
        return Condition(self, '<', other)

    def __le__(self, other):
        return Condition(self, '<=', other)

    def __ge__(self, other):
        return Condition(self, '>=', other)

    def __gt__(self, other):
        return Condition(self, '>', other)

    @staticmethod
    def parse_shift(value):
        """
        Retrieves the shift for a given value

        :param value: Value (format: VALUE/SHIFT)
        :return: Tuple of (value, shift)
        """
        shift = -1
        if '/' in value:
            i = value.index('/')
            shift = 32 - int(value[i + 1:])
            value = value[:i]

        return shift, value


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
        shift, value = Property.parse_shift(value)

        if shift == -1:
            return "htons(%s) %s %s" % (self, comparer, value)
        else:
            return "htons(%s) >> %s %s %s" % (self, shift, comparer, value >> shift)


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
        shift, value = Property.parse_shift(value)

        val = 0
        for v in value.split('.'):
            val = val << 8
            val += int(v)

        if shift <= 0:
            return "htonl(%s) %s %s" % (self, comparer, val)
        else:
            return "htonl(%s) >> %s %s %s" % (self, shift, comparer, val >> shift)
