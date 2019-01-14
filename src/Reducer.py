import ipaddress
from copy import deepcopy

from Protocols import IPv4


class Reducer:
    """
    Class to reduce fingerprints
    """

    @staticmethod
    def distance_aggregate(fingerprint, prop, dist, conv_func=None):
        """
        Aggregates values of a property if the distance between two properties is no more than the specified distance.
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param prop: Property of the fingerprint to aggregate on
        :param dist: Maximal distance between two values to be aggregated
        :param conv_func: Optional. Function to convert value to a numeric value
        :return: New fingerprint instance with modifications
        """
        result = deepcopy(fingerprint)
        values = result[prop]
        conv_map = None

        if len(values) <= 1:
            return result

        # Convert values if applicable
        if conv_func is not None:
            conv_map = dict([(conv_func(v), v) for v in values])
            values = list(conv_map.keys())

        # Aggregate values
        groups = []
        group = [values[0]]
        for v in values[1:]:
            if v - group[-1] <= dist:
                group.append(v)
            else:
                groups.append(group)
                group = [v]
        groups.append(group)

        # Convert values back if necessary
        if conv_map is not None:
            groups = [[conv_map[x] for x in g] for g in groups]

        # Reduce lists larger than one to min-max tuples
        values = [g[0] if len(g) == 1 else (g[0], g[-1]) for g in groups]

        result[prop] = values
        return result

    @staticmethod
    def distance_aggregate_ip(fingerprint, dist):
        """
        Aggregates source ips if the distance between two ips is no more than the specified distance.
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param dist: Maximal distance between two values to be aggregated (numeric)
        :return: New fingerprint instance with modifications
        """
        return Reducer.distance_aggregate(fingerprint, IPv4['src'], dist, Reducer.__ip_to_int)

    @staticmethod
    def __ip_to_int(ip):
        """
        Converts an ip address to an integer
        :param ip: IP address as string
        :return: IP address as integer
        """
        return int(ipaddress.IPv4Address(ip))

    @staticmethod
    def __ip_to_str(ip):
        return str(ipaddress.IPv4Address(ip))

    @staticmethod
    def shift_aggregate(fingerprint, prop, shift, conv_func=None, conv_back=None, size=16):
        result = deepcopy(fingerprint)
        values = result[prop]

        # Convert values if applicable
        if conv_func is not None and conv_back is not None:
            values = [conv_func(v) for v in values]
        elif conv_func is not None or conv_back is not None:
            raise AssertionError("Both conv_func as conv_back should be specified")

        values = list(set(sorted([v >> shift << shift for v in values])))

        if conv_back is not None:
            values = [conv_back(v) for v in values]

        values = ['%s/%s' % (v, size - shift) for v in values]

        result[prop] = values
        return result

    @staticmethod
    def shift_aggregate_ip(fingerprint, bits):
        return Reducer.shift_aggregate(fingerprint, IPv4['src'], bits, Reducer.__ip_to_int, Reducer.__ip_to_str,
                                       size=32)

    @staticmethod
    def binary_aggregate(fingerprint, prop, bits, conv_func=None, conv_back=None, size=16):
        result = deepcopy(fingerprint)
        values = result[prop]

        if len(values) <= 1:
            return result

        # Convert values if applicable
        if conv_func is not None and conv_back is not None:
            values = [conv_func(v) for v in values]
        elif conv_func is not None or conv_back is not None:
            raise AssertionError("Both conv_func as conv_back should be specified")

        # Aggregate values
        groups = []
        group = [values[0]]
        for v in values[1:]:
            if (v >> bits) == (values[-1] >> bits):
                group.append(v >> bits << bits)
            else:
                groups.append(group)
                group = [v]

        if len(group) >= 2:
            group = Reducer.__bit_min_max(group[0], bits)
        groups.append(group)

        # Convert values back if necessary
        if conv_back is not None:
            groups = [[conv_back(x) for x in g] for g in groups]

        # Reduce doubles
        groups = [g[0] if len(g) == 1 else '%s/%s' % (g[0], size - bits) for g in groups]

        result[prop] = groups
        return result

    @staticmethod
    def binary_aggregate_ip(fingerprint, bits):
        return Reducer.binary_aggregate(fingerprint, IPv4['src'], bits, Reducer.__ip_to_int, Reducer.__ip_to_str,
                                        size=32)

    @staticmethod
    def __bit_min_max(b, n):
        b_min = (b >> n) << n
        b_max = b_min | int('1' * n, 2)
        return [b_min, b_max]
