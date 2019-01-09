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
        return Reducer.distance_aggregate(fingerprint, IPv4['src'], dist, Reducer.__conv_ip)

    @staticmethod
    def __conv_ip(ip):
        """
        Converts an ip address to an integer
        :param ip: IP address as string
        :return: IP address as integer
        """
        return int(ipaddress.IPv4Address(ip))
