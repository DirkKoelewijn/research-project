import ipaddress
from copy import deepcopy

from Fingerprints import Fingerprint
from Program import Program
from Protocols import IPv4, UDP, TCP


class Reducer:
    """
    Class to reduce fingerprints
    """

    @staticmethod
    def auto_reduce(fingerprint, max_prop_count=Program.MaxPropCount):
        if Fingerprint.rule_size(fingerprint) <= max_prop_count:
            return deepcopy(fingerprint)

        ip = IPv4['src']
        if fingerprint['protocol'] == 'UDP':
            src, dst = (UDP['src'], UDP['dst'])
        elif fingerprint['protocol'] == 'TCP':
            src, dst = (TCP['src'], TCP['dst'])
        else:
            raise AssertionError("Auto reduce does not support protocol %s" % fingerprint['protocol'])

        # Reduce all properties to fall under the max prop count
        minimal_reducing = {}
        for p in [ip, src, dst]:
            minimal_reducing[p] = {}
            f, s = Reducer.auto_reduce_property(fingerprint, p, max_prop_count)

            for i in range(s, p.size):
                f = Reducer.reduce_property(fingerprint, p, i)
                c = Fingerprint.prop_size(f[p])
                minimal_reducing[p][i] = (c, Reducer.possible_combinations(f, p))

                # Stop if only one property is left
                if c == 1:
                    break

            tmp = {}
            for s, t in minimal_reducing[p].items():
                if t not in tmp.values():
                    tmp[s] = t

            minimal_reducing[p] = tmp

        combinations = dict([((i, s, d), (a[1] * b[1] * c[1]))
                             for i, a in minimal_reducing[ip].items()
                             for s, b in minimal_reducing[src].items()
                             for d, c in minimal_reducing[dst].items()])

        min_comb = min(combinations.values())

        optimal = [k for k, v in combinations.items() if v == min_comb][0]

        result = Reducer.reduce_property(fingerprint, ip, optimal[0])
        result = Reducer.reduce_property(result, src, optimal[1])
        result = Reducer.reduce_property(result, dst, optimal[2])

        return result

    @staticmethod
    def possible_ip_port_combinations(fingerprint):
        ip_count = Reducer.possible_combinations(fingerprint, IPv4['src'])

        if UDP['src'] in fingerprint:
            src_port = UDP['src']
            dst_port = UDP['dst']
        else:
            src_port = TCP['src']
            dst_port = TCP['dst']

        src_port_count = Reducer.possible_combinations(fingerprint, src_port)
        dst_port_count = Reducer.possible_combinations(fingerprint, dst_port)

        return ip_count * src_port_count * dst_port_count

    @staticmethod
    def possible_combinations(fingerprint, prop):
        values = fingerprint[prop]
        total = 0
        for value in values:
            if '/' in str(value):
                post_slash = int(value.split('/')[1])
                total += 2 ** (prop.size - post_slash)
            else:
                total += 1
        return total

    @staticmethod
    def auto_reduce_property(fingerprint, prop, max_props):
        res = fingerprint
        i = 0
        while Fingerprint.prop_size(res[prop]) > max_props:
            i += 1
            res = Reducer.reduce_property(fingerprint, prop, i)

        return res, i

    @staticmethod
    def reduce_property(fingerprint, prop, i):
        conv_func, conv_back = (None, None)
        if prop is IPv4['src']:
            conv_func, conv_back = (Reducer.__ip_to_int, Reducer.__ip_to_str)

        return Reducer.shift_aggregate(fingerprint, prop, i, conv_func, conv_back)

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
        """
        Converts an ip address as integer to a string
        :param ip: IP address as integer
        :return: IP address as string
        """
        return str(ipaddress.IPv4Address(ip))

    @staticmethod
    def shift_aggregate(fingerprint, prop, shift, conv_func=None, conv_back=None):
        """
        Makes a fingerprint only use the first (size-shift) bits of a property for comparison and removes duplicates
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param prop: Property of the fingerprint to aggregate on
        :param shift: Number of bits to 'throw away'
        :param conv_func: Optional. Function to convert value to a numeric value
        :param conv_back: Optional. Function to convert a numeric value back
        :return: New fingerprint instance with modifications
        """
        result = deepcopy(fingerprint)
        values = result[prop]

        # Convert values if applicable
        if conv_func is not None and conv_back is not None:
            values = [conv_func(v) for v in values]
        elif conv_func is not None or conv_back is not None:
            raise AssertionError("Both conv_func as conv_back should be specified")

        values = sorted(list(set([(v >> shift, shift) for v in values])))

        # Merge if possible
        res = []
        for v, s in values:
            # Add component to list
            res.append((v, s))

            while len(res) >= 2 and (res[-1][1] == res[-2][1]) and (res[-1][0] >> 1 == res[-2][0] >> 1):
                res = res[:-2] + [(res[-1][0] >> 1, res[-1][1] + 1)]

        values = res

        if conv_back is not None:
            values = [(conv_back(v << s), s) for v, s in values]

        values = ['%s/%s' % (v, prop.size - s) for v, s in values]

        result[prop] = values
        return result

    @staticmethod
    def shift_aggregate_ip(fingerprint, shift):
        """
        Makes a fingerprint only use the first (size-shift) bits of ips for comparison and removes duplicates
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param shift: Number of bits to 'throw away'
        :return: New fingerprint instance with modifications
        """
        return Reducer.shift_aggregate(fingerprint, IPv4['src'], shift, Reducer.__ip_to_int, Reducer.__ip_to_str)

    @staticmethod
    def binary_aggregate(fingerprint, prop, shift, conv_func=None, conv_back=None, size=16):
        """
        Aggregates property values if values have the first (size-shift) bits in common.
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param prop: Property of the fingerprint to aggregate on
        :param shift: Number of bits to 'throw away'
        :param conv_func: Optional. Function to convert value to a numeric value
        :param conv_back: Optional. Function to convert a numeric value back
        :param size: Size of the variable in bits
        :return: New fingerprint instance with modifications
        """
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
            if (v >> shift) == (values[-1] >> shift):
                group.append(v >> shift << shift)
            else:
                groups.append(group)
                group = [v]

        if len(group) >= 2:
            group = Reducer.__bit_min_max(group[0], shift)
        groups.append(group)

        # Convert values back if necessary
        if conv_back is not None:
            groups = [[conv_back(x) for x in g] for g in groups]

        # Reduce doubles
        groups = [g[0] if len(g) == 1 else '%s/%s' % (g[0], size - shift) for g in groups]

        result[prop] = groups
        return result

    @staticmethod
    def binary_aggregate_ip(fingerprint, shift):
        """
        Makes a fingerprint only use the first (size-shift) bits of ips for comparison and removes duplicates
        The original fingerprint stays untouched, as this function uses deepcopy before applying any modifications.

        :param fingerprint: Fingerprint to aggregate on
        :param shift: Number of bits to 'throw away'
        :return: New fingerprint instance with modifications
        """
        return Reducer.binary_aggregate(fingerprint, IPv4['src'], shift, Reducer.__ip_to_int, Reducer.__ip_to_str,
                                        size=32)

    @staticmethod
    def __bit_min_max(b, n):
        b_min = (b >> n) << n
        b_max = b_min | int('1' * n, 2)
        return [b_min, b_max]
