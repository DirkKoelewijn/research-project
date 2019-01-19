import json

from Protocols import IPv4, UDP, TCP
from Util import file_str


class Fingerprint:
    """
    Class for parsing fingerprint all_files into fingerprint dicts (format: {Property: [values]})
    """
    TCP_FLAG_KEY = 'TCP_FLAG'

    __tcp_flags = {
        'F': TCP['fin'],
        'S': TCP['syn'],
        'R': TCP['rst'],
        'P': TCP['psh'],
        'A': TCP['ack'],
        'U': TCP['urg'],
        'E': TCP['ece'],
        'C': TCP['cwr'],
    }

    @staticmethod
    def parse(file):
        """
        Parses a file into a fingerprint dict

        :param file: Name of the file
        :return: Fingerprint as {Property: [values]} dict
        """
        data = json.loads(file_str(file))
        protocol = str(data['protocol']).upper()

        if protocol == 'UDP':
            return Fingerprint.parse_udp(data)
        elif protocol == 'TCP':
            return Fingerprint.parse_tcp(data)
        else:
            raise AssertionError("Unsupported protocol!")

    @staticmethod
    def parse_default(data, src_ip, src_port, dst_port):
        """
        Parses the default parameters of a fingerprint (IPs and ports)

        :param data: Raw fingerprint data from JSON
        :param src_ip: property that holds the source ip (e.g: IPv4['src'])
        :param src_port: property that holds the source port (e.g: TCP['src])
        :param dst_port: property that holds the destination port (e.g: UDP['dst'])
        :return: Fingerprint containing default properties
        """
        return {
            'protocol': str(data['protocol']).upper(),
            src_ip: sorted(data['src_ips']),
            src_port: sorted([int(d) for d in data['src_ports']]),
            dst_port: sorted([int(d) for d in data['dst_ports']]),
        }

    @staticmethod
    def parse_udp(data):
        """
        Parses an UDP fingerprint

        :param data: JSON data
        :return: Fingerprint as {Property: [values]} dict
        """
        return Fingerprint.parse_default(data, IPv4['src'], UDP['src'], UDP['dst'])

    # noinspection PyTypeChecker
    @staticmethod
    def parse_tcp(data):
        """
        Parses a TCP fingerprint

        :param data: JSON data
        :return: Fingerprint as {Property: [values]} dict
        """
        result = Fingerprint.parse_default(data, IPv4['src'], TCP['src'], TCP['dst'])

        flags = data['additional']['tcp_flag']
        flag_map = Fingerprint.__tcp_flags

        for k, v in flag_map.items():
            if k in flags:
                result[v] = 1

        # # Get TCP flag
        # flags = data['additional']['tcp_flag']
        #
        # result[Fingerprint.TCP_FLAG_KEY] = [v for k, v in Fingerprint.__tcp_flags.items() if k in flags]

        return result

    @staticmethod
    def rule_size(fingerprint):
        """
        Returns expected size if this fingerprint would be parsed to a rule

        :param fingerprint: Fingerprint as {Property: [values]} dict
        :return: Expected size as rule
        """
        res = 0
        for v in fingerprint.values():
            res += Fingerprint.prop_size(v)
        return res

    @staticmethod
    def prop_size(values):
        """
        Returns the expected size of all values of a property (when parsed to a rule)

        :param values: List of values (single values or min-max tuples)
        :return: Amount of single values plus twice the amount of min-max tuples
        """
        if isinstance(values, list):
            return sum([(2 if isinstance(v, tuple) else 1) for v in values])
        else:
            return 1
