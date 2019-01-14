import json

from Protocols import IPv4, UDP, TCP
from Util import file_str


class Fingerprint:
    """
    Class for parsing fingerprint files into fingerprint dicts (format: {Property: [values]})
    """
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

        # Get TCP flag
        flags = data['additional']['tcp_flag']

        for k, v in Fingerprint.__tcp_flags.items():
            if k in flags:
                result[v] = 1

        return result

    @staticmethod
    def rule_size(fingerprint):
        """
        Returns expected size if this fingerprint would be parsed to a rule

        :param fingerprint: Fingerprint as {Property: [values]} dict
        :return: Expected size as rule
        """
        res = 0
        for k, v in fingerprint:
            if isinstance(v, list):
                res += len(v)
        return res
