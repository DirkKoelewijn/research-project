import json

from Program import Program
from Protocols import IPv4, UDP, TCP
from Util import file_str
from rulegen.SimpleRuleGenerator import SimpleRuleGenerator


class Fingerprint:
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
        data = json.loads(file_str(file))
        protocol = str(data['protocol']).upper()

        if protocol == 'UDP':
            return Fingerprint.parse_udp(data)
        elif protocol == 'TCP':
            return Fingerprint.parse_tcp(data)

    @staticmethod
    def parse_default(data, src_ip, src_port, dst_port):
        return {
            src_ip: sorted(data['src_ips']),
            src_port: sorted([int(d) for d in data['src_ports']]),
            dst_port: sorted([int(d) for d in data['dst_ports']]),
        }

    @staticmethod
    def parse_udp(data):
        return Fingerprint.parse_default(data, IPv4['src'], UDP['src'], UDP['dst'])

    @staticmethod
    def parse_tcp(data):
        result = Fingerprint.parse_default(data, IPv4['src'], TCP['src'], TCP['dst'])

        # Get TCP flag
        flags = data['additional']['tcp_flag']

        for k, v in Fingerprint.__tcp_flags.items():
            if k in flags:
                result[v] = 1

        return result


if __name__ == '__main__':
    fingerprint = Fingerprint.parse('fingerprints/1714test.json')

    for k, v in fingerprint.items():
        if isinstance(v, list):
            print(k, len(v))

    rules = SimpleRuleGenerator().generate(fingerprint)
    print(len(rules))
    Program.generate(rules, file='output.c')
