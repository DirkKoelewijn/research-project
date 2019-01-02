from abc import ABC, abstractmethod

import Functions
from Protocols import *


class Property(ABC):
    function = None

    def __init__(self, proto: Protocol, name: str):
        self.proto = proto
        self.name = name

    @abstractmethod
    def compare_code(self, comparer, value: str):
        raise NotImplementedError

    def __str__(self):
        return "%s->%s" % (self.proto.struct_name, self.name)


class SimpleProperty(Property):

    def compare_code(self, comparer, value: str):
        return "%s %s %s" % (self.name, comparer, value)


class MacProperty(Property):
    function = Functions.CompareMAC

    def compare_code(self, comparer, value: str):
        chars = [str(int(char, 16)) for char in value.split(':')]
        code = "%s(%s, %s) %s 0" % (self.function.name, self, ", ".join(chars), comparer)
        return code


class HtonsProperty(Property):

    def compare_code(self, comparer, value: str):
        return "htons(%s) %s %s" % (self, comparer, value)


class IpProperty(Property):

    def compare_code(self, comparer, value: str):
        val = 0
        for v in reversed(value.split('.')):
            val = val << 8
            val += int(v)
        return "%s %s %s" % (self, comparer, val)


class NumberProperty(Property):

    def compare_code(self, comparer, value: str):
        return "%s %s %s" % (self, comparer, value)


# TODO Add support for other protocols
LENGTH = SimpleProperty(Ethernet, 'length')
# TODO Move code below to protocols? (like line below)
Ethernet.Source = MacProperty(Ethernet, 'h_source')
ETH_SRC = MacProperty(Ethernet, 'h_source')
ETH_DST = MacProperty(Ethernet, 'h_dest')
ETH_PROTO = HtonsProperty(Ethernet, "h_proto")
IP_SRC = IpProperty(IPv4, 'saddr')
IP_DST = IpProperty(IPv4, 'daddr')
IP_LEN = HtonsProperty(IPv4, 'tot_len')
UDP_SRC = HtonsProperty(UDP, 'source')
UDP_DST = HtonsProperty(UDP, 'dest')
UDP_LEN = HtonsProperty(UDP, 'len')
TCP_SRC = HtonsProperty(TCP, 'source')
TCP_DST = HtonsProperty(TCP, 'dest')
TCP_FIN = NumberProperty(TCP, 'fin')
TCP_SYN = NumberProperty(TCP, 'syn')
TCP_RST = NumberProperty(TCP, 'rst')
TCP_PSH = NumberProperty(TCP, 'psh')
TCP_ACK = NumberProperty(TCP, 'ack')
TCP_URG = NumberProperty(TCP, 'urg')
TCP_ECE = NumberProperty(TCP, 'ece')
TCP_CWR = NumberProperty(TCP, 'cwr')

if __name__ == '__main__':
    print(TCP_SRC.function)
