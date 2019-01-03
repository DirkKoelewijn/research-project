import re

from util import file_str

PROTOCOL_TEMPLATE = file_str('templates/protocol.c')


# TODO DOC
class Protocol:
    def __init__(self, name, osi, includes, struct_type, struct_name, lower_protocols=None, p_id=None,
                 next_p='-1', size=None, _return=False):
        self.name = name
        self.includes = includes
        self.osi = osi
        self.struct_type = struct_type
        self.struct_name = struct_name

        if size is None:
            size = "sizeof(*%s)" % struct_name
        self.__size = size
        self.next_code = next_p

        if lower_protocols is None:
            lower_protocols = []
        self.lower_protocols = lower_protocols
        self.protocol_id = p_id
        self.__return = _return

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def load_code(self):
        result = PROTOCOL_TEMPLATE \
            .replace("$NAME", self.name) \
            .replace("$STRUCT_NAME", self.struct_name)

        if self.__return:
            result = result.replace("$NO_DATA", "return $NO_MATCH")
        else:
            result = result.replace("$NO_DATA", "goto Rules")

        result = result.replace("$SIZE", self.__size).replace("$NEXT_OSI", str(self.osi + 1))

        if str(self.next_code) != '-1':
            return result.replace("$PROTOCOL", self.next_code)
        return re.sub(r".+\$PROTOCOL.+", '', result, re.MULTILINE)

    def get_lower_protocols(self):
        res = set(self.lower_protocols)
        for p in res:
            res = res | p.get_lower_protocols()
        return res


# Protocol definitions
Ethernet = Protocol('Ethernet', 2, ['linux/if_ether.h'], 'ethhdr', 'eth', next_p='htons(eth->h_proto)', _return=True)
IPv4 = Protocol('IPv4', 3, ['linux/ip.h'], 'iphdr', 'ip', [Ethernet], 'ETH_P_IP', 'ip->protocol', 'ip->ihl*4')
IPv6 = Protocol('IPv6', 3, ['linux/ipv6.h'], 'ipv6hdr', 'ip6', [Ethernet], 'ETH_P_IPV6', 'ip6->nexthdr')
ARP = Protocol('ARP', 3, ['linux/if_arp.h'], 'arphdr', 'arp', [Ethernet], 'ETH_P_ARP')
ICMP = Protocol('ICMP', 4, ['linux/icmp.h'], 'icmphdr', 'icmp', [IPv4], '1')
ICMPv6 = Protocol('ICMPv6', 4, ['linux/icmpv6.h'], 'icmp6hdr', 'icmp6', [IPv6], '1')
IGMP = Protocol('IGMP', 4, ['linux/igmp.h'], 'igmphdr', 'igmp', [IPv4, IPv6], '2')
TCP = Protocol('TCP', 4, ['linux/tcp.h'], 'tcphdr', 'tcp', [IPv4, IPv6], '6')
UDP = Protocol('UDP', 4, ['linux/udp.h'], 'udphdr', 'udp', [IPv4, IPv6], '17')

# # TODO Add support for other protocols
# LENGTH = SimpleProperty(Ethernet, 'length')
# # TODO Move code below to protocols? (like line below)
# Ethernet.Source = MacProperty(Ethernet, 'h_source')
# ETH_SRC = MacProperty(Ethernet, 'h_source')
# ETH_DST = MacProperty(Ethernet, 'h_dest')
# ETH_PROTO = HtonsProperty(Ethernet, "h_proto")
# IP_SRC = IpProperty(IPv4, 'saddr')
# IP_DST = IpProperty(IPv4, 'daddr')
# IP_LEN = HtonsProperty(IPv4, 'tot_len')
# UDP_SRC = HtonsProperty(UDP, 'source')
# UDP_DST = HtonsProperty(UDP, 'dest')
# UDP_LEN = HtonsProperty(UDP, 'len')
# TCP_SRC = HtonsProperty(TCP, 'source')
# TCP_DST = HtonsProperty(TCP, 'dest')
# TCP_FIN = NumberProperty(TCP, 'fin')
# TCP_SYN = NumberProperty(TCP, 'syn')
# TCP_RST = NumberProperty(TCP, 'rst')
# TCP_PSH = NumberProperty(TCP, 'psh')
# TCP_ACK = NumberProperty(TCP, 'ack')
# TCP_URG = NumberProperty(TCP, 'urg')
# TCP_ECE = NumberProperty(TCP, 'ece')
# TCP_CWR = NumberProperty(TCP, 'cwr')
