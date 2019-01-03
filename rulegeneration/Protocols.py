import re

from Properties import *
from util import file_str


class Protocol:
    """
    Class to model an OSI layer protocol
    """

    Template = file_str('templates/protocol.c')

    def __init__(self, name: str, osi: int, includes: [str], struct_type: str, struct_name: str,
                 lower_protocols: ['Protocol'] = None, p_id=None, next_p='-1', size=None, _return=False):
        """
        Initializes a protocol

        :param name: Normal name of the protocol
        :param osi: Number of the OSI layer (e.g: 2 (Ethernet))
        :param includes: List of C libraries to include
        :param struct_type: Name of the struct type in C (e.g: ethhdr)
        :param struct_name: Name to use for the struct
        :param lower_protocols: Protocols that can be below this layer
        :param p_id: Protocol ID at the lower layer
        :param next_p: Code that returns the next protocol ID
        :param size: Code that returns the true size of this protocol header (if different from sizeof(*struct))
        :param _return: Whether to directly return if the packet does not belong to this protocol
        """
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
        """
        Generates the code to load the data into the struct of the protocol
        :return: Code to load data into protocol struct
        """
        result = Protocol.Template \
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
        """
        Gets a list of all protocols that can be before this one
        :return: List of all protocols that can be before this one
        """
        res = set(self.lower_protocols)
        for p in res:
            res = res | p.get_lower_protocols()
        return res


# Protocol and property definitions
# Ethernet
Ethernet = Protocol('Ethernet', 2, ['linux/if_ether.h'], 'ethhdr', 'eth', next_p='htons(eth->h_proto)', _return=True)

Ethernet.Len = SingularProperty(Ethernet, 'length')
Ethernet.Src = MacProperty(Ethernet, 'h_source')
Ethernet.Dst = MacProperty(Ethernet, 'h_dest')
Ethernet.Next = HtonsProperty(Ethernet, "h_proto")

# IPv4
IPv4 = Protocol('IPv4', 3, ['linux/ip.h'], 'iphdr', 'ip', [Ethernet], 'ETH_P_IP', 'ip->protocol', 'ip->ihl*4')

IPv4.Src = IpProperty(IPv4, 'saddr')
IPv4.Dst = IpProperty(IPv4, 'daddr')
IPv4.Len = HtonsProperty(IPv4, 'tot_len')

# IPv6
# Properties not yet supported
IPv6 = Protocol('IPv6', 3, ['linux/ipv6.h'], 'ipv6hdr', 'ip6', [Ethernet], 'ETH_P_IPV6', 'ip6->nexthdr')

# ARP
# Properties not yet supported
ARP = Protocol('ARP', 3, ['linux/if_arp.h'], 'arphdr', 'arp', [Ethernet], 'ETH_P_ARP')

# ICMP
# Properties not yet supported
ICMP = Protocol('ICMP', 4, ['linux/icmp.h'], 'icmphdr', 'icmp', [IPv4], '1')

# ICMPv6
# Properties not yet supported
ICMPv6 = Protocol('ICMPv6', 4, ['linux/icmpv6.h'], 'icmp6hdr', 'icmp6', [IPv6], '1')

# IGMP
# Properties not yet supported
IGMP = Protocol('IGMP', 4, ['linux/igmp.h'], 'igmphdr', 'igmp', [IPv4, IPv6], '2')

# TCP
TCP = Protocol('TCP', 4, ['linux/tcp.h'], 'tcphdr', 'tcp', [IPv4, IPv6], '6')

TCP.SrcPort = HtonsProperty(TCP, 'source')
TCP.DstPort = HtonsProperty(TCP, 'dest')
TCP.Fin = NormalProperty(TCP, 'fin')
TCP.Syn = NormalProperty(TCP, 'syn')
TCP.Rst = NormalProperty(TCP, 'rst')
TCP.Psh = NormalProperty(TCP, 'psh')
TCP.Ack = NormalProperty(TCP, 'ack')
TCP.Urg = NormalProperty(TCP, 'urg')
TCP.Ece = NormalProperty(TCP, 'ece')
TCP.Cwr = NormalProperty(TCP, 'cwr')

# UDP
UDP = Protocol('UDP', 4, ['linux/udp.h'], 'udphdr', 'udp', [IPv4, IPv6], '17')

UDP.Src = HtonsProperty(UDP, 'source')
UDP.Dst = HtonsProperty(UDP, 'dest')
UDP.Len = HtonsProperty(UDP, 'len')
