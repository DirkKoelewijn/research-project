from util import file_str

PROTOCOL_TEMPLATE = file_str('templates/protocol.c')


class Protocol:
    def __init__(self, name, osi, includes, struct_type, struct_name, lower_protocols=None, protocol_id=None,
                 next_proto_code='-1', size=None, _return=False):
        self.name = name
        self.includes = includes
        self.osi = osi
        self.struct_type = struct_type
        self.struct_name = struct_name

        if size is None:
            size = "sizeof(*%s)" % struct_name
        self.__size = size
        self.__next_code = next_proto_code

        if lower_protocols is None:
            lower_protocols = []
        self.lower_protocols = lower_protocols
        self.protocol_id = protocol_id
        self.__return = _return

    def load_code(self):
        result = PROTOCOL_TEMPLATE \
            .replace("$NAME", self.name) \
            .replace("$STRUCT_NAME", self.struct_name)

        if self.__return:
            result = result.replace("$NO_DATA", "return $NO_MATCH")
        else:
            result = result.replace("$NO_DATA", "goto $LBL_RULES")

        return result.replace("$SIZE", self.__size) \
            .replace("$NEXT_OSI", str(self.osi + 1)) \
            .replace("$PROTOCOL", self.__next_code)


Ethernet = Protocol('Ethernet', 2, ['linux/if_ether.h'], 'ethhdr', 'eth', 'htons(eth->h_proto)', _return=True)

IPv4 = Protocol('IPv4', 3, ['linux/ip.h'], 'iphdr', 'ip', [Ethernet], 'ETH_P_IP', 'ip->protocol', 'ip->ihl*4')

IPv6 = Protocol('IPv6', 3, ['linux/ipv6.h'], 'ipv6hdr', 'ip6', [Ethernet], 'ETH_P_IPV6', 'ip6->nexthdr')

ARP = Protocol('ARP', 3, ['linux/if_arp.h'], 'arphdr', 'arp', [Ethernet], 'ETH_P_ARP')

ICMP = Protocol('ICMP', 4, ['linux/icmp.h'], 'icmphdr', 'icmp', [IPv4], '1')

ICMPv6 = Protocol('ICMPv6', 4, ['linux/icmpv6.h'], 'icmp6hdr', 'icmp6', [IPv6], '1')

IGMP = Protocol('IGMP', 4, ['linux/igmp.h'], 'igmphdr', 'igmp', [IPv4, IPv6], '2')

TCP = Protocol('ICP', 4, ['linux/tcp.h'], 'tcphdr', 'tcp', [IPv4, IPv6], '6')

UDP = Protocol('UDP', 4, ['linux/udp.h'], 'udphdr', 'udp', [IPv4, IPv6], '17')

if __name__ == '__main__':
    print(Ethernet.load_code())
    print(IPv4.load_code())
    print(IPv6.load_code())
