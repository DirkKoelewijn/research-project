from Protocols import IPv4, TCP, UDP, Ethernet

# Some valid conditions
a = Ethernet['src'] != 'b1:30:a2:bf:0f:c7'
b = IPv4['src'] < '100.0.0.0'
c = TCP['fin'] == 1
d = UDP['len'] >= 100
