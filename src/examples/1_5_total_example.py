from Program import Program
from Protocols import IPv4, TCP, UDP, Ethernet
from Rules import Rule

# Filter packets from 132.68.0.0/16 larger than 250 bytes
rule1 = Rule.all(
    Ethernet['len'] > 250,
    IPv4['src'] >= '132.68.0.0',
    IPv4['src'] <= '132.68.255.255'
)

# Filter packets from port 53 (DNS) larger than 1000
rule2 = Rule.all(
    Ethernet['len'] > 1000,
    Rule.one(
        UDP['src'] == 53,
        TCP['src'] == 53
    )
)

# Generate program
Program.generate_code(rule1, rule2, file='test.c')
