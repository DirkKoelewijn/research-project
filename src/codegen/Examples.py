from codegen.Protocols import IPv4, TCP
from codegen.Rules import Rule

# Easy rule typing
ips = Rule.one(IPv4['src'] == '1.2.3.4', IPv4['src'] == '2.3.4.5')
ports = Rule.one(TCP['src'] == 80, TCP['src'] == 82)
rule = Rule.all(ips, ports)
print(rule)

# Other notation could be:
ips = (IPv4['src'] == '1.2.3.4') | (IPv4['src'] == '2.3.4.5')
ports = (TCP['src'] == 80) | (TCP['src'] == 89)
rule = Rule(ips & ports)
print(rule)
