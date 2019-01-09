from Conditions import Condition
from Protocols import IPv4, Ethernet, TCP, UDP
from Rules import Rule

# Some valid conditions
a = Ethernet['src'] != 'b1:30:a2:bf:0f:c7'
b = IPv4['src'] < '100.0.0.0'

# Combine conditions by AND
cond = a & b
cond = Condition(a, '&&', b)
rule = Rule.all(a, b)
rule = Rule(Rule(a), '&&', Rule(b))

# Combine conditions by OR
cond = a | b
cond = Condition(a, '||', b)
rule = Rule.one(a, b)
rule = Rule(Rule(a), '||', Rule(b))

# THIS WON'T WORK: Conditions cannot be combined with rules with & and |
error = Rule(a) | b
# But can be combined with Rule.all() and Rule.one()
working = Rule.all(Rule(a), b)

# Recommended way to create more complex rules
rule = Rule.all(
    Rule.one(
        Ethernet['src'] != 'b1:30:a2:bf:0f:c7',
        IPv4['src'] < '100.0.0.0',
        IPv4['len'] >= 100
    ), Rule.one(
        TCP['fin'] == 1,
        UDP['len'] >= 100
    )
)
