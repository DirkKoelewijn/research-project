from Protocols import IPv4
from Rules import Rule

# Creating a condition is pretty easy
condition = IPv4['src'] == '1.2.3.4'

# Creating a rule with the same condition can be done in various ways:
rule = Rule(condition)  # Condition in variable
rule = Rule(IPv4['src'] == '1.2.3.4')  # Condition directly in constructor
rule = Rule(IPv4['src'], '==', '1.2.3.4')  # Separate parts of condition directly in Rule
