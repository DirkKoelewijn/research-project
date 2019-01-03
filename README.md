# Automated Rule Generation for DDoS Mitigation using eBPF
This repository I use(d) for my Research Project into Automated Rule Generation for DDoS mitigation using eBPF. 
Basically, this means doing three things:

1. Generate an eBPF program based on a set of filtering rules
2. Generate these filtering rules out of a DDoS attack fingerprint from [DDoSDB.org](https://ddosdb.org/).
3. Evaluate the performance of these automatically generated rules.

## Prerequisites
This repository uses the [BPF Compiler Collection](https://github.com/iovisor/bcc) to compile the code into eBPF. 
You can find the installation instructions [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

## 1. Generate an eBPF program from a set of rules
The concept is simple: We want to define rules and then convert those rules into a runnable eBPF program that filters
packets based on this same rules.

### 1.1 Basic rules
A rule consists of one ore more conditions. A basic condition consists of:

* a property (`Protocol['property']`, e.g: `IPv4['src']`)
* a numerical comparator (`==`, `!=`, `<`. `<=`, `>=`, `>`)
* a value to compare to (e.g: `1.2.3.4`)

A basic rule with a basic condition is created as shown below:
```python
from Rules import Rule
from Protocols import IPv4

# Creating a condition is pretty easy
condition = IPv4['src'] == '1.2.3.4'

# Creating a rule with the same condition can be done in various ways:
rule = Rule(condition)                      # Condition in variable
rule = Rule(IPv4['src'] == '1.2.3.4')       # Condition directly in constructor
rule = Rule(IPv4['src'], '==' ,'1.2.3.4')   # Separate parts of condition directly in Rule
```

### 1.2 Properties
Each of the properties that can be used in a condition/rule belongs to a protocol, like `IPv4` or `TCP`. Currently, the
following properties are supported:

| Protocol | Property | Description | Expected value type* | Example value |
|----------|----------|-------------|----------------------|---------------|
|`Ethernet`|`len`| Total packet length | `int in [0, 2^16)` | `41020`
|`Ethernet`|`src`| Source MAC address | `FF:FF:FF:FF:FF:FF` | `b1:30:a2:bf:0f:c7`
|`Ethernet`|`src`| Destination MAC address | `FF:FF:FF:FF:FF:FF` | `b1:30:a2:bf:0f:c7`
|`Ethernet`|`next`| Next protocol | `int in [0, 2^16)` | `41020`
|`IPv4`|`src`| Source IP address | `255.255.255.255` | `1.2.3.4`
|`IPv4`|`dst`| Destination IP address | `255.255.255.255` | `1.2.3.4`
|`IPv4`|`len`| IP packet length | `int in [0, 2^16)` | `41020`
|`TCP`|`src`| TCP source port | `int in [0, 2^16)` | `41020`
|`TCP`|`dst`| TCP destination port | `int in [0, 2^16)` | `41020`
|`TCP`|`fin`| TCP FIN flag | `0` or `1` | `1`
|`TCP`|`syn`| TCP SYN flag | `0` or `1` | `1`
|`TCP`|`rst`| TCP RST flag | `0` or `1` | `1`
|`TCP`|`psh`| TCP PSH flag | `0` or `1` | `1`
|`TCP`|`ack`| TCP ACK flag | `0` or `1` | `1`
|`TCP`|`urg`| TCP URG flag | `0` or `1` | `1`
|`TCP`|`ece`| TCP ECE flag | `0` or `1` | `1`
|`TCP`|`cwr`| TCP CWR flag | `0` or `1` | `1`
|`UDP`|`src`| UDP source port | `int in [0, 2^16)` | `41020`
|`UDP`|`dst`| UDP destination port | `int in [0, 2^16)` | `41020`
|`UDP`|`len`| UDP packet length | `int in [0, 2^16)` | `41020`

> *A numerical value can also always be entered as a string

Every property can be used with every numerical comparator (`==`, `!=`, `<`. `<=`, `>=`, `>`), as long as the value
matches the property. Please note that the IP and MAC addresses always should be supplied in a string.

Some examples of the usage of properties:
```python
from Protocols import IPv4, TCP, UDP, Ethernet

# Some valid conditions
a = Ethernet['src'] != 'b1:30:a2:bf:0f:c7'
b = IPv4['src'] < '100.0.0.0'
c = TCP['fin'] == 1
d = UDP['len'] >= 100
```

### 1.3 Combined rules
Rules and conditions can be combined indefinitely using `OR` or `AND` operations as follows:

```python
from Rules import Rule
from Protocols import IPv4, Ethernet
from Conditions import Condition

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
``` 

To avoid illegal combination of rules and conditions, using `Rule.all()` and `Rule.one()` is recommended:
```python
from Rules import Rule
from Protocols import IPv4, TCP, UDP, Ethernet

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
```

### 1.4 Generating and running program from rules
Once the rules are defined, generating a program from a set of rules is simple:
```python
from Program import Program

# Write program code to variable
code = Program.generate(rule1, rule2, ruleX, .. ,ruleN)

# Write program code to file
Program.generate(*rules, file='test.c')

# Optionally specify whitelisting
Program.generate(*rules, blacklist=False)
```

The string or file will contain all C code of the eBPF program. The directory `src/code` contains `bpf-loader.py`
which can load BPF C files into the kernel. To execute your freshly generated file:

``` bash
sudo python bpf-loader.py <filename>

# For the program generated above
sudo python bpf-loader.py test.c
```

At the moment it is not possible to feed strings directly to BPF.