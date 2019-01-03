# Automated Rule Generation for DDoS Mitigation using eBPF
This repository I use(d) for my Research Project into Automated Rule Generation for DDoS mitigation using eBPF. 
Basically, this means doing three things:

1. Generate an eBPF program based on a set of filtering rules
2. Generate these filtering rules out of a DDoS attack fingerprint from [DDoSDB.org](https://ddosdb.org/).
3. Evaluate the performance of these automatically generated rules.


## Prerequisites
This repository uses the [BPF Compiler Collection](https://github.com/iovisor/bcc) to compile the code into BPF. 
You can find the installation instructions [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).


## Short introduction

### 1. Generate an eBPF program from a set of rules
The concept is very simple: We have rules and we want to have a program that filters packets matching one of our rules.
Likewise, we can also only allow packets that match one of our rules.

Let's say we would like to filter all HTTP and TLS packets from DDoSDB.org. HTTP uses port `80`, TLS uses port `443` and
 DDoSDB is located at `104.28.22.236`. To create the rules for this, we could do the following:

```python
from Protocols import IPv4, TCP
from Rules import Rule

# Create two rules
tls     = Rule.parse(TCP['src'] == 443, IPv4['src'] == '104.28.22.236')
http    = Rule.parse(TCP['src'] == 80 , IPv4['src'] == '104.28.22.236')

# However, it would be more efficient if we would do it in one rule
port    = Rule.parse(TCP['src'] == 443, TCP['src'] == 80, use_or=True)
ddosdb  = Rule.parse(IPv4['src'] == '104.28.22.236')
rule    = port & ddosdb
```

> Full list of protocols and properties that can be used can be found in `Protocols.py` 

> In the future it might be possible to combine ands and ors more easily. For now, it isn't ;)

Now that we have created a rule or multiple rules, we want to create a program:

```python
from Program import Program

# Combine two rules from earlier into a list and call generate
rules = [tls, http]
code = Program.generate(rules)

# Or to save to file 'test.c'
Program.generate(rules, 'test.c')
```

The result will be a completely valid C program that can be used with BPF's XDP. In the folder `src/code`, you can find
`bpf-loader.py`. This python program can load a BPF XDP program into the kernel. To load our previous test program into 
the kernel, type the following:
```
>> sudo python bpf-loader.py test.c
Loading bpf program
Following traceprint, hit CTRL+C to stop and remove
```

Your program is now running! 