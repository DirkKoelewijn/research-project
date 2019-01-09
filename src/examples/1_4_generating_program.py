from Program import Program

rules = []  # Insert rules here

# Write program code to variable
code = Program.generate(*rules)

# Write program code to file
Program.generate(*rules, file='test.c')

# Optionally specify whitelisting
Program.generate(*rules, blacklist=False)
