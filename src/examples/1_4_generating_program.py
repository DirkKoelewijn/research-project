from Program import Program

rules = []  # Insert rules here

# Write program code to variable
code = Program.generate_code(*rules)

# Write program code to file
Program.generate_code(*rules, file='test.c')

# Optionally specify whitelisting
Program.generate_code(*rules, blacklist=False)
