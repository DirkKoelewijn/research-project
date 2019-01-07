from Rules import Rule
from rulegen.RuleGenerator import RuleGenerator


class SimpleRuleGenerator(RuleGenerator):
    def generate(self, fingerprint: dict):
        tmp = []
        for prop, value in fingerprint.items():
            if isinstance(value, list):
                tmp += [[prop == v for v in value]]
            else:
                tmp += [[prop == value]]

        return Rule.all(*[Rule.one(*c) for c in tmp])
