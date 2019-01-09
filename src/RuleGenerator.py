from Fingerprints import Fingerprint
from Rules import Rule


class RuleGenerator:

    @staticmethod
    def generate(fingerprint: dict):
        rules = []
        for prop, values in fingerprint.items():
            prop_rules = []
            for v in values:
                if isinstance(v, tuple):
                    min_v, max_v = v
                    prop_rules.append((prop >= min_v) & (prop <= min_v))
                else:
                    prop_rules.append(prop == v)

            rules.append(Rule.one(*prop_rules))

        return Rule.all(*rules)


if __name__ == '__main__':
    f = Fingerprint.parse('fingerprints/02a3a3fc266b09b7645e538efbc1ea11.json')
    print(RuleGenerator.generate(f))
