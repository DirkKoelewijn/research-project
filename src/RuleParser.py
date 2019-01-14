from Rules import Rule


class RuleParser:
    """
    Class to parse rule from fingerprint
    """

    @staticmethod
    def parse(fingerprint: dict):
        """
        Parses a rule form a fingerprint

        Supports tuple min, max notation for values. Example:
        (1, 3) means include values between 1 and 3 (inclusive)

        :param fingerprint: Fingerprint as {property: [values]}
        :return:
        """
        rules = []
        for prop, values in fingerprint.items():
            prop_rules = []

            if isinstance(values, list):
                for v in values:
                    if isinstance(v, tuple):
                        min_v, max_v = v
                        prop_rules.append((prop >= min_v) & (prop <= max_v))
                    else:
                        prop_rules.append(prop == v)
            else:
                prop_rules.append(prop == values)

            rules.append(Rule.one(*prop_rules))

        return Rule.all(*rules)
