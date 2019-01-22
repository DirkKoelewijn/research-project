from Rules import Rule


class RuleParser:
    """
    Class to parse rule from fingerprint
    """

    @staticmethod
    def parse(fingerprint: dict, single_rule=True):
        """
        Parses a rule form a fingerprint

        Supports tuple min, max notation for values. Example:
        (1, 3) means include values between 1 and 3 (inclusive)

        :param single_rule: Optional. If true, a single rule will be returned,
               otherwise it will be one rule per property. Defaults to True.
        :param fingerprint: Fingerprint as {property: [values]}
        :return:
        """
        rules = []
        for prop, values in fingerprint.items():
            if prop is 'protocol':
                continue

            # if prop is Fingerprint.TCP_FLAG_KEY:
            #     prop_rules = [p == 1 for p in values]
            # else:
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

        if single_rule:
            return Rule.all(*rules)
        return rules
