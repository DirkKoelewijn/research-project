from abc import ABC, abstractmethod


class RuleGenerator(ABC):

    @abstractmethod
    def generate(self, fingerprint):
        raise NotImplementedError
