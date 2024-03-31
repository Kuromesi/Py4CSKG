import abc
from ontologies.modeling import AtomicAttack

class AtomicConverter:
    @abc.abstractmethod
    def find_by_id(self, cve_id: str) -> AtomicAttack:
        pass

    @abc.abstractmethod
    def find_by_product(self, product: str, version: str) -> list[AtomicAttack]:
        pass