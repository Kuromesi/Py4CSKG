# Field of ontologies are determined by the knowledge bases, e.g. CVE, CPE etc.
# Once the information of product and version is provided, the vulnerabilities of the product could be obtained,
# if the attack prerequisites are satisfied, the attack can happen. 
# A information system can be divided into assets, bridge, protection.

# RELATIONS
REL_ACCESS = "access"
REL_PEER = "peer"
REL_CONTROL = "control"

# PRIVILEGES
PRIV_NONE = "none"
PRIV_APP = "app"
PRIV_USER = "user"
PRIV_ROOT = "root"



# ACCESS
ACCESS_PHYSICAL = "physical"
ACCESS_LOCAL = "local"
ACCESS_ADJACENT = "adjacent"
ACCESS_NETWORK = "network"

class AtomicAttack():
    def __init__(self, id, access: str, gain: str, score: float, require: str) -> None:
        self.access = access
        self.gain = gain
        self.score = score
        self.id = id
        self.require = require

class AttackChain():
    def __init__(self) -> None:
        self.atomic_attacks = []

    def get_atomic_attacks(self) -> list[AtomicAttack]:
        return self.atomic_attacks
    
    def set_atomic_attacks(self, attacks: list[AtomicAttack]) -> None:
        self.atomic_attacks = attacks

class Product:
    def __init__(self) -> None:
        self.name = "N/A"
        self.des = "N/A"
        self.product = "N/A"
        self.version = "N/A"

class PhysicalNode:
    """Logical nodes that composed of single or multiple components.
       Depending on the complexity of the system. 
    """    
    def __init__(self) -> None:
        self.name: str = "N/A"
        self.des: str = "N/A"
        self.software: list[Software] = []
        self.hardware: list[Hardware] = []
        self.os: list[OS] = []
        self.firmware: list[Firmware] = []
        self.attacks: list[AtomicAttack] = []

class LogicalNode:
    def __init__(self) -> None:
        self.name: str = "N/A"
        self.des: str = "N/A"
        self.attacks: list[AtomicAttack] = []

class Software(Product):
    def __init__(self) -> None:
        super().__init__()

class Hardware(Product):
    def __init__(self) -> None:
        super().__init__()

class OS(Product):
    def __init__(self) -> None:
        super().__init__()

class Firmware(Product):
    def __init__(self) -> None:
        super().__init__()

class Link:
    def __init__(self) -> None:
        self.name = "N/A"
        self.description = "N/A"
        self.src = "N/A"
        self.dst = "N/A"
        self.protocol = []

if __name__ == "__main__":
    t = Node()
    print(1)