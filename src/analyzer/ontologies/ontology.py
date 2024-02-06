# Field of ontologies are determined by the knowledge bases, e.g. CVE, CPE etc.
# Once the information of product and version is provided, the vulnerabilities of the product could be obtained,
# if the attack prerequisites are satisfied, the attack can happen. 
# A information system can be divided into assets, bridge, protection.

# PRIVILEGES
# PRIV_NONE = "none"
# PRIV_APP = "app"
# PRIV_USER = "user"
# PRIV_ROOT = "root"

# # ACCESS
# ACCESS_PHYSICAL = "physical"
# ACCESS_LOCAL = "local"
# ACCESS_ADJACENT = "adjacent"
# ACCESS_NETWORK = "network"

class Product:
    def __init__(self, name: str, des="", product="", version="") -> None:
        self.name = name
        self.des = des
        self.product = product
        self.version = version

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


class AtomicAttack():
    def __init__(self, name, access: str, gain: str, score: float, require: str) -> None:
        self.access = access
        self.gain = gain
        self.score = score
        self.name = name
        self.require = require



class PhysicalNode:
    """Logical nodes that composed of single or multiple components.
       Depending on the complexity of the system. 
       They are related to specific products.
    """    
    def __init__(self, name: str, des="", 
                 software: list[Software]=[], hardware: list[Hardware]=[], 
                 os: list[OS]=[], firmware: list[Firmware]=[], 
                 atomic_attacks: list[AtomicAttack]=[]) -> None:
        self.name: str = name
        self.des: str = des
        self.software: list[Software] = software
        self.hardware: list[Hardware] = hardware
        self.os: list[OS] = os
        self.firmware: list[Firmware] = firmware
        self.atomic_attacks: list[AtomicAttack] = atomic_attacks

class LogicalNode:
    def __init__(self, name: str, atomic_attacks: list[AtomicAttack]=[], des="") -> None:
        self.name: str = name
        self.des: str = des
        self.atomic_attacks: list[AtomicAttack] = atomic_attacks


class Relation:
    def __init__(self, name: str, src: str, dst: str, 
                 access="", transitions=[], bidirectional=False) -> None:
        self.name: str = name
        self.src: str = src
        self.dst: str = dst
        self.access: str =access
        self.transitions: list = transitions
        self.bidirectional: bool = bidirectional

if __name__ == "__main__":
    t = Node()
    print(1)