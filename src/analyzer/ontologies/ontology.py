# Field of ontologies are determined by the knowledge bases, e.g. CVE, CPE etc.
# Once the information of product and version is provided, the vulnerabilities of the product could be obtained,
# if the attack prerequisites are satisfied, the attack can happen. 
# A information system can be divided into assets, bridge, protection.

class Product:
    def __init__(self) -> None:
        self.name = "N/A"
        self.des = "N/A"
        self.product = "N/A"
        self.version = "N/A"
        self.privilege = ""
        self.exposed = "" # Network, Adjacent, Local, Physical

class Node:
    """Logical nodes that composed of single or multiple components.
       Depending on the complexity of the system. 
    """    
    def __init__(self) -> None:
        self.name = "N/A"
        self.des = "N/A"
        self.group = []
        self.entry_point = []
        self.software = []
        self.hardware = []
        self.os = []
        self.firmware = []

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