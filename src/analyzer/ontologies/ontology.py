# Field of ontologies are determined by the knowledge bases, e.g. CVE, CPE etc.
# Once the information of product and version is provided, the vulnerabilities of the product could be obtained,
# if the attack prerequisites are satisfied, the attack can happen. 
# A information system can be divided into assets, bridge, protection.

class Node:
    """Logical nodes that composed of single or multiple components.
       Depending on the complexity of the system. 
    """    
    def __init__(self) -> None:
        self.name = "" # Function of the node to the whole system
        self.des = ""
        self.group = []
        self.entry_point = []
        self.exposed = "" # Network, Adjacent, Local, Physical
        self.software = []
        self.hardware = []
        self.os = []
        
class Software:
    def __init__(self) -> None:
        self.product = ""
        self.version = ""
        self.privilege = ""

class Hardware:
    def __init__(self) -> None:
        self.product = ""
        self.version = ""

class OS:
    def __init__(self) -> None:
        self.product = ""
        self.version = ""