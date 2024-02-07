# constants
ACCESS_PHYSICAL = "PHYSICAL"
ACCESS_LOCAL = "LOCAL"
ACCESS_ADJACENT = "ADJACENT_NETWORK"
ACCESS_NETWORK = "NETWORK"

CIA_LOSS = "system cia loss"
PRIV_APP = "gain privilege on application"
PRIV_USER = "gain user privilege"
PRIV_ROOT = "gain root privilege"

PRIV_REQ_NONE = "None"
PRIV_REQ_LOW = "Low"
PRIV_REQ_HIGH = "High"

CODE_EXEC_CVED = "code execution"
GAIN_PRIV_CVED = "privilege escalation"

ACCESS_ORDER = [ACCESS_PHYSICAL, ACCESS_LOCAL, ACCESS_ADJACENT, ACCESS_NETWORK]
IMPACT_ORDER = [CIA_LOSS, PRIV_APP, PRIV_USER, PRIV_ROOT]
PRIV_REQ_ORDER = [PRIV_REQ_HIGH, PRIV_REQ_LOW, PRIV_REQ_NONE]

PRIV_REQ_MAP = {
    "NONE": PRIV_REQ_NONE,
    "LOW": PRIV_REQ_LOW,
    "HIGH": PRIV_REQ_HIGH
}