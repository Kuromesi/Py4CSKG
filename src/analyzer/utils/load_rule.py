import yaml

PROPERTY_KEY = "properties"
TRANSITION_KEY = "internalTransitions"
EXPLOIT_KEY = "exploitTransitions"
PREREQUISITE_KEY = "prerequisites"
DELIMITER = ":"

class AnalyzerRule:
    def __init__(self, properties: list[str], transitions: list[tuple], 
                 exploit_transitions: dict[str, str], prerequisites: dict[str, str]):
        self.properties = properties
        self.transitions = transitions
        self.exploit_transitions = exploit_transitions
        self.prerequisites = prerequisites

def check_rule(properties: list[str], transitions: list[str]) -> bool:
    return True

def load_rule(path: str) -> AnalyzerRule:
    with open(path, 'r', encoding='utf-8') as file:
        rule_file = yaml.safe_load(file)
    properties: list[str] = rule_file[PROPERTY_KEY]
    transition: list[str] = rule_file[TRANSITION_KEY]
    exploit: list[str] = rule_file[EXPLOIT_KEY]
    prerequisites: list[str] = rule_file[PREREQUISITE_KEY]
    if not check_rule(properties, transition):
        raise Exception("bad rules detected")
    transition_list = []
    for trans in transition:
        trans_left, trans_right = trans.split(DELIMITER)
        if trans_left == "":
            for prop in properties:
                if prop == trans_right:
                    continue
                transition_list.append((prop, trans_right))
        elif trans_right == "":
            for prop in properties:
                if prop == trans_left:
                    continue
                transition_list.append((trans_left, prop))
        else:
            transition_list.append((trans_left, trans_right))
    exploit_dict = {}
    for exp in exploit:
        exp_left, exp_right = exp.split(DELIMITER)
        exploit_dict[exp_left] = exp_right
    pre_dict = {}
    for pre in prerequisites:
        pre_left, pre_right = pre.split(DELIMITER)
        pre_dict[pre_left] = pre_right
    return AnalyzerRule(properties, transition_list, exploit_dict, pre_dict)

if __name__ == "__main__":
    load_rule("src/analyzer/rules/experiment/rule.yaml")