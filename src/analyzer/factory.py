from analyzer.analyzer import ModelAnalyzer
from analyzer.extensions.extension import FlanAnalyzerExtension
from analyzer.graph.graph_editor import GraphEditor

def new_flan_analyzer(rule_path: str):
    model_analyzer = ModelAnalyzer(rule_path, extension=FlanAnalyzerExtension(), graph_editor=GraphEditor())
    return model_analyzer