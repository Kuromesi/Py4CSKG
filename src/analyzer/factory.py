from analyzer.analyzer import ModelAnalyzer
from analyzer.extensions.extension import FlanAnalyzerExtension
from analyzer.graph_editors.graph_editor import GraphEditor
from analyzer.atomic_convert.neo4j_converter import Neo4jAtomicConverter

def new_flan_analyzer(rule_path: str):
    model_analyzer = ModelAnalyzer(rule_path, extension=FlanAnalyzerExtension(Neo4jAtomicConverter()), graph_editor=GraphEditor())
    return model_analyzer