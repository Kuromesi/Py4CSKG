import os
from analyzer.analyzer import ModelAnalyzer
from analyzer.extensions.extension import FlanAnalyzerExtension
from analyzer.graph_editors.graph_editor import GraphEditor
from analyzer.atomic_convert.neo4j_converter import Neo4jAtomicConverter
from analyzer.atomic_convert.mongo_converter import MongoAtomicConverter
from service.mongo_connector import new_mongo_connector

def new_flan_analyzer(rule_path: str, database: str="mongo", **kwargs):
    if database == "neo4j":
        model_analyzer = ModelAnalyzer(rule_path, extension=FlanAnalyzerExtension(Neo4jAtomicConverter()), graph_editor=GraphEditor())
    elif database == "mongo":
        uri = kwargs['mongo_uri']
        port = kwargs['mongo_port']
        username = kwargs['mongo_user']
        password = kwargs['mongo_password']
        connector = new_mongo_connector(uri, port, username, password)
        model_analyzer = ModelAnalyzer(rule_path, extension=FlanAnalyzerExtension(MongoAtomicConverter(connector)), graph_editor=GraphEditor())
    return model_analyzer