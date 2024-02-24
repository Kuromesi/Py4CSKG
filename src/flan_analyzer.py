import argparse, yaml

from typing import Optional, List
from pydantic import BaseModel
from analyzer import new_flan_analyzer

class AttackPath(BaseModel):
    src: str
    dst: str
    plotAll: Optional[bool] = False
    pathType: Optional[str] = "shortest"

class FlanAnalyzerConfiguration(BaseModel):
    reportsPaths: List[str]
    analyzerRulePath: str
    attackPaths: List[AttackPath]
    graphAddPath: str
    outputDir: Optional[str] = ""

parser = argparse.ArgumentParser(description='Flan cyber attacks analyzer')
parser.add_argument('-c', '--configuration', help='Analyzer configuration')

args = parser.parse_args()
with open(args.configuration, 'r') as f:
    conf = yaml.safe_load(f)
conf = FlanAnalyzerConfiguration(**conf)

analyzer =  new_flan_analyzer(conf.analyzerRulePath)
model = analyzer.load_model(data_path=conf.graphAddPath, model_path=conf.reportsPaths)
attack_graph = analyzer.generate_attack_graph(model)

all_attack_paths = []
for attack_path in conf.attackPaths:
    attack_paths = analyzer.generate_attack_path(attack_graph, attack_path.src, attack_path.dst, kind=attack_path.pathType)
    all_attack_paths.append(attack_paths)
    analyzer.print_path(attack_graph, attack_paths)

if conf.outputDir:
    for i in range(len(all_attack_paths)):
        attack_paths = all_attack_paths[i]
        analyzer.plot_vis_graph(attack_graph, "attack", conf.outputDir)
        analyzer.plot_vis_graph(model, "model", conf.outputDir)
        analyzer.plot_vis_attack_path(attack_graph, attack_paths, conf.outputDir, plot_all=conf.attackPaths[i].plotAll)
