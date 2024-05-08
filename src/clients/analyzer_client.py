from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, HTTPException

from clients.security import check_identity
from clients.new_client import new_client
from pydantic import BaseModel
from analyzer.factory import new_flan_analyzer
from analyzer.graph_editors.graph_editor import GraphData
from utils import logger
from typing import Optional
import networkx as nx

class LoadModelRequest(BaseModel):
    edit_file: Optional[GraphData]
    models: list[dict]

class AttackGraphRequest(BaseModel):
    model: dict
    classified_atomic_attacks: dict

class AttackPathRequest(BaseModel):
    attack_graph: dict
    src: str
    dst: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model_analyzer
    uri = os.getenv("MONGO_URI")
    port = int(os.getenv("MONGO_PORT"))
    username = os.getenv("MONGO_USERNAME")
    password = os.getenv("MONGO_PASSWORD")
    model_analyzer = new_flan_analyzer("src/analyzer/rules/experiment/rule.yaml", mongo_uri=uri, mongo_port=port, mongo_user=username, mongo_password=password)
    yield

app = new_client(lifespan=lifespan)

@app.post("/load_model")
def load_model(load_request: LoadModelRequest, identity: str = Depends(check_identity)):
    try:
        model, classified_atomic_attacks = model_analyzer.load_model_api(load_request.edit_file, models=load_request.models)
        model = nx.to_dict_of_dicts(model)
        return {"model": model, "classified_atomic_attacks": classified_atomic_attacks}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/attack_graph")
def get_vul_graph(request: AttackGraphRequest, identity: str = Depends(check_identity)):
    try:
        model = nx.from_dict_of_dicts(request.model, create_using=nx.DiGraph)
        classified_atomic_attacks = request.classified_atomic_attacks
        attack_graph = model_analyzer.generate_attack_graph(model, classified_atomic_attacks)
        attack_graph = nx.to_dict_of_dicts(attack_graph)
        return {"attack_graph": attack_graph}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/attack_path")
def get_attack_path(request: AttackPathRequest, identity: str = Depends(check_identity)):
    try:
        attack_graph = nx.from_dict_of_dicts(request.attack_graph, create_using=nx.DiGraph)
        attack_paths = model_analyzer.generate_attack_path(attack_graph, request.src, request.dst)
        return {"attack_paths": attack_paths}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))