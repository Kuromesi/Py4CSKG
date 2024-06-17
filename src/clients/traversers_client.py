from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, HTTPException

from clients.security import check_identity
from clients.new_client import new_client
from pydantic import BaseModel
from knowledge_graph import new_kg_builder
from utils import logger
from threading import Lock

class TraverseRequest(BaseModel):
    type: str # full, cve, cwe, capec, attack
    base: str # path of the knowledge bases

@asynccontextmanager
async def lifespan(app: FastAPI):
    global traverser, traverse_lock
    traverse_lock = Lock()
    traverser = new_kg_builder()
    yield

app = new_client(lifespan=lifespan)

@app.post("/traverse")
def traverse(traverse_request: TraverseRequest, identity: str = Depends(check_identity)):
    if not traverse_lock.acquire(blocking=False):
        raise HTTPException(status_code=400, detail="traverse is traversing")
    
    logger.info(f"lock acquired, starting to traverse: {traverse_request.type}")
    if traverse_request.type == "full":
        logger.info("traversing all")
        update_func = traverser.traverse_all
    elif traverse_request.type == "cve":
        logger.info("traversing cve")
        update_func = traverser.traverse_cve
    elif traverse_request.type == "cwe":
        logger.info("traversing cwe")
        update_func = traverser.traverse_cwe
    elif traverse_request.type == "capec":
        logger.info("traversing capec")
        update_func = traverser.traverse_capec
    elif traverse_request.type == "attack":
        logger.info("traversing attack")
        update_func = traverser.traverse_attack
    else:
        logger.error(f"unknown data update type: {traverse_request.type}")
        traverse_lock.release()
        raise HTTPException(status_code=400, detail=f"unknown data traverse type: {traverse_request.type}")
    done, message = update_func(path=traverse_request.base)
    traverse_lock.release()
    if done:
        return {"message": "traverse done"}
    else:
        raise HTTPException(status_code=400, detail=message)