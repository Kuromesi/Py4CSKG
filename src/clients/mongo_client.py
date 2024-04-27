from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, HTTPException

from clients.security import check_identity
from clients.new_client import new_client
from pymongo import MongoClient
from pydantic import BaseModel
from database.mongo_updater import MongoUpdater
from utils import logger
from threading import Lock

class CVEItem(BaseModel):
    id: str
    description: str
    cwe: str
    cvssV2: dict
    cvssV3: dict
def init_mongo_client() -> MongoClient:
    uri = os.getenv("MONGO_URI")
    port = int(os.getenv("MONGO_PORT"))
    username = os.getenv("MONGO_USERNAME")
    password = os.getenv("MONGO_PASSWORD")
    logger.info(f"Connecting to MongoDB at {uri}:{port}")
    mongo_client = MongoClient(uri, port, username=username, password=password)
    return mongo_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    global mongo_client, mu, lock
    mongo_client = init_mongo_client()
    mu = MongoUpdater(mongo_client)
    lock = Lock()
    yield
    logger.info("closing mongo client")
    mongo_client.close()

app = new_client(lifespan=lifespan)

@app.get("/cve/{item_id}", response_model=CVEItem)
def get_by_cve_id(item_id: str, identity: str = Depends(check_identity)):
    one = mongo_client['knowledge']['cve'].find_one({'id': item_id})
    if one is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    else:
        cve = CVEItem.parse_obj(one)
        return cve
    
@app.post("/cve/update")
async def update_cve(identity: str = Depends(check_identity)):
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Update already in progress")
    try:
        last_count, count = mu.update_cve(os.getenv("CVE_DIR"))
        lock.release()
        return {"total_documents": last_count + count, "updated": count, "last_updated": last_count}
    except Exception as e:
        lock.release()
        raise HTTPException(status_code=500, detail=str(e))