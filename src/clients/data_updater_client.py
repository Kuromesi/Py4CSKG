from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, HTTPException

from clients.security import check_identity
from clients.new_client import new_client
from pydantic import BaseModel
from data_updater.updater import new_updater
from utils import logger
from threading import Lock

class UpdateRequest(BaseModel):
    type: str # full, cve, cwe, capec, attack

@asynccontextmanager
async def lifespan(app: FastAPI):
    global updater, updater_lock
    updater = new_updater(os.getenv("BASE_PATH"))
    updater_lock = Lock()
    yield

app = new_client(lifespan=lifespan)

@app.post("/updater")
def update(update_request: UpdateRequest, identity: str = Depends(check_identity)):
    if updater_lock.locked():
        raise HTTPException(status_code=400, detail="updater is updating")
    if not updater_lock.acquire(blocking=False):
        raise HTTPException(status_code=400, detail="updater is updating")
    logger.info(f"successfully acquire lock, updating: {update_request.type}")
    if update_request.type == "full":
        logger.info("Updating all")
        update_func = updater.update
    elif update_request.type == "cve":
        logger.info("Updating cve")
        update_func = updater.update_cve
    elif update_request.type == "cwe":
        logger.info("Updating cwe")
        update_func = updater.update_cwe
    elif update_request.type == "capec":
        logger.info("Updating capec")
        update_func = updater.update_capec
    elif update_request.type == "attack":
        logger.info("updating attack")
        update_func = updater.update_attack
    else:
        logger.error(f"unknown data update type: {update_request.type}")
        updater_lock.release()
        raise HTTPException(status_code=400, detail=f"unknown data update type: {update_request.type}")
    done, message = update_func()
    updater_lock.release()
    if done:
        return {"message": "update done"}
    else:
        raise HTTPException(status_code=400, detail=message)