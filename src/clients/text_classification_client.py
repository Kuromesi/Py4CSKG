from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, HTTPException
from utils import logger
from clients.new_client import new_client
from clients.security import check_identity
from pydantic import BaseModel
from text_classification import new_bert_text_classification

class TextClassificationRequest(BaseModel):
    id: str
    description: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    global tc
    tc = new_bert_text_classification(os.getenv("MODEL_PATH"), os.getenv("DEVICE"), os.getenv("LABEL_PATH"))
    yield

app = new_client(lifespan=lifespan)

@app.post("/classification")
def classify_cwe(request: TextClassificationRequest, identity: str = Depends(check_identity)):
    logger.info(f"get classification request: {request.id}")
    try:
        cwe = tc.predict(request.description)
    except Exception as e:
        logger.error(f"error in classification: {request.id}")
        raise HTTPException(status_code=500, detail=str(e))
    logger.info(f"cwe classified for {request.id}: {cwe}")
    return cwe