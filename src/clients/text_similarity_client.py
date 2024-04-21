from contextlib import asynccontextmanager
import os, re
from fastapi import FastAPI, Depends, HTTPException
from utils import logger
from clients.new_client import new_client
from clients.security import check_identity
from pydantic import BaseModel
from text_similarity import new_text_similarity

class TextSimilarityRequest(BaseModel):
    query: str
    # regexp
    filter: str

ts = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ts
    ts = new_text_similarity(os.getenv("DOCS_PATH"), os.getenv("WEIGHT_PATH"), os.getenv("NER_PATH"))
    yield

app = new_client(lifespan=lifespan)

@app.post("/similarity")
def calculate_similarity(request: TextSimilarityRequest, identity: str = Depends(check_identity)):
    filter_func = None
    if request.filter:
        try:
            filter_patter = re.compile(request.filter)
        except Exception as e:
            logger.error(f"invalid filter pattern: {request.filter}")
            raise HTTPException(status_code=400, detail=str(e))
        filter_func = lambda x: filter_patter.match(x)
    try:
        df = ts.calculate_similarity(request.query, filter_func)
    except Exception as e:
        logger.error(f"error calculating similarity: {request.query}")
        raise HTTPException(status_code=500, detail=str(e))
    res = {"query": request.query, "results": {}}
    for _, row in df.iterrows():
        res["results"][row["id"]] = {}
        res["results"][row["id"]]["name"] = row["name"]
        res["results"][row["id"]]["similarity"] = row["similarity"]
        res["results"][row["id"]]["description"] = row["description"]
    logger.info(f"similarity calculated: {request.query}: {res}")
    return res