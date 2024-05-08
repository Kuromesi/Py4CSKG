from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

def new_client(lifespan=None):
    app = FastAPI(lifespan=lifespan)
    app.mount("/static", StaticFiles(directory="./dist"), name="static")
    return app