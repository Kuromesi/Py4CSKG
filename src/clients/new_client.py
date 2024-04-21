from fastapi import FastAPI

def new_client(lifespan=None):
    app = FastAPI(lifespan=lifespan)
    return app