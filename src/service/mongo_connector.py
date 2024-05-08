import pymongo, os
from utils import logger

def new_mongo_connector(uri: str, port: int, username: str, password: str) -> pymongo.MongoClient:
    # uri = os.getenv("MONGO_URI")
    # port = int(os.getenv("MONGO_PORT"))
    # username = os.getenv("MONGO_USERNAME")
    # password = os.getenv("MONGO_PASSWORD")
    logger.info(f"connection to mongodb: {uri}:{port}")
    return pymongo.MongoClient(uri, port, username=username, password=password)
    
if __name__ == "__main__":
    new_mongo_connector()