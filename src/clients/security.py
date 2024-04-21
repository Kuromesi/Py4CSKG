
from fastapi.security import APIKeyHeader
from fastapi import Depends

# api_key_header = APIKeyHeader(name="api_key")
def check_identity() -> str:
    # print(identity)
    return "test"