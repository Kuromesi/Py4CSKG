import uvicorn
import argparse

def run_ts_client():
    from clients.text_similarity_client import app as ts_app
    uvicorn.run(ts_app, host="127.0.0.1", port=8000)

def run_tc_client():
    from clients.text_classification_client import app as tc_app
    uvicorn.run(tc_app, host="127.0.0.1", port=8000)

def run_mongo_client():
    from clients.mongo_client import app as mongo_app
    uvicorn.run(mongo_app, host="127.0.0.1", port=8000)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--client", type=str, help="client wish to run")
    args = parser.parse_args()
    if args.client == "ts":
        run_ts_client()
    elif args.client == "tc":
        run_tc_client()
    elif args.client == "mongo":
        run_mongo_client()
    else:
        print("Please specify a client to run")