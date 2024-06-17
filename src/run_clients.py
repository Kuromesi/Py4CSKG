import uvicorn
import argparse

def run_ts_client():
    from clients.text_similarity_client import app as ts_app
    uvicorn.run(ts_app, host="0.0.0.0", port=8000)

def run_tc_client():
    from clients.text_classification_client import app as tc_app
    uvicorn.run(tc_app, host="0.0.0.0", port=8000)

def run_mongo_client():
    from clients.mongo_client import app as mongo_app
    uvicorn.run(mongo_app, host="0.0.0.0", port=8000)

def run_updater_client():
    from clients.data_updater_client import app as updater_app
    uvicorn.run(updater_app, host="0.0.0.0", port=8000)

def run_analyzer_client():
    from clients.analyzer_client import app as analyzer_app
    uvicorn.run(analyzer_app, host="0.0.0.0", port=8000)

def run_traverser_client():
    from clients.traversers_client import app as traverser_app
    uvicorn.run(traverser_app, host="0.0.0.0", port=8000)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    run_funcs = {
        "ts": run_ts_client, "tc": run_tc_client, "mongo": run_mongo_client, 
        "updater": run_updater_client, "analyzer": run_analyzer_client,
        "traverser": run_traverser_client,
    }
    parser.add_argument("-c", "--client", type=str, help="client wish to run")
    args = parser.parse_args()
    client = args.client
    if client in run_funcs:
        run_func = run_funcs[client]
        run_func()
    else:
        print("please specify a right client to run")