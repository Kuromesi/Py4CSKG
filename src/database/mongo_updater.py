from utils import logger, CVE_YEAR_PATTERN
from pymongo.errors import DuplicateKeyError
from pymongo import MongoClient
import json, os

def get_cve_entry(cve: json):
    entry = {}
    entry['id'] = cve['cve']['CVE_data_meta']['ID']
    entry['description'] = cve['cve']['description']['description_data'][0]['value']
    try:
        entry['cwe'] = cve['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
    except Exception as e:
        logger.info(f"cwe not found: {entry['id']}")
        entry['cwe'] = "unknown"
    if 'baseMetricV2' in cve['impact']:
        entry['cvssV2'] = cve['impact']['baseMetricV2']
    else:
        entry['cvssV2']= {}
    if 'baseMetricV3' in cve['impact']:
        entry['cvssV3'] = cve['impact']['baseMetricV3']
    else:
        entry['cvssV3'] = {}
    return entry

class MongoUpdater():
    def __init__(self, mongo_connector: MongoClient) -> None:
        logger.info("MongoUpdater init")
        self.mongo_connector = mongo_connector

    def update_cve(self, cve_dir: str):
        """
        MongoDB cve update
        """
        logger.info("MongoDB cve update")

        col = self.mongo_connector['knowledge']['cve']
        col.create_index([('id', 1)], unique=True)
        last_year, last_count = 0, col.count_documents({})
        if last_count > 0:
            last_document = col.find().sort('id', -1).limit(1).next()
            _, last_year, last_id = last_document['id'].split('-')
            last_year = int(last_year)

        count = 0
        cve_paths = os.listdir(cve_dir)
        cve_paths = list(filter(lambda x: CVE_YEAR_PATTERN.match(x.split('.')[0]), cve_paths))
        cve_paths.sort(key=lambda x: int(CVE_YEAR_PATTERN.findall(x)[0]))
        for cve_path in cve_paths:
            if last_year != 0:
                year = CVE_YEAR_PATTERN.findall(cve_path)[0]
                if int(year) < last_year:
                    logger.info(f"latest cve year: {last_year}, skipping: {cve_path}")
                    continue
            with open(os.path.join(cve_dir, cve_path), 'r') as f:
                cve_json = json.load(f)
            for cve in cve_json['CVE_Items']:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                cve_entry = get_cve_entry(cve)
                try:
                    col.insert_one(cve_entry)
                    logger.info(f"insert cve: {cve_entry['id']} ")
                    count += 1
                except DuplicateKeyError:
                    logger.info(f"cve {cve_entry['id']} already exists")
                except Exception as e:
                    logger.error(f"cve {cve_entry['id']} insert error: {e}")
        return last_count, count