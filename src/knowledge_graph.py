import os, shutil, tempfile, json, re

from data_updater import CVEUpdater
from knowledge_graph import CVETraverser
from utils import CVE_YEAR_PATTERN, logger, download_and_unzip

def get_cve_diff(old_cve: dict, new_cve: dict):
    # only return the new cve items
    return new_cve['CVE_Items'][len(old_cve['CVE_Items']): ]

def incremental_update_cve(cve_path: str, output_path: str):
    old_cve_list = os.listdir(cve_path)
    old_cve_list = [CVE_YEAR_PATTERN.findall(cve)[0] for cve in old_cve_list if CVE_YEAR_PATTERN.match(cve)]
    old_cve_list.sort()
    cve_updater = CVEUpdater()
    try:
        new_cve_dict = cve_updater.get_cve_links()
        new_cve_list = [cve for cve, _ in new_cve_dict.items()]
        
    except Exception as e:
        logger.error(f"failed to get new cve list: {e}")
        return
    new_cve_list.sort()

    # we only consider the last cve data
    last_year_cve = old_cve_list[-1]
    if last_year_cve in new_cve_list:
        increment_cve_list = new_cve_list[new_cve_list.index(last_year_cve): ]
        increment_cve_dict = {cve: new_cve_dict[cve] for cve in increment_cve_list}
    else:
        logger.error("maybe something wrong with the old cve data")
        return

    tmp_dir = tempfile.mkdtemp()
    cve_diff = {'CVE_Items': []}
    pattern = re.compile(r"/feeds/json/cve/1.1/(.*).zip")
    for cve_name, cve_link in increment_cve_dict.items():
        logger.info(f"incrementally updating cve: {cve_name}")

        link =  'https://nvd.nist.gov' + cve_link
        new_cve_dir = os.path.join(tmp_dir)
        try:
            download_and_unzip(link, new_cve_dir)
        except Exception as e:
            logger.error(f"failed to download and unzip cve: {cve_name}")
            break
        name = pattern.match(cve_link).group(1)
        new_cve_dict = json.load(open(os.path.join(new_cve_dir, name), 'r'))
        if cve_name in old_cve_list:
            old_cve_name = os.path.join(cve_path, f"{cve_name}.json")
            old_cve_dict = json.load(open(old_cve_name, 'r'))
            diff = get_cve_diff(old_cve_dict, new_cve_dict)
        else:
            diff = new_cve_dict['CVE_Items']
        cve_diff['CVE_Items'].extend(diff)
    
    cve_traverser = CVETraverser()
    try:
        logger.info("recording cve diff into csv")
        cve_df, cpe_df, rel_df = cve_traverser.convert_json_to_csv(cve_diff)
        output_path = os.path.join(output_path, "increment")
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        cve_df.to_csv(os.path.join(output_path, 'cve_diff.csv'), index=False)
        cpe_df.to_csv(os.path.join(output_path, 'cpe_diff.csv'), index=False)
        rel_df.to_csv(os.path.join(output_path, 'rel_diff.csv'), index=False)
        
        # move new cve data to cve dir
        pattern = re.compile(r"nvdcve-1.1-(\d+).json")
        for file in os.listdir(tmp_dir):
            src_path = os.path.join(tmp_dir, file)
            dst_path = os.path.join(cve_path, f"CVE-{pattern.findall(file)[0]}.json")
            shutil.move(src_path, dst_path)
    except Exception as e:
        logger.error(f"failed to record cve diff in csv: {e}")
    shutil.rmtree(tmp_dir)

if __name__ == "__main__":
    incremental_update_cve("data/base_copy/cve", "shared/knowledge")