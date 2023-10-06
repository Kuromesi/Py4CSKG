import zipfile
import gzip
import io
import shutil
import requests
import os, re
from lxml import etree
from tqdm import tqdm
from data_updater.updaters.utils import *
from utils.Logger import logger
from utils.Config import config

class CVEUpdater():
    def __init__(self) -> None:
        self.pattern = re.compile(r"/feeds/json/cve/1.1/(.*).zip")
    
    def get_cve_links(self):
        """get cve download links

        Returns:
            dict: a diction of cve links
        """        
        index = 'https://nvd.nist.gov/vuln/data-feeds'
        try:
            res = do_request(index)
        except:
            logger.error("Failed to update cve: %s"%index)
            raise
        res = etree.HTML(res.content)
        links_tab = res.xpath('//*[@id="vuln-feed-table"]/div/table/tbody/tr[@class="xml-feed-data-row"]/td/a')
        names_tab = res.xpath('//*[@id="vuln-feed-table"]/div/table/tbody/tr[@class="xml-feed-desc-row"]/td[1]')
        cves = {}
        for i in range(len(names_tab)):
            name = names_tab[i].text
            link = links_tab[2 * i + 1].attrib['href']
            cves[name] = link
        return cves

    def download_and_unzip(self, url):
        """Downloads and unzips a file.

        Keyword Args:
            link to zipped xml file.

        Returns:
            unzipped data file in the current directory.
        """
        r = requests.get(url)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        return z.extractall()

    def update(self):
        logger.info("Starting to update CVE")
        base = config.get("DataUpdater", "base_path")
        cve_loc = os.path.join(base, "base/cve")
        index = 'https://nvd.nist.gov'
        try:
            cve_links = self.get_cve_links()
        except:
            return
        cve_links = tqdm(cve_links.items())
        cve_links.set_description("Updating CVE data")
        for cve_name, cve_link in cve_links:
            name = self.pattern.match(cve_link).group(1)
            cve_links.set_postfix(downloading=name)
            link =  index + cve_link
            download_and_unzip(link)
            cf = os.path.join(cve_loc, cve_name + ".json")
            shutil.move(name, cf)
    
if __name__ == '__main__':
    cveu = CVEUpdater()
    cveu.update()