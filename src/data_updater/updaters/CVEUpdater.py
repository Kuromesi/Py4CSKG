import zipfile
import io
import shutil
import requests
import os, re
from lxml import etree
from tqdm import tqdm
from data_updater.utils.utils import *
from utils.Logger import logger
from utils.Config import config
from utils import CVE_YEAR_PATTERN

class CVEUpdater():
    pattern = re.compile(r"/feeds/json/cve/1.1/(.*).zip")
    
    def get_cve_links(self) -> dict[str: str]:
        """get cve download links

        Returns:
            dict: a diction of cve links
        """        
        index = 'https://nvd.nist.gov/vuln/data-feeds'
        res = do_request(index)
        res = etree.HTML(res.content)
        links_tab = res.xpath('//*[@id="vuln-feed-table"]/div/table/tbody/tr[@class="xml-feed-data-row"]/td/a')
        names_tab = res.xpath('//*[@id="vuln-feed-table"]/div/table/tbody/tr[@class="xml-feed-desc-row"]/td[1]')
        cves = {}
        for i in range(len(names_tab)):
            name = names_tab[i].text
            # do not download CVE-Modified and CVE-Recent since they only contains data of recent 8 days
            if name == 'CVE-Modified' or name == 'CVE-Recent':
                continue
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
        logger.info("starting to update CVE")
        base = config.get("KnowledgeGraph", "base_path")
        cve_loc = os.path.join(base, "base/cve")
        index = 'https://nvd.nist.gov'
        try:
            cve_links = self.get_cve_links()
        except Exception as e:
            logger.error(f"failed to get CVE links: {e}")
            raise e
        
        cve_links = tqdm(cve_links.items())
        cve_links.set_description("Updating CVE data")
        for cve_name, cve_link in cve_links:
            name = self.pattern.match(cve_link).group(1)
            cve_links.set_postfix(downloading=name)
            link =  index + cve_link
            download_and_unzip(link)
            cf = os.path.join(cve_loc, cve_name + ".json")
            shutil.move(name, cf)