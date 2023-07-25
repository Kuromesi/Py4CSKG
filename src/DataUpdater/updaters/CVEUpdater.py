import zipfile
import gzip
import io
import shutil
import requests
import os, re
from lxml import etree
from tqdm import tqdm

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
            res = requests.get(index)
        except:
            print("Connection to %s Failed!"%index)
            exit()
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
        cve_loc = "./data/base/cve"
        index = 'https://nvd.nist.gov'
        cve_links = self.get_cve_links()
        cve_links = tqdm(cve_links.items())
        cve_links.set_description("Updating CVE data")
        for cve_name, cve_link in cve_links:
            name = self.pattern.match(cve_link).group(1)
            cve_links.set_postfix(downloading=name)
            link =  index + cve_link
            self.download_and_unzip(link)
            cf = os.path.join(cve_loc, cve_name + ".json")
            shutil.move(name, cf)

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
    
if __name__ == '__main__':
    cveu = CVEUpdater()
    cveu.update()