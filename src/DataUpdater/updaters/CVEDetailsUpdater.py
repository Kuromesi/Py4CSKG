from random import randint
from bs4 import BeautifulSoup as bs
import os
import requests
import re
import multiprocessing
from tqdm import tqdm
from lxml import etree
from functools import wraps
import time, json
from utils.Logger import logger
from DataUpdater.updaters.utils import *
from utils.Config import config
from DataUpdater.updaters.utils import do_request
from utils.MultiTask import MultiTask

def logging(source):
    def decorator(func):
        @wraps(func)
        def wrapper(self, url, *args, **kw):
            cur = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
            print("%s [%s] %s"%(cur, source, url))
            return func(self, url, *args, **kw)
        return wrapper
    return decorator


class CVEDetailsUpdater():
    url_prefix = "https://www.cvedetails.com"
    def __init__(self) -> None:
        self.pattern = re.compile('\[.*\]' )
        self.user_agents = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
            "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
            "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
            "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
            "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
            "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
            "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
            "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
            "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
        ]
    
    def find_index_type_pages_urls(self):
        """find cve type urls in index

        Returns:
            _type_: _description_
        """        
        url = "https://www.cvedetails.com/vulnerabilities-by-types.php"
        try:
            cookie = {
                "cvedconsent": "1--94912313670ceed2c3095fca18f17fff9cde5b81",
                "_ga": "GA1.1.1535701902.1691412836",
                "_ga_3404JT2267": "GS1.1.1691412835.1.1.1691413260.0.0.0"
            }
            headers = {
                'User-Agent': self.user_agents[randint(0, len(self.user_agents) - 1)],
            }
            res = do_request(url, headers=headers)
        except Exception as e:
            logger.error("Failed to update CVE details: %s"%e)
            exit()
            
        
        idx = etree.HTML(res.content) 
        headers_tab1 = idx.xpath('//*[@id="contentdiv"]/div/main/div[2]/table/thead/tr/th')
        headers_tab2 = idx.xpath('//*[@id="contentdiv"]/div/main/div[3]/table/thead/tr/th')
        headers = []
        headers.extend([text_proc(header.text) for header in headers_tab1][2: ])
        headers.extend([text_proc(header.text) for header in headers_tab2][2: ])
               
        urls_tab1 = idx.xpath('//*[@id="contentdiv"]/div/main/div[2]/table/tbody/tr[12]/td/a')
        urls_tab2 = idx.xpath('//*[@id="contentdiv"]/div/main/div[3]/table/tbody/tr[12]/td/a')
        urls = []
        urls.extend([self.url_prefix + url.attrib['href'] for url in urls_tab1])
        urls.extend([self.url_prefix + url.attrib['href'] for url in urls_tab2])
        return headers, urls
    
    # @logging('www.cvedetails.com')
    def find_type_page_urls(self, url):
        """find type page urls in type pages

        Args:
            url (_type_): _description_

        Returns:
            _type_: _description_
        """             
        urls = []
        headers = {
                'User-Agent': self.user_agents[randint(0, len(self.user_agents) - 1)],
            }
        try:
            res = do_request(url, headers=headers)
        except:
            print("Connection to %s Failed!"%url)
            exit()
        idx = etree.HTML(res.content)
        urls_tab = idx.xpath('//*[@id="pagingb"]/a[@href]')
        urls = [url + u.attrib['href'] for u in urls_tab[1: ]]
        return urls        
    
    # @logging('www.cvedetails.com')
    def type_page_proc(self, url, q, impact, max_retries=0):
        """process a single page of type of vulnerabilities, get types

        Args:
            url (_type_): _description_

        Returns:
            _type_: _description_
        """     
        headers = {
            'User-Agent': self.user_agents[randint(0, len(self.user_agents) - 1)],
        }
        try:
            res = do_request(url, headers=headers)
            idx = etree.HTML(res.content)
            ids = idx.xpath('//*[@id="searchresults"]/div/div[1]/div[1]/h3/a')
            cves = {}
            for id in ids:
                id = text_proc(id.text)
                cves[id] = [impact]
            q.put(cves)
        except Exception as e:
            logger.error("Failed to update CVE details: %s"%e)
        
    def update(self):
        logger.info("Starting to update CVE details")
        """Multiprocessing

        Args:
            path (_type_): saved file path
            type (str, optional): enterprise, mobile or ICS. Defaults to "enterprise".
        """        
        # init process pool
        headers, type_page_urls = self.find_index_type_pages_urls()
        imapct_urls = {}
        for header, url in zip(headers, type_page_urls):
            imapct_urls[header] = self.find_type_page_urls(url)
        # urls.extend(self.find_type_page_urls(type_page_urls[0]))
        
        mt = MultiTask()
        mt.create_pool()
        saver = Saver()
        manager = multiprocessing.Manager()
        q = manager.Queue()
        p = multiprocessing.Process(target=saver.save, args=(q, ))
        p.start()

        tasks = []
        for impact, urls in imapct_urls.items():
            for url in urls:
                tasks.append((url, q, impact))
        mt.apply_task(self.type_page_proc, tasks)
        mt.delete_pool()
        p.join()
            
class Saver():
    def __init__(self) -> None:
        self.content = {}
        self.cur = 0
        self.fidx = 0
        self.size = 500

    def save(self, queue):
        base = config.get("DataUpdater", "base_path")
        path = os.path.join(base, "base/cve_details")
        content = {}
        while True:
            try:
                res = queue.get(True, 60)
                for id, impact in res.items():
                    if id in content:
                        content[id].extend(impact)
                    else:
                        content[id] = impact
            except:
                with open(os.path.join(path, 'impact.json'), 'w') as f:
                    json.dump(content, f, sort_keys=True, indent=4)
                break 

if __name__ == '__main__':
    # pattern = re.compile('\[.*\]' )   
    # url_finder_mobile()
    cve = CVEDetailsUpdater()
    # cve.url_finder("")
    path = "src\DataUpdate\data"
    cve.run("src\DataUpdate\data")

