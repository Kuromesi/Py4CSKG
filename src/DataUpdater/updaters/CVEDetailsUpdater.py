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

LOGGING_PATH = ""

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
            res = requests.get(url)
        except:
            logger.error("Failed to update CVE details: %s"%e)
            exit()
        idx = etree.HTML(res.content) 
        headers_tab = idx.xpath('//*[@id="contentdiv"]/table[1]/tr[1]/th')
        headers = [text_proc(header.text) for header in headers_tab]
        headers = headers[2: -1]
        urls_tab = idx.xpath('//*[@id="contentdiv"]/table[1]/tr[27]/td/a')
        urls = [self.url_prefix + url.attrib['href'] for url in urls_tab]
        urls = urls[: -1]
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
        try:
            res = requests.get(url)
        except:
            print("Connection to %s Failed!"%url)
            exit()
        idx = etree.HTML(res.content)
        urls_tab = idx.xpath('//*[@id="pagingb"]/a[@href]')
        urls = [self.url_prefix + url.attrib['href'] for url in urls_tab]
        return urls        
    
    # @logging('www.cvedetails.com')
    def type_page_proc(self, url, q, max_retries=0):
        """process a single page of type of vulnerabilities, get types

        Args:
            url (_type_): _description_

        Returns:
            _type_: _description_
        """     
        random_agent = self.user_agents[randint(0, len(self.user_agents) - 1)]
        headers = {
            'User-Agent':random_agent,
        }
        try:
            res = requests.get(url, headers=headers)
            idx = etree.HTML(res.content)
            ids = idx.xpath('//*[@id="vulnslisttable"]/tr[@class="srrowns"]/td[2]/a')
            vul_types = idx.xpath('//*[@id="vulnslisttable"]/tr[@class="srrowns"]/td[5]')
            cves = {}
            for i in range(len(ids)):
                t = etree.tostring(ids[i])
                id = text_proc(ids[i].text)
                vul_type = text_proc(vul_types[i].text)
                cves[id] = vul_type
            q.put(cves)
        except Exception as e:
            if max_retries > 10:
                logger.error("Failed to update CVE details: %s"%e)
            else:
                time.sleep(10)
                self.type_page_proc(url, q, max_retries + 1)
        
    def update(self):
        logger.info("Starting to update CVE details")
        """Multiprocessing

        Args:
            path (_type_): saved file path
            type (str, optional): enterprise, mobile or ICS. Defaults to "enterprise".
        """        
        # init process pool
        path = "./data/base/cve_details"
        headers, type_page_urls = self.find_index_type_pages_urls()
        urls = []
        for url in type_page_urls:
            urls.extend(self.find_type_page_urls(url))
        # urls.extend(self.find_type_page_urls(type_page_urls[0]))
        
        saver = Saver()
        manager = multiprocessing.Manager()
        q = manager.Queue()
        p = multiprocessing.Process(target=saver.save, args=(q, ))
        p.start()

        pool = multiprocessing.Pool(32)
        result = []
        for url in urls:
            result.append(pool.apply_async(self.type_page_proc, (url, q)))
        pool.close()
        pool.join()
        p.join()
            
class Saver():
    def __init__(self) -> None:
        self.content = {}
        self.cur = 0
        self.fidx = 0
        self.size = 500

    def save(self, queue):
        path = "./data/base/cve_details"
        content = {}
        cur = self.cur
        fidx = self.fidx
        size = self.size
        while True:
            try:
                s = queue.qsize()
                res = queue.get(True, 60)
                cur += 1
                content.update(res)
                if cur == size:
                    with open(os.path.join(path, 'cve_type_%d.json'%fidx), 'w') as f:
                        json.dump(content, f, sort_keys=True, indent=4)
                    fidx += 1
                    content = {}
                    cur = 0
            except:
                if cur != 0:
                    with open(os.path.join(path, 'cve_type_%d.json'%fidx), 'w') as f:
                        json.dump(content, f, sort_keys=True, indent=4)
                break    

if __name__ == '__main__':
    # pattern = re.compile('\[.*\]' )   
    # url_finder_mobile()
    cve = CVEDetailsUpdater()
    # cve.url_finder("")
    path = "src\DataUpdate\data"
    cve.run("src\DataUpdate\data")

