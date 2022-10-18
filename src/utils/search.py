from googlesearch import search
import urllib
from bs4 import BeautifulSoup
import os
os.environ["http_proxy"] = "http://127.0.0.1:2340"
os.environ["https_proxy"] = "http://127.0.0.1:2340"

CWE = "cwe.mitre.org"
CAPEC = "capec.mitre.org"

def google_scrape(url):
    thepage = urllib.request.urlopen(url)
    soup = BeautifulSoup(thepage, "html.parser")
    return soup.title.text

def knowledge_search():
    query = "information disclosure \"cwe.mitre.org\""
    for url in search(query, num_results=5):
        if "cwe.mitre.org" not in url:
            break
        a = google_scrape(url)
        print (a)
        print (url)