from bs4 import BeautifulSoup as bs
import os, sys, time
import requests
import re, json
import multiprocessing
from tqdm import tqdm
from utils.Logger import logger
from DataUpdater.updaters.utils import *
from lxml import etree

class ATTACKUpdater():
    def __init__(self) -> None:
        self.pattern = re.compile('\[.*\]' )
        

    def extract_content(self, url:str, retries=0, max_retries=5) -> str:
        """extract content from web pages

        Args:
            url (str): web url

        Returns:
            str: content
        """        
        soup = bs(features='xml')
        try:
            res = do_request(url)
        except:
            logger.error("Failed to update ATT&CK techniques: %s"%url)
        s = bs(res.content, "lxml")
        
        # find id
        id = s.find("div", attrs={"class": "col-md-11 pl-0"})
        if id:
            id.string = id.get_text().replace("ID:", "").strip()
            technique = soup.new_tag("Technique")
            technique["id"] = id.get_text().strip()
            # print(id.get_text())

            # find name
            name = s.find("h1")
            names = name.find("span")
            if names:
                technique["name"] = names.get_text() + " " + name.contents[2].strip()
            else:
                technique["name"] = name.get_text().replace("\n", "").strip()
            # print(technique["name"])

            # find description
            description = s.find("div", attrs={"class": "description-body"})
            tmp = ""
            for des in description.children:
                if des == '\n': continue
                if des.name == 'ul':
                    for d in des.find_all("li"):
                        tmp += self.pattern.sub("", d.get_text()) + " "
                    tmp = tmp.strip()
                    tmp += "\n"
                else:
                    tmp += self.pattern.sub("", des.get_text()) + "\n"
            technique.string = tmp

            # find card information
            logos = s.find_all("span", attrs={"data-toggle": "tooltip"})
            if logos:
                for logo in logos:
                    logo = logo.parent
                    content = logo.find_next_sibling()
                    title = content.find("span", attrs={"class": "h5 card-title"})
                    title = title.get_text().replace(":", "").strip().replace(" ", "_")
                    temp_tag = soup.new_tag(title)
                    if title in ["Tactics", "CAPEC_ID", "Tactic"]:
                        contents = content.find_all("a")
                        temp = ""
                        for cont in contents:
                            temp += cont.get_text() + ", "
                        temp = temp.rstrip(", ").replace(",,", ",")
                        temp_tag.string = temp
                    elif title == "MTC_ID":
                        contents = content.find_all("a", attrs={"target": "_blank"})
                        for cont in contents:
                            link = cont["href"]
                            try:
                                res = requests.get(link)
                            except:
                                print("Connection Failed!")
                                exit()
                            sub = bs(res.content, "lxml")
                            temp_res = sub.find_all("a", attrs={"target": "_blank"})
                            if temp_res:
                                temp_tag = soup.new_tag("CVE_Examples")
                                temp = ""
                                for su in temp_res:
                                    temp += su.get_text() + ", "
                                temp = temp.rstrip(", ")
                                temp_tag.string = temp
                    else:
                        temp_tag.string = content.contents[2].replace("\n", "").strip()
                    technique.append(temp_tag)
            
            # find examples
            examples = s.find("h2", attrs={"id": "examples"})
            if examples:
                examples = examples.find_next_sibling()
                examples = examples.find_all("tr")
                technique.append(soup.new_tag("Examples"))
                for example in examples:
                    exam = example.find_all("td")
                    if exam:
                        example = soup.new_tag("Example")
                        example["id"] = self.pattern.sub("", exam[0].get_text()).strip()
                        example["name"] = self.pattern.sub("", exam[1].get_text()).strip()
                        example.string = self.pattern.sub("", exam[2].get_text())
                        technique.Examples.append(example)
                        # for ex in exam:
                        #     print(pattern.sub("", ex.get_text()))

            # find mitigations
            mitigation = s.find("h2", attrs={"id": "mitigations"})
            if mitigation:
                mitigation = mitigation.find_next_sibling()
                mitigation = mitigation.find_all("tr")
                technique.append(soup.new_tag("Mitigations"))
                for mitiga in mitigation:
                    mitiga = mitiga.find_all("td")
                    if mitiga:
                        mitigation = soup.new_tag("Mitigation")
                        mitigation["id"] = self.pattern.sub("", mitiga[0].get_text()).strip()
                        mitigation["name"] = self.pattern.sub("", mitiga[1].get_text()).strip()
                        mitigation.string = self.pattern.sub("", mitiga[2].get_text())
                        technique.Mitigations.append(mitigation)
                        # for miti in mitiga:
                        #     print(pattern.sub("", miti.get_text()))

            # find detections
            detections = s.find("table", attrs={"class": "table datasources-table table-bordered"})
            if detections:
                detections = detections.find_next_sibling()
                detections = detections.find_all("p")
                technique.append(soup.new_tag("Detections"))
                total = ""
                for dec in detections:
                    total += self.pattern.sub("", dec.get_text()) + " "
                    # print(dec.get_text(), "\n")
                technique.Detections.string = total

                detections = s.find("h2", attrs={"id": "detection"})
                detections = detections.find_next_sibling()
                detections = detections.find_all("tr")
                for detect in detections:
                    detect = detect.find_all("td")
                    if detect:
                        if self.pattern.sub("", detect[0].get_text()).strip() == "":
                            detection.string += " | " + self.pattern.sub("", detect[2].get_text()).replace("\n", "")
                        else:
                            detection = soup.new_tag("Detection")
                            detection["id"] = self.pattern.sub("", detect[0].get_text()).strip()
                            detection["name"] = self.pattern.sub("", detect[1].get_text()).strip()
                            detection.string = self.pattern.sub("", detect[2].get_text()).replace("\n", "")
                            technique.Detections.append(detection)
                            # for dete in detect:
                            #     print(pattern.sub("", dete.get_text()))
            else:
                detections = s.find("h2", attrs={"id": "detection"})
                if detections:
                    detections = detections.find_next_sibling()
                    detections = detections.find_all("p")
                    technique.append(soup.new_tag("Detections"))
                    total = ""
                    for dec in detections:
                        total += self.pattern.sub("", dec.get_text()) + " "
                        # print(dec.get_text(), "\n")
                    technique.Detections.string = total
            # self.res.put(technique)
            return str(technique)
        else:
            return 0
    
    def update_technique(self, path="data/base/attack"):
        target_urls = {
            "mobile": "https://attack.mitre.org/techniques/mobile/",
            "enterprise": "https://attack.mitre.org/techniques/enterprise/",
            "ics": "https://attack.mitre.org/techniques/ics/"
        }
        url_main = "https://attack.mitre.org"
        for kind, url in target_urls.items():
            logger.info("Updating ATT&CK %s techniques"%kind)
            urls = []
            result = []
            pool = multiprocessing.Pool(64)
            soup = bs(features='xml')
            soup.append(soup.new_tag("Techniques"))
            try:
                res = do_request(url)
            except:
                print("Failed to update ATT&CK techniques: %s"%url)
                continue
            s = bs(res.content, "lxml")
            s.find("table", attrs={"class": "table-techniques"})
            s = s.find("tbody")
            s = s.find_all("tr")
            for tr in s:
                links = tr.find_all("a")
                sub_url = url_main + links[0]["href"]
                urls.append(sub_url)
            for temp in urls:
                temp = pool.apply_async(self.extract_content, (temp, ))    
                result.append(temp)
            for temp in result:
                temp = temp.get()
                if temp:
                    tag = bs(temp, "xml")
                    soup.Techniques.append(tag.Technique)
            soup = soup.prettify()
            with open(os.path.join(path, kind + ".xml"), "w", encoding="utf-8") as f:
                f.write(soup)
                f.close()
        pool.close()
        pool.join()

    def update_tactic(self):
        logger.info("Updating ATT&CK tactics")
        urls = {
            "enterprise": "https://attack.mitre.org/tactics/enterprise/",
            "mobile": "https://attack.mitre.org/tactics/mobile/",
            "ics": "https://attack.mitre.org/tactics/ics/",
        }
        for n, url in urls.items():
            try:
                res = do_request(url)
            except:
                logger.error("Failed to update ATT&CK tactic: %s"%url)
                continue
            res = etree.HTML(res.content)
            rows = res.xpath('//*[@id="v-attckmatrix"]/div[2]/div/div/div/div/div[2]/div/table/tbody/tr')
            tactics = {}
            for row in rows:
                id = text_proc(row.xpath('td[1]/a')[0].text)
                name = text_proc(row.xpath('td[2]/a')[0].text)
                des = text_proc(row.xpath('td[3]')[0].text)
                tactics[name] = {}
                tactics[name]['id'] = id
                tactics[name]['description'] = des
            with open(os.path.join("./data/base/attack", n + "_tactic.json"), 'w') as f:
                json.dump(tactics, f)

        
    def update(self, path="data/base/attack"):
        """Multiprocessing

        Args:
            path (_type_): saved file path
            type (str, optional): enterprise, mobile or ICS. Defaults to "enterprise".
        """        
        # init process pool
        logger.info("Starting to update ATT&CK")
        self.update_tactic()
        self.update_technique()

        

if __name__ == '__main__':
    # pattern = re.compile('\[.*\]' )   
    # url_finder_mobile()
    # url_finder_enterprise()
    # soup = bs(features='xml')
    # soup.append(soup.new_tag("Techniques"))
    # content_finder("https://attack.mitre.org/techniques/T1134/004/", soup)
    updater = ATTACKUpdater()
    updater.url_finder("./data/attack/enterpriseN.xml", "enterprise")
