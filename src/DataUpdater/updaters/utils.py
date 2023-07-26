import requests, zipfile, io
from Logging.Logger import logger

def download_and_unzip(url, path="", retries=0, max_retries=5):
        """Downloads and unzips a file.

        Keyword Args:
            link to zipped xml file.

        Returns:
            unzipped data file in the current directory.
        """
        try:
            r = requests.get(url)
        except Exception as e:
            if retries < max_retries:
                download_and_unzip(path, retries=retries + 1)
            else:
                raise
        z = zipfile.ZipFile(io.BytesIO(r.content))
        return z.extractall(path)

def do_request(url, retries=0, max_retries=5):
    try:
        res = requests.get(url)
        if res.status_code != 200:
            raise Exception("status code of request is %d"%res.status_code)
    except Exception as e:
        if retries < max_retries:
            try:
                res = do_request(url, retries=retries + 1, max_retries=max_retries)
            except:
                raise
        else:
            logger.error("Failed to request %s: %s"%(url, e))
            raise
    return res.content

def text_proc(text):
    text = text.strip()
    return text