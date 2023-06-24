import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'src'))


# from traversers.CVEImpact import *

# cve = CVEImpact()
# sentence = "The kernel-mode drivers in Microsoft Windows XP SP3 do not properly perform indexing of a function-pointer table during the loading of keyboard layouts from disk, which allows local users to gain privileges via a crafted application, as demonstrated in the wild in July 2010 by the Stuxnet worm, aka \"Win32k Keyboard Layout Vulnerability.\"  NOTE: this might be a duplicate of CVE-2010-3888 or CVE-2010-3889."
# tmp = cve.predict(sentence)
# print(1)
# cve.traverse()

# from utils.cveImpact import *

# save_cveimpact()

from utils.utils import hotTechniqueSummary

hotTechniqueSummary()