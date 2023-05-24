from traversers.CVEImpact import *

cve = CVEImpact()
sentence = "	protected/apps/admin/controller/photoController.php in YXcms 1.4.7 allows remote attackers to delete arbitrary files via the index.php?r=admin/photo/delpic picname parameter."
cve.predict(sentence)
cve.traverse()

# from utils.cveImpact import *

# save_cveimpact()