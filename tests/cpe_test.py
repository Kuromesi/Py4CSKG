from cpe.cpeset2_3 import CPESet2_3
from cpe.cpe2_3 import CPE2_3

str23_fs = 'cpe:2.3:o:huawei:mate_10_firmware'
c23_fs = CPE2_3(str23_fs)
a = CPESet2_3()
a.append(c23_fs)
t = a.name_match(c23_fs)
print(c23_fs.get_product())