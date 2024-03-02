import re

CVE_YEAR_PATTERN = re.compile(r'CVE-\d{4}')
CVE_PATTERN = re.compile(r'CVE-[0-9]+-[0-9]+')