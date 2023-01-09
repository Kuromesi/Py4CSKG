# Py4CSKG
This is a python project for creating CyberSecurity Knowledge Graph (CSKG) developed and maintained by Kuromesi, graduate student of School of Systems and Science Engineering, Sun Yat-sen University.

## USAGE
### SOME SPACY COMMANDS
`spacy train config.cfg --output ./output --gpu-id 0`
`spacy convert ./train.conll . -s -n 10`
`spacy evaluate output/model-best/ dev.spacy --gpu-id 0`

## DEMONSTRATIONS
### FIND HIDDEN RELATIONS
PHP remote file inclusion vulnerabilities CVE-2007
CVE-2012-5970
obtain sensitive information CVE-2007
CVE-2021-0109 Insecure inherited permissions

### FIND RELATED ATTACK PATTERNS
CVE-2021-36758
CVE-2021-21482

## FIND RELATED WEAKNESSES
CVE-2021-0056 Insecure inherited permissions
CVE-1999-0003 CWE-119 CVE-1999-0027
CVE-2019-5314 CWE-74