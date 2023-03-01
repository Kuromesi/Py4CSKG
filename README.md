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

## NEO4J COMMANDS
docker run -it --rm -v /shared/databases/neo4j/data/:/data neo4j:latest \
neo4j-admin database import full --overwrite-destination \
--nodes=/data/import/capec_pt.csv --nodes=/data/import/capec_misc.csv \
--nodes=/data/import/attack_tech.csv --nodes=/data/import/attack_misc.csv \
--nodes=/data/import/cwe_wk.csv --nodes=/data/import/cwe_misc.csv \
--relationships=/data/import/capec_rel.csv --relationships=/data/import/cwe_rel.csv --relationships=/data/import/attack_rel.csv \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true
--skip-bad-relationships=true --skip-duplicate-nodes=true

docker run -it --rm -v /shared/databases/neo4j/data/:/data neo4j:latest \
neo4j-admin database import full --overwrite-destination \
--nodes=/data/import/nodes/capec_pt.csv --nodes=/data/import/nodes/capec_misc.csv \
--nodes=/data/import/nodes/attack_tech.csv --nodes=/data/import/nodes/attack_misc.csv \
--nodes=/data/import/nodes/cwe_wk.csv --nodes=/data/import/nodes/cwe_misc.csv \
--nodes=/data/import/nodes/cve_cve.*.csv --nodes=/data/import/nodes/cve_cpe.*.csv \
--relationships=/data/import/relations/.*.csv \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true --skip-bad-relationships=true --auto-skip-subsequent-headers=true

docker run -it --rm -v /shared/databases/neo4j/data/:/data neo4j:latest \
neo4j-admin database import full --overwrite-destination \
--nodes=/data/import/nodes/cve_cve.*.csv --nodes=/data/import/nodes/cve_cpe.*.csv \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true --skip-bad-relationships=true --auto-skip-subsequent-headers=true