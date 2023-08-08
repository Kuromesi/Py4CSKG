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
--nodes=/data/import/nodes/.*.csv \
--relationships=/data/import/relations/.*.csv \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true --skip-bad-relationships=true --auto-skip-subsequent-headers=true

docker run -it --rm -v /shared/databases/neo4j/data/:/data neo4j:latest \
neo4j-admin database import full --overwrite-destination \
--nodes=/data/import/nodes/cve_cve.*.csv --nodes=/data/import/nodes/cve_cpe.*.csv \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true --skip-bad-relationships=true --auto-skip-subsequent-headers=true

docker run -it --rm -v /Users/kuromesi/MyCOde/share/neo4j/data:/data neo4j:latest \
neo4j-admin database import full --overwrite-destination \
--nodes="/data/import/nodes/attack_misc.*.csv" --nodes="/data/import/nodes/attack_tech.*.csv" \
--nodes="/data/import/nodes/capec_misc.csv" --nodes="/data/import/nodes/capec_pt.csv" \
--nodes="/data/import/nodes/cve_cpe1.csv" --nodes="/data/import/nodes/cve_cve1.csv" \
--relationships="/data/import/relations/.*.csv" \
--multiline-fields=true --ignore-empty-strings=true --skip-duplicate-nodes=true --skip-bad-relationships=true \
--auto-skip-subsequent-headers=true neo4j

### FULL-TEXT INDEX
CREATE FULLTEXT INDEX vulDes FOR (n:Vulnerability) ON EACH [n.description]

CALL db.index.fulltext.queryNodes("vulDes", "sql injection") YIELD node, score
RETURN node.id, node.description, score limit 25

### DELETE DUPLICATE RELATIONS
match ()-[r]->() 
match (s)-[r]->(e) 
with s,e,type(r) as typ, tail(collect(r)) as coll 
foreach(x in coll | delete x)

## RULES
[]: represent list
(): represent nodes, id etc. e.g. (component), (component.id)
    ontology:
        component, firmware, hardware, software, os, entry
{}: represent functions
    \#: defend, this comonent is designed to perform some defensive functions ,e.g. #{component.*} which means restrict access of all nodes
    @: compromised, 
    ->: lead to
    <-: require
    !: not, disable some functions, e.g. @(software.id)->!#{component*}
    <=>: communicate
$: asset, default values are userPrivilege, rootPrivilege, appPrivilege, appCodeExec, systemCodeExec

some examples:
    (\$<appPrivilege>)<-@->(:<component>.<firewall>)!\#(component.*)
    \#(:<entry>.<id>)

## ATTACK EXAMPLES
### wannacry 
CVE-2017-0144 System arbitrary code execution 
https://success.trendmicro.com/dcx/s/solution/1117391-preventing-wannacry-wcry-ransomware-attacks-using-trend-micro-products?language=en_US&sfdcIFrameOrigin=null

### Stuxnet
CVE-2010-2568 System arbitrary code execution
CVE-2008-4250 System arbitrary code execution
CVE-2010-2729 System arbitrary code execution Print spooler

CVE-2010-2743 Privilege escalation

### Ukraine power grid
CVE-2014-4114 System arbitrary code execution 
https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf

## CVE CLASSIFICATION
CVE-2020-10814 N/N/P Code exec/Application crash https://sourceforge.net/p/codeblocks/tickets/934/
CVE-2020-10374 P/P/P Code exec/Chromium engine to create the screenshot https://kb.paessler.com/en/topic/87668-how-can-i-mitigate-cve-2020-10374-until-i-can-update
CVE-2020-10214 C/C/C Code exec/Any code https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability4.md