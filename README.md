# Py4CSKG
This is a python project for creating CyberSecurity Knowledge Graph (CSKG) developed and maintained by Kuromesi.

## Code Structure

```
├── docker # dockerfile and docker-compose files of apis
│   ├── analyzer
│   ├── data_updater
│   ├── mongo_client
│   ├── text_classification # undone
│   └── text_similarity # undone
├── src
│   ├── analyzer # generate attack graph and attack path
│   ├── clients # apis to call different modules
│   ├── database
│   ├── data_updater # update cve, capec, att&ck and cwe
│   ├── misc
│   ├── ner
│   ├── ontologies
│   ├── requirements
│   ├── service
│   ├── tests
│   ├── text_classification # discover relations between cve and cwe
│   ├── text_similarity # discover relations between cve and capec
│   ├── utils
│   └── webapp
```