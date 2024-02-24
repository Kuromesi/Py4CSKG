
ANALYZER_IMG = security-analyzer:test
build-analyzer:
	docker build -f Dockerfile.analyzer src -t $(ANALYZER_IMG)

ANALYZER_CONF = shared/demo/analyzer_conf.yaml
analyzer_name = analyzer_$(shell date +'%s')
analyze:
	docker run --rm --name $(analyzer_name) -v $(CURDIR)/config.cfg:/app/config.cfg:Z \
	-v $(CURDIR)/shared/analyzer:/app/shared:Z \
	-e CONF_PATH=$(ANALYZER_CONF) $(ANALYZER_IMG)