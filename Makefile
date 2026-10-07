.PHONY: help setup demo lint test sigma check

PY ?= python3

help:  ## Show targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/ -/'

setup:  ## Install Python dependencies for tooling, linting and tests
	$(PY) -m pip install -r requirements-dev.txt

demo:  ## Run the IOC enricher offline on bundled synthetic sample data (no API keys)
	$(PY) tools/ioc-enricher/ioc_enricher.py --demo

lint:  ## yamllint + ruff
	yamllint -c .yamllint.yml .
	ruff check .

test:  ## Run the offline test-suite
	$(PY) -m pytest -q

sigma:  ## Validate Sigma rules and convert the Windows ones to Elasticsearch queries
	sigma check -x attacktag detections/sigma
	sigma plugin install elasticsearch
	sigma convert -t lucene -p ecs_windows detections/sigma/execution detections/sigma/defense-evasion \
		detections/sigma/credential-access/SOC-051-mimikatz-indicators.yml

check: lint test sigma  ## Everything CI runs except Suricata and Ansible
