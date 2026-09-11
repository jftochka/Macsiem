# MacSIEM. Standard library only: there is nothing to install to run the tests.
PYTHON ?= python3
LOOBINS_DIR ?= ../infosecb/loobins/LOOBins

.PHONY: help test selftest rulepack docs check coverage clean install

help:
	@echo "make test      - run the test suite (Linux, no Mac required)"
	@echo "make selftest  - replay the recorded intrusion end to end"
	@echo "make rulepack  - rebuild detection rules from the LOOBins corpus"
	@echo "make docs      - regenerate generated documentation"
	@echo "make check     - test + selftest + safety audit + coverage"
	@echo "make install   - install the launchd jobs (macOS, root)"

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

selftest:
	$(PYTHON) -m macsiem selftest

rulepack:
	$(PYTHON) tools/build_rulepack.py --loobins-dir $(LOOBINS_DIR)

# Refresh from the published feed instead of a local checkout.
rulepack-remote:
	curl -fsSL -o /tmp/loobins.json https://loobins.io/loobins.json
	$(PYTHON) tools/build_rulepack.py --json /tmp/loobins.json

docs:
	$(PYTHON) tools/gen_docs.py

coverage:
	$(PYTHON) -m macsiem probes --coverage

check: test selftest
	$(PYTHON) -m macsiem version
	$(PYTHON) -m macsiem probes --coverage | tail -1

install:
	sudo ./install.sh

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete
