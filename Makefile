.PHONY: install build validate test web-install web-build serve clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
CVEZD3FEND := $(VENV)/bin/CVEzD3FEND

DIST_DIR := data/dist
WEB_DATA_DIR := web/public/data

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

build:
	$(CVEZD3FEND) build

validate:
	$(CVEZD3FEND) validate

test:
	$(VENV)/bin/pytest

web-install:
	cd web && npm install

web-build: web-install
	mkdir -p $(WEB_DATA_DIR)
	cp $(DIST_DIR)/knowledge-bundle.json $(WEB_DATA_DIR)/knowledge-bundle.json
	if [ -f $(DIST_DIR)/promoted-edges.json ]; then \
		cp $(DIST_DIR)/promoted-edges.json $(WEB_DATA_DIR)/promoted-edges.json; \
	fi
	cd web && npm run build

serve:
	$(CVEZD3FEND) serve

clean:
	rm -rf $(VENV) web/dist web/node_modules $(WEB_DATA_DIR)
