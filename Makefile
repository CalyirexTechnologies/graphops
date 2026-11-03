.DEFAULT_GOAL := help
PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e '.[api,dev,neo4j]'

.PHONY: install
install: $(BIN)/python ## Create the venv and install everything

.PHONY: demo
demo: ## Run the engine demo. No dependencies, no venv needed.
	$(PY) -m graphops.demo

.PHONY: ingest
ingest: ## Run every connector in replay mode and resolve entities
	$(PY) -m graphops.cli ingest

.PHONY: analyse
analyse: ## Print the findings from the connector-built estate
	$(PY) -m graphops.cli analyse

.PHONY: test
test: install ## Run the test suite
	GRAPHOPS_SIGNING_KEY=local-test-key-$$(date +%s)-padding-padding \
		$(BIN)/pytest

.PHONY: cov
cov: install ## Run the suite with coverage
	GRAPHOPS_SIGNING_KEY=local-test-key-$$(date +%s)-padding-padding \
		$(BIN)/pytest --cov=graphops --cov-report=term-missing

.PHONY: lint
lint: install ## Lint
	$(BIN)/ruff check graphops tests

.PHONY: serve
serve: install ## Run the API on 127.0.0.1:8000
	@test -n "$$GRAPHOPS_SIGNING_KEY" || \
		(echo "GRAPHOPS_SIGNING_KEY is not set. Run: make keygen" && exit 1)
	$(BIN)/graphops serve

.PHONY: keygen
keygen: ## Print a signing key
	$(PY) -m graphops.cli keygen

.PHONY: fixtures
fixtures: ## Regenerate the connector fixtures
	$(PY) -m graphops.connectors.make_fixtures

.PHONY: neo4j-demo
neo4j-demo: install ## Compare the in-memory engine against Neo4j
	$(BIN)/python -m graphops.demo_neo4j

.PHONY: viewer
viewer: ## Serve the viewer on 127.0.0.1:8777
	$(PY) -m http.server 8777 --bind 127.0.0.1

.PHONY: clean
clean: ## Remove build and test output
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
