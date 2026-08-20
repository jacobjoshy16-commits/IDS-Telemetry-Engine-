SHELL := /bin/bash
PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help install test lint typecheck check replay benchmark compose-up compose-down clean

help:
	@printf '%s\n' \
	  'install       Install the package and development dependencies' \
	  'test          Run the automated test suite' \
	  'lint          Run Ruff checks' \
	  'typecheck     Run strict mypy checks' \
	  'check         Run lint, typecheck, and tests' \
	  'replay        Replay the bundled mixed-sensor fixture' \
	  'benchmark     Run the deterministic ingestion benchmark' \
	  'compose-up    Start engine, OpenSearch, and Dashboards' \
	  'compose-down  Stop the Compose stack and remove containers'

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: $(BIN)/python
	$(BIN)/pip install -e '.[dev]'

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck:
	$(BIN)/mypy

check: lint typecheck test

replay:
	$(BIN)/ids-telemetry replay \
	  --suricata tests/fixtures/suricata_eve.jsonl \
	  --zeek-conn tests/fixtures/zeek_conn.jsonl \
	  --zeek-dns tests/fixtures/zeek_dns.jsonl \
	  --endpoint-auth tests/fixtures/endpoint_auth.jsonl \
	  --output data/output/replay.jsonl

benchmark:
	$(BIN)/python scripts/benchmark.py --events 100000 --assert-eps 5000

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

clean:
	rm -rf .coverage .mypy_cache .pytest_cache .ruff_cache htmlcov
