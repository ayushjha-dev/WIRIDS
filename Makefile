# WIDIRS - developer task runner
#
# Usage:
#   make test              Run the full test suite
#   make test-cov          Run tests with coverage report
#   make test-verbose      Run tests with verbose output
#   make test-integration  Run only integration tests
#   make test-monitor      Run only monitor module tests
#   make test-change-detect Run only change_detect tests
#   make test-ioc-extract  Run only ioc_extract tests
#   make test-ai-classify  Run only ai_classify tests
#   make test-threat-intel Run only threat_intel tests
#   make lint              Static analysis (ruff + mypy)
#   make format            Auto-format (black + ruff --fix)
#   make format-check      Check formatting without changes
#   make clean             Remove caches and generated artefacts

PYTHON ?= python
PIP    ?= $(PYTHON) -m pip
PKGS   := modules config.py database.py main.py models.py
TESTS  := tests

.DEFAULT_GOAL := test
.PHONY: test test-cov test-verbose test-integration test-monitor test-change-detect test-ioc-extract test-ai-classify test-threat-intel lint format format-check clean install help

help:
	@echo "WIDIRS Test Suite & Development Makefile"
	@echo "========================================"
	@echo ""
	@echo "Test targets:"
	@echo "  make test                 - Run all unit and integration tests"
	@echo "  make test-cov             - Run tests with coverage report"
	@echo "  make test-verbose         - Run tests with verbose output"
	@echo "  make test-integration     - Run only integration tests"
	@echo "  make test-monitor         - Run only monitor module tests"
	@echo "  make test-change-detect   - Run only change_detect tests"
	@echo "  make test-ioc-extract     - Run only ioc_extract tests"
	@echo "  make test-ai-classify     - Run only ai_classify tests"
	@echo "  make test-threat-intel    - Run only threat_intel tests"
	@echo ""
	@echo "Code quality targets:"
	@echo "  make lint                 - Run code linting (ruff + mypy)"
	@echo "  make format               - Auto-format (black + ruff --fix)"
	@echo "  make format-check         - Check formatting without changes"
	@echo ""
	@echo "Maintenance targets:"
	@echo "  make install              - Install dependencies from requirements.txt"
	@echo "  make clean                - Remove caches and generated artefacts"
	@echo ""

install:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-asyncio pytest-cov ruff black mypy

test:
	$(PYTHON) -m pytest

test-cov:
	$(PYTHON) -m pytest \
		--cov=modules --cov=config --cov=database --cov=main --cov=models \
		--cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

test-verbose:
	$(PYTHON) -m pytest -vv -s --tb=long

test-integration:
	$(PYTHON) -m pytest tests/ -v -m integration

test-monitor:
	$(PYTHON) -m pytest tests/test_monitor.py -v

test-change-detect:
	$(PYTHON) -m pytest tests/test_change_detect.py -v

test-ioc-extract:
	$(PYTHON) -m pytest tests/test_ioc_extract.py -v

test-ai-classify:
	$(PYTHON) -m pytest tests/test_ai_classify.py -v

test-threat-intel:
	$(PYTHON) -m pytest tests/test_threat_intel.py -v

lint:
	$(PYTHON) -m ruff check $(PKGS) $(TESTS)
	$(PYTHON) -m mypy $(PKGS)

format-check:
	$(PYTHON) -m black --check $(PKGS) $(TESTS)
	$(PYTHON) -m ruff check $(PKGS) $(TESTS)

format:
	$(PYTHON) -m black $(PKGS) $(TESTS)
	$(PYTHON) -m ruff check --fix $(PKGS) $(TESTS)

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	rm -rf data/diffs data/snapshots data/reports
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

