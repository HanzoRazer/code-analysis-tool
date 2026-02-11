# Makefile for code-analysis-tool
# Intentionally simple: one obvious way to run tests and lint

.PHONY: help install test lint lint-copy lint-copy-prose lint-schema lint-parity lint-ruff clean

PYTHON ?= python

help:
	@echo "Available targets:"
	@echo "  make install         Install dev dependencies"
	@echo "  make test            Run pytest (includes copy + schema checks)"
	@echo "  make lint            Run all linters"
	@echo "  make lint-copy       Run schema-aware copy linter against i18n/en"
	@echo "  make lint-copy-prose Run prose copy linter against i18n/"
	@echo "  make lint-schema     Validate cbsp21 schema example"
	@echo "  make lint-parity     Check locale key parity"
	@echo "  make lint-ruff       Run ruff linter on src/"
	@echo "  make clean           Remove Python cache files"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint: lint-copy lint-copy-prose lint-schema lint-parity lint-ruff

lint-copy:
	$(PYTHON) scripts/copy_lint_vibe_saas.py lint i18n/en --format text

lint-copy-prose:
	$(PYTHON) scripts/copy_lint.py lint i18n/ --format text

lint-schema:
	$(PYTHON) -m pytest tests/test_cbsp21_schema.py -q

lint-parity:
	$(PYTHON) scripts/locale_parity.py i18n/

lint-ruff:
	$(PYTHON) -m ruff check src/ tests/

clean:
	$(PYTHON) -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"
	@echo "Cleaned __pycache__ directories"
