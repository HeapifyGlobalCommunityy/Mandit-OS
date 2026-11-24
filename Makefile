# Same commands locally and in CI (.github/workflows/ci.yml). Run `make help` for the list.

PYTHON ?= python
PY_SRC := services sdk apps redteam scripts
STRICT_MODULES := services/core/mandit/common services/core/mandit/policy services/core/mandit/tokens
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.24.3

.PHONY: help install lint format test migrations secrets ci

help:
	@echo "install     install runtime and dev dependencies"
	@echo "lint        ruff (lint + format check) and mypy"
	@echo "format      apply ruff fixes and formatting"
	@echo "test        pytest (services/core/tests)"
	@echo "migrations  alembic round trip against DATABASE_URL (needs Postgres)"
	@echo "secrets     gitleaks over the git history (needs Docker)"
	@echo "ci          lint + test (what you should run before opening a PR)"

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check $(PY_SRC)
	$(PYTHON) -m ruff format --check $(PY_SRC)
	$(PYTHON) -m mypy services/core/mandit
	$(PYTHON) -m mypy --strict $(STRICT_MODULES)

format:
	$(PYTHON) -m ruff check --fix $(PY_SRC)
	$(PYTHON) -m ruff format $(PY_SRC)

test:
	$(PYTHON) -m pytest

migrations:
	$(PYTHON) scripts/ci/check_migrations.py

secrets:
	docker run --rm -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git /repo --redact --verbose

ci: lint test
