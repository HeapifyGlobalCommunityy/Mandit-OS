"""Smoke test: every module of the core package imports cleanly.

Catches syntax errors, missing dependencies and circular imports in modules that do not have
their own tests yet. It says nothing about behaviour; each team adds tests under tests/<module>/.
"""

import importlib
import pkgutil

import pytest

import mandit

# Every submodule is imported, so modules must not do real work at import time.
MODULES = sorted(name for _, name, _ in pkgutil.walk_packages(mandit.__path__, prefix="mandit."))


def test_core_modules_found():
    team_packages = {"identity", "mandates", "safety", "gateway", "grounding", "policy",
                     "payments", "tokens", "confirmation", "evidence", "common"}  # fmt: skip
    found = {name.split(".")[1] for name in MODULES}
    assert team_packages <= found, f"missing packages: {sorted(team_packages - found)}"


@pytest.mark.parametrize("module", MODULES)
def test_module_imports(module):
    importlib.import_module(module)
