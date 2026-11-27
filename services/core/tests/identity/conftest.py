"""Pytest fixtures for identity tests. Helpers live in identity_support.py."""

import pytest
from identity_support import Registry, make_registry


@pytest.fixture
def registry() -> Registry:
    return make_registry()
