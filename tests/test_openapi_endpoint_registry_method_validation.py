"""Unit tests for endpoint registry method validation.

Locks behavior:
  - accepts uppercase canonical verbs
  - rejects invalid verbs
  - rejects lowercase in dict form (canonical contract)
  - rejects string-form entries (banned)
"""
from __future__ import annotations

import pytest

from tests.test_release_openapi_registry_matches_snapshot import _extract_registry_endpoints


def test_registry_accepts_uppercase_verbs() -> None:
    reg = {"endpoints": [{"method": "GET", "path": "/health"}]}
    assert _extract_registry_endpoints(reg) == [("GET", "/health")]


def test_registry_rejects_invalid_verb() -> None:
    reg = {"endpoints": [{"method": "FETCH", "path": "/x"}]}
    with pytest.raises(AssertionError):
        _extract_registry_endpoints(reg)


def test_registry_rejects_lowercase_dict_method_to_keep_canonical() -> None:
    reg = {"endpoints": [{"method": "get", "path": "/health"}]}
    with pytest.raises(AssertionError):
        _extract_registry_endpoints(reg)


def test_registry_rejects_string_form_entries() -> None:
    reg = {"endpoints": ["GET /health"]}
    with pytest.raises(AssertionError):
        _extract_registry_endpoints(reg)
