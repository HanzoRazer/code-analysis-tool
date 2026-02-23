"""Unit tests for OpenAPI path template normalization.

Locks the semantics:
  - {id} and {item_id} match via normalization
  - differing segment counts don't match
  - literals must match
  - paths_equivalent_by_template is deterministic
"""
from __future__ import annotations

from code_audit.web_api.openapi_path_match import (
    normalize_openapi_path_template,
    paths_equivalent_by_template,
)


def test_normalize_openapi_path_template() -> None:
    assert normalize_openapi_path_template("/items/{id}") == "/items/{}"
    assert normalize_openapi_path_template("/a/{x}/b/{y}") == "/a/{}/b/{}"
    assert normalize_openapi_path_template("items/{id}") == "/items/{}"


def test_paths_equivalent_by_template_param_names_ignored() -> None:
    assert paths_equivalent_by_template("/items/{id}", "/items/{item_id}") is True
    assert paths_equivalent_by_template("/a/{x}/b", "/a/{y}/b") is True


def test_paths_equivalent_by_template_requires_same_literals_and_shape() -> None:
    assert paths_equivalent_by_template("/items/{id}", "/items/{id}/sub") is False
    assert paths_equivalent_by_template("/items/{id}", "/itemz/{id}") is False
    assert paths_equivalent_by_template("/a/{x}/b/{y}", "/a/{x}/c/{y}") is False
