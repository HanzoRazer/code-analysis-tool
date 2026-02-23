from __future__ import annotations

from code_audit.web_api.openapi_diff import diff_openapi_core
from code_audit.web_api.openapi_normalize import normalize_openapi


def _doc(paths: dict, components: dict | None = None) -> dict:
    d = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}
    if components:
        d["components"] = components
    return d


def test_param_enum_narrowed_is_breaking_enum_widened_is_non_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "parameters": [
                            {"in": "query", "name": "q", "required": False, "schema": {"type": "string", "enum": ["a", "b", "c"]}}
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    after_narrow = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "parameters": [
                            {"in": "query", "name": "q", "required": False, "schema": {"type": "string", "enum": ["a", "b"]}}
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after_narrow)
    assert any(c.kind == "parameter_schema_narrowed" for c in rep.breaking_changes)

    after_wide = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "parameters": [
                            {"in": "query", "name": "q", "required": False, "schema": {"type": "string", "enum": ["a", "b", "c", "d"]}}
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    rep2 = diff_openapi_core(before, after_wide)
    assert any(c.kind == "parameter_schema_widened" for c in rep2.non_breaking_changes)


def test_request_schema_narrowed_is_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "post": {
                        "requestBody": {"required": False, "content": {"application/json": {"schema": {"type": "string"}}}},
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    after = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "post": {
                        "requestBody": {
                            "required": False,
                            "content": {"application/json": {"schema": {"type": "string", "enum": ["a", "b"]}}},
                        },
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "request_schema_narrowed" for c in rep.breaking_changes)


def test_success_response_schema_narrowed_is_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {
                            "200": {"content": {"application/json": {"schema": {"type": "string"}}}}
                        }
                    }
                }
            }
        )
    )
    after = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {
                            "200": {"content": {"application/json": {"schema": {"type": "string", "enum": ["a"]}}}}
                        }
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "success_response_schema_narrowed" for c in rep.breaking_changes)


def test_oneof_change_is_unknown_by_default() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"oneOf": [{"type": "string"}, {"type": "integer"}]}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
    )
    after = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"oneOf": [{"type": "string"}, {"type": "number"}]}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "success_response_schema_changed_unknown" for c in rep.unknown_changes)
