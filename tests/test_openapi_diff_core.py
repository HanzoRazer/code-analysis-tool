from __future__ import annotations

from code_audit.web_api.openapi_diff import diff_openapi_core
from code_audit.web_api.openapi_normalize import normalize_openapi


def _doc(paths: dict) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}


def test_removed_operation_is_breaking() -> None:
    before = normalize_openapi(_doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}}))
    after = normalize_openapi(_doc({}))
    rep = diff_openapi_core(before, after)
    assert rep.breaking is True
    kinds = [c.kind for c in rep.breaking_changes]
    assert "removed_operation" in kinds


def test_added_operation_is_non_breaking() -> None:
    before = normalize_openapi(_doc({}))
    after = normalize_openapi(_doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}}))
    rep = diff_openapi_core(before, after)
    assert rep.breaking is False
    assert any(c.kind == "added_operation" for c in rep.non_breaking_changes)


def test_removed_parameter_is_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "parameters": [{"in": "query", "name": "q", "required": False, "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    after = normalize_openapi(
        _doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}})
    )
    rep = diff_openapi_core(before, after)
    assert rep.breaking is True
    assert any(c.kind == "removed_parameter" for c in rep.breaking_changes)


def test_parameter_required_tightened_is_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "parameters": [{"in": "query", "name": "q", "required": False}],
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
                    "get": {
                        "parameters": [{"in": "query", "name": "q", "required": True}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "parameter_required_tightened" for c in rep.breaking_changes)


def test_request_body_required_tightened_is_breaking() -> None:
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
                        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "string"}}}},
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "request_body_required_tightened" for c in rep.breaking_changes)


def test_removed_success_status_is_breaking_added_is_non_breaking() -> None:
    before = normalize_openapi(
        _doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}, "404": {"description": "no"}}}}})
    )
    after = normalize_openapi(
        _doc({"/x/{id}": {"get": {"responses": {"201": {"description": "ok"}, "404": {"description": "no"}}}}})
    )
    rep = diff_openapi_core(before, after, success_status_prefixes=("2",))
    # 200 removed => breaking
    assert any(c.kind == "removed_success_response_status" for c in rep.breaking_changes)
    # 201 added => non-breaking
    assert any(c.kind == "added_response_status" for c in rep.non_breaking_changes)


def test_removed_success_media_type_is_breaking() -> None:
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {"schema": {"type": "string"}},
                                    "text/plain": {"schema": {"type": "string"}},
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
                        "responses": {"200": {"content": {"application/json": {"schema": {"type": "string"}}}}}
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "removed_success_response_media_type" for c in rep.breaking_changes)


def test_diff_report_to_dict_is_deterministic() -> None:
    before = normalize_openapi(_doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}}))
    after = normalize_openapi(_doc({}))
    rep = diff_openapi_core(before, after)
    d = rep.to_dict()
    assert d["version"] == 1
    assert d["breaking"] is True
    assert d["summary"]["breaking_count"] >= 1
    assert isinstance(d["breaking_changes"], list)
    assert isinstance(d["non_breaking_changes"], list)
    assert isinstance(d["unknown_changes"], list)
