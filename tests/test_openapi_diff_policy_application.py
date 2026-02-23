from __future__ import annotations

from code_audit.web_api.openapi_diff import apply_allowlist_policy, diff_openapi_core
from code_audit.web_api.openapi_normalize import normalize_openapi


def _doc(paths: dict) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}


def test_allow_unknown_converts_unknown_to_non_breaking_with_annotation() -> None:
    # Create an 'unknown' by removing a non-success response media type (core diff treats this as unknown)
    before = normalize_openapi(
        _doc(
            {
                "/x/{id}": {
                    "get": {
                        "responses": {"404": {"content": {"application/json": {"schema": {"type": "string"}}}}}
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
                        "responses": {"404": {"content": {}}}
                    }
                }
            }
        )
    )
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "removed_non_success_response_media_type" for c in rep.unknown_changes)

    policy = {
        "version": 1,
        "allow_unknown": [
            {
                "kind": "removed_non_success_response_media_type",
                "op": "GET /x/{}",
                "location": "responses.404.content.application/json",
                "reason": "404 payload is not part of success contract"
            }
        ],
        "allow_breaking": [],
        "allow_breaking_to_non_breaking": False,
    }
    rep2 = apply_allowlist_policy(rep, policy=policy)
    assert not any(c.kind == "removed_non_success_response_media_type" for c in rep2.unknown_changes)
    assert any(c.kind == "allowed_unknown" for c in rep2.non_breaking_changes)
    assert all(
        "allowed_by_policy" in (c.detail or "")
        for c in rep2.non_breaking_changes
        if c.kind == "allowed_unknown"
    )


def test_allow_breaking_defaults_to_unknown_unless_explicitly_permitted() -> None:
    before = normalize_openapi(_doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}}))
    after = normalize_openapi(_doc({}))
    rep = diff_openapi_core(before, after)
    assert any(c.kind == "removed_operation" for c in rep.breaking_changes)

    policy = {
        "version": 1,
        "allow_unknown": [],
        "allow_breaking": [
            {"kind": "removed_operation", "op": "GET /x/{}", "reason": "Intentional deprecation"}
        ],
        "allow_breaking_to_non_breaking": False,
    }
    rep2 = apply_allowlist_policy(rep, policy=policy)
    assert not any(c.kind == "removed_operation" for c in rep2.breaking_changes)
    assert any(c.kind == "allowed_breaking_to_unknown" for c in rep2.unknown_changes)


def test_allow_breaking_to_non_breaking_when_enabled() -> None:
    before = normalize_openapi(_doc({"/x/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}}))
    after = normalize_openapi(_doc({}))
    rep = diff_openapi_core(before, after)

    policy = {
        "version": 1,
        "allow_unknown": [],
        "allow_breaking": [
            {"kind": "removed_operation", "op": "GET /x/{}", "reason": "Coordinated removal across clients"}
        ],
        "allow_breaking_to_non_breaking": True,
    }
    rep2 = apply_allowlist_policy(rep, policy=policy)
    assert rep2.breaking is False
    assert any(c.kind == "allowed_breaking" for c in rep2.non_breaking_changes)
