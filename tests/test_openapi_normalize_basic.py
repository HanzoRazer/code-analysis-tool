from __future__ import annotations

from code_audit.web_api.openapi_normalize import normalize_openapi


def test_normalize_openapi_merges_template_paths_by_shape_and_keys_ops() -> None:
    doc = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/items/{id}": {
                "get": {
                    "responses": {"200": {"description": "ok"}}
                }
            },
            "/items/{item_id}": {
                "post": {
                    "responses": {"201": {"description": "ok"}}
                }
            },
        },
    }

    n = normalize_openapi(doc)
    ops = [o.op for o in n.operations]
    assert ops == ["GET /items/{}", "POST /items/{}"]


def test_normalize_openapi_extracts_request_and_response_schema_signatures() -> None:
    doc = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "components": {"schemas": {"X": {"type": "string", "enum": ["b", "a"]}}},
        "paths": {
            "/x/{id}": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/X"}}
                        },
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "integer", "minimum": 0}}
                            }
                        }
                    },
                }
            }
        },
    }

    n = normalize_openapi(doc)
    op = n.operations[0]
    assert op.op == "PUT /x/{}"
    assert op.request_body.present is True
    assert op.request_body.required is True
    assert op.request_body.contents[0].content_type == "application/json"
    # enum should be sorted in signature
    assert op.request_body.contents[0].schema["target"]["enum"] == ["a", "b"]
    assert op.responses[0].status == "200"
    assert op.responses[0].contents[0].schema["minimum"] == 0
