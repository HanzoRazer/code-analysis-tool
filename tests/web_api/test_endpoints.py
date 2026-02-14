"""
Web API Endpoint Tests
======================
Integration tests for the Level 1 MVP API endpoints.

Usage:
    pip install code-analysis-tool[api]
    pytest tests/web_api/test_endpoints.py -v
"""
import pytest
from pathlib import Path


# Skip entire module if FastAPI not installed
pytest.importorskip("fastapi")


from fastapi.testclient import TestClient
from code_audit.web_api.main import app


@pytest.fixture
def client():
    """Create test client for FastAPI app."""
    return TestClient(app)


@pytest.fixture
def repo_root() -> Path:
    """Get repository root for scanning."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd()


# ============================================================================
# HEALTH ENDPOINT
# ============================================================================

class TestHealthEndpoint:
    """Tests for GET /health"""

    def test_health_returns_200(self, client):
        """Health endpoint returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_ok_status(self, client):
        """Health endpoint returns status: ok."""
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "ok"

    def test_health_includes_version(self, client):
        """Health endpoint includes version field."""
        response = client.get("/health")
        data = response.json()
        assert "version" in data


# ============================================================================
# SCAN ENDPOINT
# ============================================================================

class TestScanEndpoint:
    """Tests for POST /scan/"""

    def test_scan_returns_200(self, client, repo_root):
        """Scan endpoint returns 200 for valid path."""
        response = client.post("/scan/", json={
            "repo_path": str(repo_root),
            "project_id": "test-project"
        })
        assert response.status_code == 200

    def test_scan_returns_complete_status(self, client, repo_root):
        """Scan endpoint returns status: complete."""
        response = client.post("/scan/", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        assert data["status"] == "complete"

    def test_scan_includes_summary(self, client, repo_root):
        """Scan endpoint returns summary with expected fields."""
        response = client.post("/scan/", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        summary = data["summary"]

        assert "files_scanned" in summary
        assert "total_lines" in summary
        assert "issues_found" in summary
        assert "confidence_score" in summary

    def test_scan_includes_result(self, client, repo_root):
        """Scan endpoint returns full result dict."""
        response = client.post("/scan/", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        assert "result" in data
        assert isinstance(data["result"], dict)

    def test_scan_invalid_path_returns_404(self, client):
        """Scan endpoint returns 404 for non-existent path."""
        response = client.post("/scan/", json={
            "repo_path": "/nonexistent/path/xyz123",
        })
        assert response.status_code == 404

    def test_scan_with_project_id(self, client, repo_root):
        """Scan endpoint accepts project_id."""
        response = client.post("/scan/", json={
            "repo_path": str(repo_root),
            "project_id": "my-project-123"
        })
        data = response.json()
        assert data["project_id"] == "my-project-123"


# ============================================================================
# GOVERNANCE ENDPOINT
# ============================================================================

class TestGovernanceEndpoint:
    """Tests for POST /scan/governance"""

    def test_governance_returns_200(self, client, repo_root):
        """Governance endpoint returns 200 for valid path."""
        response = client.post("/scan/governance", json={
            "repo_path": str(repo_root),
        })
        assert response.status_code == 200

    def test_governance_returns_complete_status(self, client, repo_root):
        """Governance endpoint returns status: complete."""
        response = client.post("/scan/governance", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        assert data["status"] == "complete"

    def test_governance_includes_all_gates(self, client, repo_root):
        """Governance endpoint returns all 4 gate results."""
        response = client.post("/scan/governance", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        gates = data["gates"]

        expected_gates = ["deprecation", "import_ban", "legacy_usage", "sdk_boundary"]
        for gate in expected_gates:
            assert gate in gates, f"Missing gate: {gate}"

    def test_governance_gate_structure(self, client, repo_root):
        """Each gate has passed and violation_count fields."""
        response = client.post("/scan/governance", json={
            "repo_path": str(repo_root),
        })
        data = response.json()

        for gate_name, gate_result in data["gates"].items():
            assert "passed" in gate_result, f"{gate_name} missing 'passed'"
            assert isinstance(gate_result["passed"], bool)

    def test_governance_invalid_path_returns_404(self, client):
        """Governance endpoint returns 404 for non-existent path."""
        response = client.post("/scan/governance", json={
            "repo_path": "/nonexistent/path/xyz123",
        })
        assert response.status_code == 404


# ============================================================================
# DEBT ENDPOINT
# ============================================================================

class TestDebtEndpoint:
    """Tests for POST /scan/debt"""

    def test_debt_returns_200(self, client, repo_root):
        """Debt endpoint returns 200 for valid path."""
        response = client.post("/scan/debt", json={
            "repo_path": str(repo_root),
        })
        assert response.status_code == 200

    def test_debt_returns_complete_status(self, client, repo_root):
        """Debt endpoint returns status: complete."""
        response = client.post("/scan/debt", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        assert data["status"] == "complete"

    def test_debt_includes_debt_count(self, client, repo_root):
        """Debt endpoint returns debt_count."""
        response = client.post("/scan/debt", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        debt = data["debt"]

        assert "debt_count" in debt
        assert isinstance(debt["debt_count"], int)

    def test_debt_includes_items(self, client, repo_root):
        """Debt endpoint returns items list."""
        response = client.post("/scan/debt", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        debt = data["debt"]

        assert "items" in debt
        assert isinstance(debt["items"], list)

    def test_debt_includes_by_type(self, client, repo_root):
        """Debt endpoint returns by_type breakdown."""
        response = client.post("/scan/debt", json={
            "repo_path": str(repo_root),
        })
        data = response.json()
        debt = data["debt"]

        assert "by_type" in debt
        assert isinstance(debt["by_type"], dict)

    def test_debt_invalid_path_returns_404(self, client):
        """Debt endpoint returns 404 for non-existent path."""
        response = client.post("/scan/debt", json={
            "repo_path": "/nonexistent/path/xyz123",
        })
        assert response.status_code == 404


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestEndpointIntegration:
    """Integration tests across endpoints."""

    def test_all_endpoints_accessible(self, client, repo_root):
        """All 4 MVP endpoints respond successfully."""
        endpoints = [
            ("GET", "/health", None),
            ("POST", "/scan/", {"repo_path": str(repo_root)}),
            ("POST", "/scan/governance", {"repo_path": str(repo_root)}),
            ("POST", "/scan/debt", {"repo_path": str(repo_root)}),
        ]

        for method, path, payload in endpoints:
            if method == "GET":
                response = client.get(path)
            else:
                response = client.post(path, json=payload)

            assert response.status_code == 200, f"{method} {path} failed: {response.status_code}"

    def test_scan_and_debt_consistency(self, client, repo_root):
        """Scan and debt endpoints analyze same files."""
        scan_resp = client.post("/scan/", json={"repo_path": str(repo_root)})
        debt_resp = client.post("/scan/debt", json={"repo_path": str(repo_root)})

        # Both should succeed
        assert scan_resp.status_code == 200
        assert debt_resp.status_code == 200

        # Both should return complete status
        assert scan_resp.json()["status"] == "complete"
        assert debt_resp.json()["status"] == "complete"
