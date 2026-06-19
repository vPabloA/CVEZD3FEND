"""End-to-end tests for the `CVEzD3FEND` Typer CLI.

Each test runs against an isolated `CVEZD3FEND_DATA_DIR` (a tmp_path) seeded
with the in-memory `sample_bundle`, so commands exercise the real CLI
plumbing (settings, bundle loading, export, AI candidate lifecycle) without
touching the real `data/` directory or the network.
"""

from __future__ import annotations

import errno
import json

import pytest
from typer.testing import CliRunner

from CVEzD3FEND.cli import _bind_static_server, app
from CVEzD3FEND.config import Settings
from CVEzD3FEND.intelligence import candidates as ai_candidates

runner = CliRunner()


@pytest.fixture
def cli_env(tmp_path, monkeypatch, sample_bundle):
    monkeypatch.setenv("CVEZD3FEND_DATA_DIR", str(tmp_path))
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(sample_bundle.model_dump_json(), encoding="utf-8")
    return settings


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_validate(cli_env):
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 0
    assert "structurally valid" in result.stdout


def test_bind_static_server_retries_busy_ports():
    seen_ports: list[int] = []

    class FakeHTTPServer:
        def __init__(self, address, handler):
            seen_ports.append(address[1])
            if address[1] < 8789:
                raise OSError(errno.EADDRINUSE, "Address already in use")
            self.address = address

    httpd, bound_port = _bind_static_server(FakeHTTPServer, object(), "127.0.0.1", 8787, retry_ports=5)
    assert bound_port == 8789
    assert seen_ports == [8787, 8788, 8789]
    assert httpd.address == ("127.0.0.1", 8789)


def test_serve_accepts_host_and_port(cli_env, monkeypatch):
    captured: dict[str, object] = {}

    class FakeHTTPServer:
        def serve_forever(self):
            raise KeyboardInterrupt

        def shutdown(self):
            captured["shutdown"] = True

    def fake_bind(httpd_cls, handler, host, port, retry_ports=25):
        captured["host"] = host
        captured["port"] = port
        captured["handler_directory"] = handler.keywords["directory"]
        return FakeHTTPServer(), port

    monkeypatch.setattr("CVEzD3FEND.cli._bind_static_server", fake_bind)

    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "8999"])
    assert result.exit_code == 0
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 8999
    assert captured["handler_directory"].endswith("dist")
    assert captured["shutdown"] is True
    assert "Serving" in result.stdout


def test_search(cli_env):
    result = runner.invoke(app, ["search", "PowerShell"])
    assert result.exit_code == 0
    assert "T1059.001" in result.stdout


def test_search_no_match(cli_env):
    result = runner.invoke(app, ["search", "zzz-no-such-thing-zzz"])
    assert result.exit_code == 1
    assert "No matches" in result.stdout


def test_route_for_cve(cli_env):
    result = runner.invoke(app, ["route", "CVE-2099-0001"])
    assert result.exit_code == 0
    assert "# Route" in result.stdout


def test_route_unknown(cli_env):
    result = runner.invoke(app, ["route", "DOES-NOT-EXIST"])
    assert result.exit_code == 1
    assert "No route found" in result.stdout


@pytest.mark.parametrize("fmt", ["md", "mermaid", "json", "csv"])
def test_export_route_formats(cli_env, fmt):
    result = runner.invoke(app, ["export", "route", "CVE-2099-0001", "--format", fmt])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_export_route_to_file(cli_env, tmp_path):
    out = tmp_path / "route.md"
    result = runner.invoke(app, ["export", "route", "CVE-2099-0001", "--format", "md", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("# Route")


@pytest.mark.parametrize("fmt", ["json", "csv"])
def test_export_coverage_formats(cli_env, fmt):
    result = runner.invoke(app, ["export", "coverage", "--format", fmt])
    assert result.exit_code == 0
    assert result.stdout.strip()


@pytest.mark.parametrize("fmt", ["md", "json"])
def test_export_soc_action_pack(cli_env, fmt):
    result = runner.invoke(app, ["export", "soc-action-pack", "T1059", "--format", fmt])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_export_soc_action_pack_unresolvable(cli_env):
    result = runner.invoke(app, ["export", "soc-action-pack", "DOES-NOT-EXIST"])
    assert result.exit_code == 1
    assert "Could not resolve" in result.stdout


def test_ai_explain_route(cli_env, sample_bundle):
    route_id = sample_bundle.routes[0].route_id
    result = runner.invoke(app, ["ai", "explain-route", route_id])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_ai_hunt_hypothesis(cli_env):
    result = runner.invoke(app, ["ai", "hunt-hypothesis", "T1059"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_ai_detection_brief(cli_env):
    result = runner.invoke(app, ["ai", "detection-brief", "T1059"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_ai_candidate_lifecycle(cli_env):
    # No candidates yet.
    result = runner.invoke(app, ["ai", "list-candidates"])
    assert result.exit_code == 0
    assert "No candidates" in result.stdout

    # Generate.
    result = runner.invoke(app, ["ai", "generate-candidates", "--limit", "10"])
    assert result.exit_code == 0
    assert "Generated 1 new candidate" in result.stdout

    queue = ai_candidates.load_candidates(cli_env)
    assert len(queue) == 1
    candidate_id = queue[0].candidate_id

    # Validate.
    result = runner.invoke(app, ["ai", "validate-candidates"])
    assert result.exit_code == 0
    assert "validated=1 rejected=0" in result.stdout

    # List with status filter (table truncates long ids, so check a stable prefix).
    result = runner.invoke(app, ["ai", "list-candidates", "--status", "validated_candidate"])
    assert result.exit_code == 0
    assert candidate_id[:13] in result.stdout

    # Promote requires --reviewer (Typer enforces it as a required option).
    result = runner.invoke(app, ["ai", "promote-candidate", candidate_id, "--reviewer", "alice"])
    assert result.exit_code == 0
    assert "Promoted" in result.stdout
    assert cli_env.promoted_edges_path.exists()

    overlay = json.loads(cli_env.promoted_edges_path.read_text(encoding="utf-8"))
    assert len(overlay) == 1
    assert overlay[0]["metadata"]["promoted_from_candidate"]["candidate_id"] == candidate_id


def test_ai_promote_candidate_unknown_id(cli_env):
    result = runner.invoke(app, ["ai", "promote-candidate", "AIC-does-not-exist", "--reviewer", "alice"])
    assert result.exit_code == 1


def test_ai_reject_candidate(cli_env):
    runner.invoke(app, ["ai", "generate-candidates", "--limit", "10"])
    queue = ai_candidates.load_candidates(cli_env)
    candidate_id = queue[0].candidate_id

    result = runner.invoke(app, ["ai", "reject-candidate", candidate_id, "--reviewer", "bob"])
    assert result.exit_code == 0
    assert "Rejected" in result.stdout

    queue = ai_candidates.load_candidates(cli_env)
    assert queue[0].final_status == "rejected"
