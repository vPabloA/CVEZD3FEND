"""CVEzD3FEND CLI — build/validate/serve/route/search/export/ai/api/mcp.

See docs/OPERATIONS.md for the full command reference.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from CVEzD3FEND import __version__
from CVEzD3FEND.actions.soc_action_pack import build_soc_action_pack
from CVEzD3FEND.config import Settings, get_settings
from CVEzD3FEND.export import csv_export, json_export, markdown, mermaid
from CVEzD3FEND.intelligence import candidates as ai_candidates
from CVEzD3FEND.intelligence import explain as ai_explain
from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import Node, NodeType
from CVEzD3FEND.pipeline import run_build
from CVEzD3FEND.reasoning import ReasoningEngine
from CVEzD3FEND.reasoning.models import EnrichmentResult, ReasoningResult
from CVEzD3FEND.validation.schema import validate_structure

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)
export_app = typer.Typer(no_args_is_help=True, help="Export routes/coverage/SOC action packs.")
ai_app = typer.Typer(no_args_is_help=True, help="AI candidate generation/review (offline by default).")
app.add_typer(export_app, name="export")
app.add_typer(ai_app, name="ai")

console = Console()
_TOKEN_RE = re.compile(r"[a-z0-9]+")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_bundle(settings: Settings) -> Bundle:
    if not settings.bundle_path.exists():
        console.print(
            f"[red]Bundle not found at {settings.bundle_path}. Run `CVEzD3FEND build` first.[/red]"
        )
        raise typer.Exit(code=1)
    data = json.loads(settings.bundle_path.read_text(encoding="utf-8"))
    return Bundle.model_validate(data)


def _resolve_route(bundle: Bundle, ref: str) -> Route | None:
    route = next((r for r in bundle.routes if r.route_id == ref), None)
    if route is not None:
        return route
    route_ids: list[str] = bundle.indexes.get("cve_routes", {}).get(ref, [])
    if route_ids:
        return next((r for r in bundle.routes if r.route_id == route_ids[0]), None)
    return None


def _resolve_attack_id(bundle: Bundle, ref: str) -> str | None:
    nodes_by_id = {n.id: n for n in bundle.nodes}
    node = nodes_by_id.get(ref)
    if node is not None and node.type == NodeType.ATTACK:
        return ref
    route = _resolve_route(bundle, ref)
    if route is not None:
        for node_id in route.nodes:
            candidate = nodes_by_id.get(node_id)
            if candidate is not None and candidate.type == NodeType.ATTACK:
                return node_id
    return None


def _search_nodes(bundle: Bundle, query: str, limit: int) -> list[Node]:
    nodes_by_id = {n.id: n for n in bundle.nodes}
    stripped = query.strip()
    if stripped in nodes_by_id:
        return [nodes_by_id[stripped]]

    tokens = [t for t in _TOKEN_RE.findall(stripped.lower()) if len(t) >= 2]
    by_text: dict[str, list[str]] = bundle.indexes.get("by_text", {})
    by_alias: dict[str, list[str]] = bundle.indexes.get("by_alias", {})
    scores: Counter[str] = Counter()
    for token in tokens:
        for node_id in by_text.get(token, []):
            scores[node_id] += 1
        for node_id in by_alias.get(token, []):
            scores[node_id] += 2

    if not scores:
        needle = stripped.lower()
        for node in bundle.nodes:
            if needle in node.id.lower() or needle in node.name.lower():
                scores[node.id] += 1

    return [nodes_by_id[node_id] for node_id, _ in scores.most_common(limit) if node_id in nodes_by_id]


def _write_output(content: str, output: Optional[Path]) -> None:
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        print(content)


def _load_reasoning_engine(settings: Settings) -> ReasoningEngine:
    return ReasoningEngine(settings)


def _render_enrichment_result(result: EnrichmentResult, format: str) -> str:
    if format == "json":
        return result.model_dump_json(indent=2)
    if format == "tree":
        lines = [
            f"{result.normalized_input}",
            f"|-- status: {result.status}",
            f"|-- source_mode: {result.source_mode}",
            "|-- profile",
            f"   |-- description: {result.profile.description or 'n/a'}",
            f"   |-- cwes: {', '.join(result.profile.cwes) if result.profile.cwes else 'n/a'}",
            f"   |-- semantic_tags: {', '.join(result.profile.semantic_tags) if result.profile.semantic_tags else 'n/a'}",
            f"   `-- affected_products: {', '.join(result.profile.affected_products) if result.profile.affected_products else 'n/a'}",
        ]
        return "\n".join(lines)
    return "\n".join(
        [
            f"# Enrichment for {result.normalized_input}",
            "",
            f"- Status: {result.status}",
            f"- Source mode: {result.source_mode}",
            f"- Description: {result.profile.description or 'n/a'}",
            f"- CWEs: {', '.join(result.profile.cwes) if result.profile.cwes else 'n/a'}",
            f"- Semantic tags: {', '.join(result.profile.semantic_tags) if result.profile.semantic_tags else 'n/a'}",
        ]
    )


def _render_reasoning_result(result: ReasoningResult, format: str) -> str:
    if format == "json":
        return result.model_dump_json(indent=2)
    if format == "tree":
        return result.exports.tree
    return result.exports.markdown


FormatOption = typer.Option("md", "--format", "-f", help="Output format")
OutputOption = typer.Option(None, "--output", "-o", help="Write to file instead of stdout")


# ---------------------------------------------------------------------------
# Core commands
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the CVEzD3FEND package version."""
    console.print(__version__)


@app.command()
def enrich(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
    format: str = typer.Option("json", "--format", "-f", help="Output format", case_sensitive=False),
) -> None:
    """Fetch live/cache/static enrichment and emit a normalized CVE profile."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        result = engine.enrich(cve_id)
    finally:
        engine.close()
    content = _render_enrichment_result(result, format.lower())
    print(content)


@app.command()
def reason(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
    format: str = typer.Option("json", "--format", "-f", help="Output format", case_sensitive=False),
) -> None:
    """Compute the reasoned route contract and provenance classification."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        result = engine.reason(cve_id)
    finally:
        engine.close()
    content = _render_reasoning_result(result, format.lower())
    print(content)


@app.command()
def explain(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
) -> None:
    """Print the Spanish defensive narrative for a CVE."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        console.print(engine.explain(cve_id))
    finally:
        engine.close()


@app.command()
def hunt(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
) -> None:
    """Print a threat-hunting brief derived from the reasoning contract."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        console.print(engine.hunt(cve_id))
    finally:
        engine.close()


@app.command()
def detect(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
) -> None:
    """Print a detection-engineering brief derived from the reasoning contract."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        console.print(engine.detect(cve_id))
    finally:
        engine.close()


@app.command()
def ctem(
    cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2025-0168"),
) -> None:
    """Print a CTEM-oriented prioritization brief derived from the reasoning contract."""
    settings = get_settings()
    engine = _load_reasoning_engine(settings)
    try:
        console.print(engine.ctem(cve_id))
    finally:
        engine.close()


@app.command()
def build() -> None:
    """Fetch sources and build knowledge-bundle.json + quality-report.json."""
    settings = get_settings()
    settings.ensure_dirs()
    bundle, quality = run_build(settings)
    settings.bundle_path.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    settings.quality_report_path.write_text(quality.model_dump_json(indent=2), encoding="utf-8")
    console.print(
        f"[green]Wrote {settings.bundle_path}[/green] "
        f"({len(bundle.nodes)} nodes, {len(bundle.edges)} edges, {len(bundle.routes)} routes)"
    )
    console.print(f"[green]Wrote {settings.quality_report_path}[/green]")
    if quality.warnings:
        console.print(f"[yellow]{len(quality.warnings)} warning(s) — see quality-report.json[/yellow]")
    if quality.fatal_errors:
        for err in quality.fatal_errors:
            console.print(f"[red]FATAL: {err}[/red]")
        raise typer.Exit(code=1)


@app.command()
def validate() -> None:
    """Validate the bundle structurally and report quality. Exits non-zero on fatal errors."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    errors = validate_structure(bundle)
    if errors:
        for err in errors:
            console.print(f"[red]FATAL: {err}[/red]")
        raise typer.Exit(code=1)
    console.print("[green]Bundle is structurally valid.[/green]")

    warnings = bundle.quality.get("warnings", [])
    if warnings:
        console.print(f"[yellow]{len(warnings)} quality warning(s):[/yellow]")
        for w in warnings:
            console.print(f"  - {w.get('code')}: {w.get('message')}")
    else:
        console.print("[green]No quality warnings.[/green]")


@app.command()
def serve() -> None:
    """Serve the static SPA (web/dist if built) and the bundle (data/dist) over HTTP."""
    import functools
    import http.server

    settings = get_settings()
    root = Path("web/dist") if Path("web/dist").is_dir() else settings.dist_dir
    if not root.is_dir():
        console.print(f"[red]Nothing to serve: {root} does not exist. Run `CVEzD3FEND build` first.[/red]")
        raise typer.Exit(code=1)

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    httpd = http.server.ThreadingHTTPServer((settings.api_host, settings.serve_port), handler)
    console.print(f"Serving {root} at http://{settings.api_host}:{settings.serve_port} (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


@app.command()
def route(ref: str = typer.Argument(..., help="Route id or CVE id")) -> None:
    """Print the top route for a CVE id (or a specific route id) to the console."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    matched = _resolve_route(bundle, ref)
    if matched is None:
        console.print(f"[red]No route found for '{ref}'[/red]")
        raise typer.Exit(code=1)
    console.print(markdown.render_route_markdown(bundle, matched))


@app.command()
def search(
    query: str = typer.Argument(..., help="Free-text query, node id, or alias"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """Search nodes by id, alias, or text index."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    results = _search_nodes(bundle, query, limit)
    if not results:
        console.print(f"[yellow]No matches for '{query}'[/yellow]")
        raise typer.Exit(code=1)

    table = Table("id", "type", "name", "confidence", "canonical")
    for node in results:
        table.add_row(node.id, node.type.value, node.name, f"{node.confidence:.2f}", str(node.canonical))
    console.print(table)


# ---------------------------------------------------------------------------
# export subcommands
# ---------------------------------------------------------------------------


@export_app.command("route")
def export_route(
    ref: str = typer.Argument(..., help="Route id or CVE id"),
    format: str = FormatOption,
    output: Optional[Path] = OutputOption,
) -> None:
    """Export a route as md|mermaid|json|csv."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    matched = _resolve_route(bundle, ref)
    if matched is None:
        console.print(f"[red]No route found for '{ref}'[/red]")
        raise typer.Exit(code=1)

    if format == "md":
        content = markdown.render_route_markdown(bundle, matched)
    elif format == "mermaid":
        content = mermaid.render_route_mermaid(bundle, matched)
    elif format == "json":
        content = json.dumps(json_export.export_json(matched), indent=2)
    elif format == "csv":
        content = csv_export.routes_csv([matched])
    elif format == "stix":
        from CVEzD3FEND.export.stix import export_stix

        export_stix()
        return
    else:
        console.print(f"[red]Unknown format '{format}' (expected md|mermaid|json|csv|stix)[/red]")
        raise typer.Exit(code=1)

    _write_output(content, output)


@export_app.command("coverage")
def export_coverage(
    format: str = typer.Option("json", "--format", "-f", help="Output format"),
    output: Optional[Path] = OutputOption,
) -> None:
    """Export the coverage table as json|csv."""
    settings = get_settings()
    bundle = _load_bundle(settings)

    if format == "json":
        content = json.dumps(json_export.export_json(bundle.coverage), indent=2)
    elif format == "csv":
        content = csv_export.coverage_csv(bundle.coverage)
    else:
        console.print(f"[red]Unknown format '{format}' (expected json|csv)[/red]")
        raise typer.Exit(code=1)

    _write_output(content, output)


@export_app.command("soc-action-pack")
def export_soc_action_pack(
    ref: str = typer.Argument(..., help="ATT&CK technique id, route id, or CVE id"),
    format: str = FormatOption,
    output: Optional[Path] = OutputOption,
) -> None:
    """Export a SOC Action Pack as md|json."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    attack_id = _resolve_attack_id(bundle, ref)
    if attack_id is None:
        console.print(f"[red]Could not resolve '{ref}' to an ATT&CK technique[/red]")
        raise typer.Exit(code=1)

    pack = build_soc_action_pack(bundle, attack_id)
    if format == "md":
        content = markdown.render_soc_action_pack_markdown(bundle, pack)
    elif format == "json":
        content = json.dumps(json_export.export_json(pack), indent=2)
    else:
        console.print(f"[red]Unknown format '{format}' (expected md|json)[/red]")
        raise typer.Exit(code=1)

    _write_output(content, output)


# ---------------------------------------------------------------------------
# ai subcommands
# ---------------------------------------------------------------------------


@ai_app.command("generate-candidates")
def ai_generate_candidates(
    target: Optional[str] = typer.Option(None, "--target", help="Reserved for future scoping; currently scans all open gaps"),
    limit: int = typer.Option(10, "--limit", help="Max new candidates to generate"),
) -> None:
    """Generate AI candidates by analogy over open coverage gaps (AI_ASSISTANCE_CONTRACT)."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    if target:
        console.print(f"[dim]--target {target} noted; scanning all open 'attack_without_defend' gaps.[/dim]")
    try:
        new_candidates = ai_candidates.generate_candidates(bundle, settings, limit=limit)
    except Exception as exc:  # provider/network errors surface loudly
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    console.print(f"Generated {len(new_candidates)} new candidate(s) -> {settings.ai_candidates_path}")
    for c in new_candidates:
        console.print(f"  {c.candidate_id}  confidence={c.confidence:.2f}  proposed_edges={len(c.proposed_edges)}")


@ai_app.command("validate-candidates")
def ai_validate_candidates() -> None:
    """Run deterministic structural validation on all pending candidates."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    pending = ai_candidates.load_candidates(settings)
    if not pending:
        console.print("No candidates in queue.")
        return

    updated = ai_candidates.validate_candidates(bundle, pending)
    ai_candidates.save_candidates(settings, updated)

    n_validated = sum(1 for c in updated if c.final_status == "validated_candidate")
    n_rejected = sum(1 for c in updated if c.validation_status == "rejected")
    console.print(f"validated={n_validated} rejected={n_rejected} total={len(updated)}")
    for c in updated:
        if c.validation_errors:
            console.print(f"  [red]{c.candidate_id}: {'; '.join(c.validation_errors)}[/red]")


@ai_app.command("list-candidates")
def ai_list_candidates(
    status: Optional[str] = typer.Option(None, "--status", help="Filter by final_status"),
) -> None:
    """List candidates in the review queue."""
    settings = get_settings()
    queue = ai_candidates.load_candidates(settings)
    if status:
        queue = [c for c in queue if c.final_status == status]
    if not queue:
        console.print("No candidates in queue.")
        return

    table = Table("candidate_id", "provider", "confidence", "validation_status", "final_status")
    for c in queue:
        table.add_row(c.candidate_id, c.provider, f"{c.confidence:.2f}", c.validation_status, c.final_status)
    console.print(table)


@ai_app.command("promote-candidate")
def ai_promote_candidate(
    candidate_id: str = typer.Argument(...),
    reviewer: str = typer.Option(..., "--reviewer", help="Human reviewer name (required)"),
) -> None:
    """Promote a validated_candidate to canonical, writing data/dist/promoted-edges.json."""
    settings = get_settings()
    queue = ai_candidates.load_candidates(settings)
    try:
        promoted, updated = ai_candidates.promote_candidate(settings, queue, candidate_id, reviewer)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    ai_candidates.save_candidates(settings, updated)
    console.print(
        f"[green]Promoted {promoted.candidate_id} -> {settings.promoted_edges_path} "
        f"(reviewer={reviewer})[/green]"
    )


@ai_app.command("reject-candidate")
def ai_reject_candidate(
    candidate_id: str = typer.Argument(...),
    reviewer: str = typer.Option(..., "--reviewer", help="Human reviewer name (required)"),
) -> None:
    """Reject a candidate, recording the reviewer."""
    settings = get_settings()
    queue = ai_candidates.load_candidates(settings)
    try:
        updated = ai_candidates.reject_candidate(queue, candidate_id, reviewer)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    ai_candidates.save_candidates(settings, updated)
    console.print(f"[green]Rejected {candidate_id} (reviewer={reviewer})[/green]")


@ai_app.command("explain-route")
def ai_explain_route(route_id: str = typer.Argument(...)) -> None:
    """Print a grounded explanation of a route (template-only unless AI is enabled)."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    try:
        result = ai_explain.explain_route(bundle, settings, route_id)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    console.print(result["text"])


@ai_app.command("hunt-hypothesis")
def ai_hunt_hypothesis(attack_id: str = typer.Argument(...)) -> None:
    """Print a threat hunting hypothesis for an ATT&CK technique."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    try:
        result = ai_explain.generate_hunt_hypothesis(bundle, settings, attack_id)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    console.print(result["text"])


@ai_app.command("detection-brief")
def ai_detection_brief(attack_id: str = typer.Argument(...)) -> None:
    """Print a detection brief for an ATT&CK technique."""
    settings = get_settings()
    bundle = _load_bundle(settings)
    try:
        result = ai_explain.generate_detection_brief(bundle, settings, attack_id)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    console.print(result["text"])


# ---------------------------------------------------------------------------
# Optional sidecars
# ---------------------------------------------------------------------------


@app.command()
def api() -> None:
    """Run the optional FastAPI sidecar (requires `pip install .[api]`)."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]FastAPI/uvicorn not installed. Run `pip install .[api]`.[/red]")
        raise typer.Exit(code=1)

    settings = get_settings()
    uvicorn.run("CVEzD3FEND.api.app:create_app", factory=True, host=settings.api_host, port=settings.api_port)


@app.command()
def mcp() -> None:
    """Run the optional MCP stdio server (requires `pip install .[mcp]`)."""
    try:
        from CVEzD3FEND.mcp.server import run
    except ImportError as exc:
        console.print(f"[red]MCP SDK not installed. Run `pip install .[mcp]`. ({exc})[/red]")
        raise typer.Exit(code=1)
    run()


if __name__ == "__main__":
    app()
