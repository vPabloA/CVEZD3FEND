"""CSV export for routes and coverage tables (EXPORT_CONTRACT §4)."""

from __future__ import annotations

import csv
import io

from CVEzD3FEND.models.bundle import Coverage, Route


def routes_csv(routes: list[Route]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["route_id", "start_node", "end_node", "path", "confidence", "coverage_status", "canonical", "inferred", "source_refs"]
    )
    for r in routes:
        writer.writerow(
            [
                r.route_id,
                r.start_node,
                r.end_node,
                "|".join(r.path),
                f"{r.confidence:.2f}",
                r.coverage_status,
                r.canonical,
                r.inferred,
                "|".join(r.source_refs),
            ]
        )
    return buf.getvalue()


def coverage_csv(coverage: Coverage) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["attack_technique", "defend_techniques", "controls", "detections", "coverage_status", "gap_reason", "confidence"]
    )
    for t in coverage.techniques:
        writer.writerow(
            [
                t.attack_technique,
                "|".join(t.defend_techniques),
                "|".join(t.controls),
                "|".join(t.detections),
                t.coverage_status,
                t.gap_reason or "",
                f"{t.confidence:.2f}",
            ]
        )
    return buf.getvalue()
