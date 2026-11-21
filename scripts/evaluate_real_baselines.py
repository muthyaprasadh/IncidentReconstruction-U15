"""Compare real-case relationship predictions on the explicitly labeled subgraph."""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.models import NormalizedEvent
import database.db as db
from config.settings import logger
from evaluation.baselines import BaselineRunner
from evaluation.metrics import ForensicEvaluator
from experiments.ground_truth_manager import GroundTruthManager


def evaluate_case(case_id: str, temporal_window: float = 5.0) -> Dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", case_id):
        raise ValueError("case_id may contain only letters, digits, dot, underscore, and hyphen")
    if temporal_window <= 0:
        raise ValueError("temporal_window must be greater than zero")

    ground_truth = GroundTruthManager.load_ground_truth(case_id)
    if not ground_truth:
        raise ValueError(f"No ground truth found for case {case_id}")
    if ground_truth.get("dataset_type") not in ("real_world", "held_out_real_world"):
        raise ValueError(f"Case {case_id} is not labeled as real-world evidence")
    if ground_truth.get("independent_of_correlation_engine") is not True:
        raise ValueError(f"Case {case_id} lacks the ground-truth independence flag")

    event_records = db.get_events(case_id)
    if not event_records:
        raise ValueError(f"No normalized events found for case {case_id}")
    events = [
        NormalizedEvent(**{
            key: value
            for key, value in record.items()
            if key in NormalizedEvent.__annotations__
        })
        for record in event_records
    ]

    incident_ids = set(ground_truth.get("incident_event_ids", []))
    all_event_ids = {event.event_id for event in events}
    missing_ids = sorted(incident_ids - all_event_ids)
    if missing_ids:
        raise ValueError(
            f"Ground-truth events missing from normalized case {case_id}: {missing_ids[:10]}"
        )
    expected = [tuple(item) for item in ground_truth.get("expected_relationships", [])]

    methods = [
        ("Baseline 1: Process-only", BaselineRunner.run_method_1_process_only),
        ("Baseline 2: Process + Registry", BaselineRunner.run_baseline_2_proc_and_reg),
        ("Baseline 3: Conventional all-source", BaselineRunner.run_method_3_rule_based),
        ("Proposed: Provenance graph", BaselineRunner.run_method_4_proposed_graph),
    ]
    results = []
    for name, run_method in methods:
        started = perf_counter()
        _, predicted_relationships, _ = run_method(
            events,
            case_id,
            temporal_window=temporal_window,
        )
        scoped_predictions = sorted({
            (
                relationship[0],
                relationship[1],
                relationship[2],
            )
            for relationship in predicted_relationships
            if relationship[0] in incident_ids and relationship[1] in incident_ids
        })
        coverage = ForensicEvaluator.calculate_labeled_relationship_coverage(
            scoped_predictions,
            expected,
            incident_ids,
        )
        results.append({
            "method": name,
            "runtime_seconds": round(perf_counter() - started, 3),
            "total_predicted_relationships": len(predicted_relationships),
            **coverage,
        })

    return {
        "case_id": case_id,
        "dataset_type": ground_truth["dataset_type"],
        "evaluation_type": "exact event-relationship comparison on annotated event subgraph",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "temporal_window_seconds": temporal_window,
        "normalized_event_count": len(events),
        "incident_event_count": len(incident_ids),
        "expected_relationship_count": len(expected),
        "scored_scope": (
            "Exact event-ID relationship matches are counted only when both endpoints are labeled. "
            "Unmatched predictions are reported as unreviewed, not false positives, because the "
            "expected edge list may not enumerate every valid evidence-source pairing."
        ),
        "not_computed": [
            "Event detection precision/recall/F1 and false-positive rate: the full case is not exhaustively event-labeled.",
            "Timeline accuracy: the ground-truth chronology is partial.",
            "Held-out performance: real-case correlations were inspected during development.",
            "Relationship precision/F1: negative edge labels and source-equivalence mappings are not exhaustive.",
        ],
        "methods": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_id", help="Real-world case ID with validated independent ground truth")
    parser.add_argument("--window", type=float, default=5.0, help="Correlation window in seconds")
    args = parser.parse_args()

    logger.setLevel(logging.ERROR)
    for handler in logger.handlers:
        handler.setLevel(logging.ERROR)

    report = evaluate_case(args.case_id, args.window)
    output = ROOT / "output" / "reports" / f"{args.case_id}_baseline_comparison.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "report": str(output),
        "case_id": args.case_id,
        "methods": [
            {
                "method": item["method"],
                "expected_link_coverage": item["expected_link_coverage"],
                "exact_matches": item["exact_expected_relationship_matches"],
                "unreviewed_scoped_relationships": len(item["unreviewed_scoped_relationships"]),
            }
            for item in report["methods"]
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
