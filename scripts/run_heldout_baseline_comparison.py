
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.test_heldout_correlation_readonly import CASES, load_case
from evaluation.baselines import BaselineRunner


METHODS = [
    (
        "Baseline 1: Process Only",
        BaselineRunner.run_method_1_process_only
    ),
    (
        "Baseline 2: Process + Registry",
        BaselineRunner.run_baseline_2_proc_and_reg
    ),
    (
        "Baseline 3: All Sources Rule-Based",
        BaselineRunner.run_method_3_rule_based
    ),
    (
        "Proposed: Provenance Graph",
        BaselineRunner.run_method_4_proposed_graph
    ),
]

WINDOW = 5.0


def evaluate_case(case_id):
    events, expected = load_case(case_id)

    labeled_event_ids = {
        event_id
        for relationship in expected
        for event_id in relationship[:2]
    }

    results = []

    print(f"\n{'=' * 85}")
    print(f"CASE: {case_id}")
    print(f"{'=' * 85}")
    print(f"Events: {len(events)}")
    print(f"Labeled relationship endpoints: {len(labeled_event_ids)}")
    print(f"Expected relationships: {len(expected)}")

    for method_name, runner in METHODS:
        start = perf_counter()

        _, predicted_relationships, _ = runner(
            events,
            case_id,
            temporal_window=WINDOW
        )

        runtime = perf_counter() - start

        predicted_set = {
            (
                relationship[0],
                relationship[1],
                relationship[2]
            )
            for relationship in predicted_relationships
            if relationship[0] in labeled_event_ids
            and relationship[1] in labeled_event_ids
        }

        matched = predicted_set & expected
        missing = expected - predicted_set
        unreviewed = predicted_set - expected

        recall = (
            len(matched) / len(expected)
            if expected else None
        )

        result = {
            "method": method_name,
            "runtime_seconds": round(runtime, 6),
            "total_predicted_relationships": len(predicted_relationships),
            "scoped_predicted_relationships": len(predicted_set),
            "expected_relationships": len(expected),
            "matched_relationships": len(matched),
            "missing_relationships": [
                list(item) for item in sorted(missing)
            ],
            "unreviewed_relationships": [
                list(item) for item in sorted(unreviewed)
            ],
            "expected_link_recall": round(recall, 6) if recall is not None else None
        }

        results.append(result)

        print(f"\n{method_name}")
        print(f"  Runtime: {runtime:.6f} seconds")
        print(f"  Total predictions: {len(predicted_relationships)}")
        print(f"  Scoped predictions: {len(predicted_set)}")
        print(f"  Matched: {len(matched)}")
        print(f"  Missing: {len(missing)}")
        print(f"  Unreviewed: {len(unreviewed)}")
        print(
            f"  Expected-link recall: "
            f"{recall:.2%}" if recall is not None else "  Recall: N/A"
        )

    return {
        "case_id": case_id,
        "event_count": len(events),
        "labeled_event_count": len(labeled_event_ids),
        "expected_relationship_count": len(expected),
        "methods": results
    }


def main():
    print("=" * 85)
    print("U-15 EXP-04: HELD-OUT BASELINE COMPARISON")
    print("READ-ONLY EXPERIMENT")
    print("=" * 85)

    case_results = [
        evaluate_case(case_id)
        for case_id in CASES
    ]

    method_summaries = []

    for method_name, _ in METHODS:
        matched_total = 0
        expected_total = 0
        recalls = []
        runtimes = []

        for case in case_results:
            method = next(
                item for item in case["methods"]
                if item["method"] == method_name
            )

            matched_total += method["matched_relationships"]
            expected_total += method["expected_relationships"]
            runtimes.append(method["runtime_seconds"])

            if method["expected_link_recall"] is not None:
                recalls.append(method["expected_link_recall"])

        micro_recall = (
            matched_total / expected_total
            if expected_total else None
        )

        macro_recall = (
            sum(recalls) / len(recalls)
            if recalls else None
        )

        method_summaries.append({
            "method": method_name,
            "total_expected_relationships": expected_total,
            "total_matched_relationships": matched_total,
            "micro_expected_link_recall": (
                round(micro_recall, 6)
                if micro_recall is not None else None
            ),
            "macro_expected_link_recall": (
                round(macro_recall, 6)
                if macro_recall is not None else None
            ),
            "mean_runtime_seconds": (
                round(sum(runtimes) / len(runtimes), 6)
                if runtimes else None
            )
        })

    report = {
        "experiment": "EXP-04 Held-Out Baseline Comparison",
        "project": "U-15 Cross-Artifact Incident Reconstruction",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_type": "Synthetic held-out validation",
        "cases": CASES,
        "temporal_window_seconds": WINDOW,
        "evaluation_scope": (
            "Exact expected event-relationship matches. Predictions are "
            "scoped to endpoints appearing in independently documented "
            "expected relationships."
        ),
        "limitations": [
            "The held-out cases are synthetic, not real-world captures.",
            "Unreviewed relationships are not classified as false positives.",
            "Precision, F1 and false-positive rate are not calculated.",
            "Event detection metrics are not calculated.",
            "Baseline 3 and Proposed share the underlying correlation engine; "
            "their comparison measures graph-based expansion."
        ],
        "case_results": case_results,
        "method_summaries": method_summaries,
        "database_writes": False,
        "ground_truth_modifications": False,
        "evidence_ingestion": False
    }

    output_dir = ROOT / "output" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "EXP-04_heldout_baseline_comparison.json"

    output_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 85)
    print("EXP-04 AGGREGATE RESULTS")
    print("=" * 85)

    for result in method_summaries:
        print(f"\n{result['method']}")
        print(
            f"  Matched: "
            f"{result['total_matched_relationships']}/"
            f"{result['total_expected_relationships']}"
        )
        print(
            f"  Micro recall: "
            f"{result['micro_expected_link_recall']:.2%}"
            if result["micro_expected_link_recall"] is not None
            else "  Micro recall: N/A"
        )
        print(
            f"  Macro recall: "
            f"{result['macro_expected_link_recall']:.2%}"
            if result["macro_expected_link_recall"] is not None
            else "  Macro recall: N/A"
        )

    print("\nREPORT:", output_file)
    print("DATABASE WRITES: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")


if __name__ == "__main__":
    main()