import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from time import perf_counter
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.test_heldout_correlation_readonly import CASES, load_case
from evaluation.baselines import BaselineRunner

WINDOW = 5.0

ABLATIONS = {
    "Full Evidence": None,
    "Without Procmon": "procmon",
    "Without Sysmon": "sysmon",
    "Without Wireshark": "wireshark",
    "Without Registry": "registry"
}


def get_artifact(event):
    return Path(event.evidence_file or "").name.lower()


def filter_events(events, removed_source):
    if removed_source is None:
        return list(events)

    filtered = []

    for event in events:
        artifact = get_artifact(event)

        if removed_source == "procmon":
            if artifact == "procmon_events.csv":
                continue

        elif removed_source == "sysmon":
            if artifact == "sysmon_events.xml":
                continue

        elif removed_source == "wireshark":
            if artifact == "wireshark_packets.csv":
                continue

        elif removed_source == "registry":
            if event.source == "registry":
                continue

        filtered.append(event)

    return filtered


def evaluate_case(case_id):
    events, expected = load_case(case_id)

    labeled_event_ids = {
        event_id
        for relationship in expected
        for event_id in relationship[:2]
    }

    print("\n" + "=" * 85)
    print("CASE:", case_id)
    print("Original events:", len(events))
    print("Expected relationships:", len(expected))
    print("=" * 85)

    results = []

    for ablation_name, removed_source in ABLATIONS.items():
        filtered_events = filter_events(events, removed_source)

        start = perf_counter()

        _, predicted_relationships, _ = (
            BaselineRunner.run_method_4_proposed_graph(
                filtered_events,
                case_id,
                temporal_window=WINDOW
            )
        )

        runtime = perf_counter() - start

        predicted_set = {
            (item[0], item[1], item[2])
            for item in predicted_relationships
            if item[0] in labeled_event_ids
            and item[1] in labeled_event_ids
        }

        matched = predicted_set & expected
        missing = expected - predicted_set
        unreviewed = predicted_set - expected

        recall = (
            len(matched) / len(expected)
            if expected else None
        )

        source_counts = dict(
            Counter(event.source for event in filtered_events)
        )

        result = {
            "ablation": ablation_name,
            "removed_source": removed_source,
            "remaining_event_count": len(filtered_events),
            "remaining_source_counts": source_counts,
            "runtime_seconds": round(runtime, 6),
            "predicted_relationship_count": len(predicted_set),
            "matched_relationship_count": len(matched),
            "missing_relationship_count": len(missing),
            "unreviewed_relationship_count": len(unreviewed),
            "expected_link_recall": (
                round(recall, 6) if recall is not None else None
            ),
            "missing_relationships": [
                list(item) for item in sorted(missing)
            ],
            "unreviewed_relationships": [
                list(item) for item in sorted(unreviewed)
            ]
        }

        results.append(result)

        print(f"\n{ablation_name}")
        print("  Remaining events:", len(filtered_events))
        print("  Source counts:", source_counts)
        print("  Runtime:", f"{runtime:.6f} seconds")
        print("  Matched:", len(matched))
        print("  Missing:", len(missing))
        print("  Unreviewed:", len(unreviewed))
        print(
            "  Expected-link recall:",
            f"{recall:.2%}" if recall is not None else "N/A"
        )

    return {
        "case_id": case_id,
        "original_event_count": len(events),
        "expected_relationship_count": len(expected),
        "results": results
    }


def summarize(case_results):
    summaries = []

    for ablation_name in ABLATIONS:
        matched_total = 0
        expected_total = 0
        recalls = []
        runtimes = []

        for case in case_results:
            result = next(
                item for item in case["results"]
                if item["ablation"] == ablation_name
            )

            matched_total += result["matched_relationship_count"]
            expected_total += case["expected_relationship_count"]
            runtimes.append(result["runtime_seconds"])

            if result["expected_link_recall"] is not None:
                recalls.append(result["expected_link_recall"])

        summaries.append({
            "ablation": ablation_name,
            "matched_relationships": matched_total,
            "expected_relationships": expected_total,
            "micro_recall": (
                round(matched_total / expected_total, 6)
                if expected_total else None
            ),
            "macro_recall": (
                round(sum(recalls) / len(recalls), 6)
                if recalls else None
            ),
            "mean_runtime_seconds": (
                round(sum(runtimes) / len(runtimes), 6)
                if runtimes else None
            )
        })

    return summaries


def main():
    print("=" * 85)
    print("U-15 EXP-06: HELD-OUT ABLATION STUDY")
    print("READ-ONLY EXPERIMENT")
    print("=" * 85)

    case_results = [
        evaluate_case(case_id)
        for case_id in CASES
    ]

    summaries = summarize(case_results)

    report = {
        "experiment": "EXP-06 Held-Out Ablation Study",
        "project": "U-15 Cross-Artifact Incident Reconstruction",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_type": "Synthetic held-out validation",
        "cases": CASES,
        "temporal_window_seconds": WINDOW,
        "method": "Proposed provenance graph",
        "ablation_definitions": {
            "Without Procmon": "Removes events from procmon_events.csv",
            "Without Sysmon": "Removes events from sysmon_events.xml",
            "Without Wireshark": "Removes events from wireshark_packets.csv",
            "Without Registry": "Removes all events with source registry"
        },
        "evaluation_scope": (
            "Exact expected event-relationship matches, scoped to event "
            "endpoints appearing in the original expected relationships."
        ),
        "limitations": [
            "All held-out cases are synthetic.",
            "Registry evidence is absent in the standalone registry snapshot "
            "for CASE-21 and CASE-22.",
            "Procmon also contributes Registry-source observations.",
            "Unreviewed relationships are not confirmed false positives.",
            "Precision, F1 and false-positive rate are not calculated.",
            "Results measure this implementation on these three cases only."
        ],
        "case_results": case_results,
        "aggregate_results": summaries,
        "database_writes": False,
        "ground_truth_modifications": False,
        "evidence_ingestion": False
    }

    output_dir = ROOT / "output" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "EXP-06_heldout_ablation_study.json"

    output_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 85)
    print("EXP-06 AGGREGATE RESULTS")
    print("=" * 85)

    for result in summaries:
        print("\n", result["ablation"])
        print(
            "  Matched:",
            f'{result["matched_relationships"]}/'
            f'{result["expected_relationships"]}'
        )
        print(
            "  Micro recall:",
            f'{result["micro_recall"]:.2%}'
            if result["micro_recall"] is not None else "N/A"
        )
        print(
            "  Macro recall:",
            f'{result["macro_recall"]:.2%}'
            if result["macro_recall"] is not None else "N/A"
        )
        print(
            "  Mean runtime:",
            result["mean_runtime_seconds"]
        )

    print("\nREPORT:", output_file)
    print("DATABASE WRITES: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")


if __name__ == "__main__":
    main()
