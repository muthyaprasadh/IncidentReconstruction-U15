import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.test_heldout_correlation_readonly import CASES, load_case
from correlation.correlation_engine import CorrelationEngine
from correlation.process_correlation import ProcessLifetimeTracker, event_process_guid

OUTPUT_DIR = Path("output/reports")
JSON_PATH = OUTPUT_DIR / "EXP-09_process_instance_equivalent_evaluation.json"
MD_PATH = OUTPUT_DIR / "EXP-09_process_instance_equivalent_evaluation.md"
WINDOW = 5.0


def canonicalize(event_id, event_map, tracker):
    event = event_map.get(event_id)

    if event is None or event.source != "process" or event.pid is None:
        return event_id

    epoch = tracker.get_active_epoch(
        event.pid,
        event.timestamp,
        process_guid=event_process_guid(event)
    )

    if epoch is None:
        return event_id

    return epoch.start_event_id


def normalize_relationship(relationship, event_map, tracker):
    source, target, relation_type = relationship

    return (
        canonicalize(source, event_map, tracker),
        canonicalize(target, event_map, tracker),
        relation_type
    )


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if JSON_PATH.exists() or MD_PATH.exists():
        raise FileExistsError(
            "EXP-09 report already exists. No existing report was overwritten."
        )

    case_results = []
    total_expected = 0
    total_strict = 0
    total_equivalent = 0

    for case_id in CASES:
        events, expected = load_case(case_id)
        event_map = {event.event_id: event for event in events}

        tracker = ProcessLifetimeTracker()
        tracker.register_events(events)

        predictions = CorrelationEngine(
            case_id=case_id,
            temporal_window=WINDOW
        ).run(events, save_to_db=False)

        predicted = {
            (
                relationship.source_event_id,
                relationship.target_event_id,
                relationship.relationship_type
            )
            for relationship in predictions
        }

        strict_matches = expected & predicted

        normalized_expected = {
            normalize_relationship(item, event_map, tracker)
            for item in expected
        }

        normalized_predicted = {
            normalize_relationship(item, event_map, tracker)
            for item in predicted
        }

        equivalent_matches = normalized_expected & normalized_predicted

        prediction_lookup = {}

        for item in predicted:
            normalized = normalize_relationship(item, event_map, tracker)
            prediction_lookup.setdefault(normalized, []).append(item)

        matched_details = []

        for expected_link in sorted(expected):
            normalized_link = normalize_relationship(
                expected_link, event_map, tracker
            )

            matching_predictions = prediction_lookup.get(
                normalized_link, []
            )

            matched_details.append({
                "expected_relationship": list(expected_link),
                "canonical_relationship": list(normalized_link),
                "strict_event_id_match": expected_link in predicted,
                "process_instance_equivalent_match": bool(matching_predictions),
                "matching_predicted_relationships": [
                    list(item) for item in matching_predictions
                ]
            })

        result = {
            "case_id": case_id,
            "event_count": len(events),
            "expected_relationships": len(expected),
            "predicted_relationships": len(predicted),
            "strict_event_id_matches": len(strict_matches),
            "strict_event_id_recall": (
                round(len(strict_matches) / len(expected), 6)
                if expected else None
            ),
            "process_instance_equivalent_matches": len(equivalent_matches),
            "process_instance_equivalent_recall": (
                round(len(equivalent_matches) / len(normalized_expected), 6)
                if normalized_expected else None
            ),
            "relationship_details": matched_details
        }

        case_results.append(result)

        total_expected += len(expected)
        total_strict += len(strict_matches)
        total_equivalent += len(equivalent_matches)

        print("\nCASE:", case_id)
        print("Expected:", len(expected))
        print("Strict matches:", len(strict_matches))
        print("Equivalent matches:", len(equivalent_matches))

    report = {
        "experiment": "EXP-09",
        "title": "Process-Instance-Equivalent Held-Out Evaluation",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "temporal_window_seconds": WINDOW,
        "evaluation_method": {
            "strict": "Exact source event ID, target event ID and relationship type.",
            "equivalent": (
                "Process-source event IDs are mapped to their validated "
                "process epoch start event ID. Relationship direction and "
                "relationship type are preserved."
            )
        },
        "limitations": [
            "Held-out cases are synthetic.",
            "The evaluation covers annotated expected relationships only.",
            "Unreviewed predictions are not classified as false positives.",
            "This experiment does not establish precision, F1 or false-positive rate.",
            "Equivalent matching depends on process-lifetime attribution.",
            "Equivalent recall does not replace strict event-level recall."
        ],
        "summary": {
            "cases": len(case_results),
            "expected_relationships": total_expected,
            "strict_event_id_matches": total_strict,
            "strict_event_id_recall": round(
                total_strict / total_expected, 6
            ) if total_expected else None,
            "process_instance_equivalent_matches": total_equivalent,
            "process_instance_equivalent_recall": round(
                total_equivalent / total_expected, 6
            ) if total_expected else None
        },
        "case_results": case_results,
        "integrity": {
            "database_writes": False,
            "ground_truth_modifications": False,
            "evidence_modifications": False,
            "existing_reports_overwritten": False
        }
    }

    with JSON_PATH.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    summary = report["summary"]

    lines = [
        "# EXP-09: Process-Instance-Equivalent Held-Out Evaluation",
        "",
        f"Generated (UTC): {report['generated_utc']}",
        "",
        "## Objective",
        "",
        "Evaluate held-out relationships using both strict event-ID matching "
        "and validated process-instance-equivalent matching.",
        "",
        "## Overall results",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Held-out cases | {summary['cases']} |",
        f"| Expected relationships | {summary['expected_relationships']} |",
        f"| Strict event-ID matches | {summary['strict_event_id_matches']} "
        f"/ {summary['expected_relationships']} |",
        f"| Strict event-level recall | "
        f"{summary['strict_event_id_recall']:.2%} |",
        f"| Equivalent matches | "
        f"{summary['process_instance_equivalent_matches']} "
        f"/ {summary['expected_relationships']} |",
        f"| Process-instance-equivalent recall | "
        f"{summary['process_instance_equivalent_recall']:.2%} |",
        "",
        "## Per-case results",
        "",
        "| Case | Expected | Strict matches | Equivalent matches |",
        "|---|---:|---:|---:|"
    ]

    for case in case_results:
        lines.append(
            f"| {case['case_id']} | {case['expected_relationships']} "
            f"| {case['strict_event_id_matches']} "
            f"| {case['process_instance_equivalent_matches']} |"
        )

    lines.extend([
        "",
        "## Evaluation methodology",
        "",
        "**Strict matching:** Requires exact source event ID, target event ID "
        "and relationship type.",
        "",
        "**Equivalent matching:** Maps process-source event IDs to the "
        "validated process epoch's start event ID. Relationship direction "
        "and type remain unchanged. Non-process events retain their original IDs.",
        "",
        "## Limitations",
        ""
    ])

    lines.extend(f"- {item}" for item in report["limitations"])

    lines.extend([
        "",
        "## Integrity",
        "",
        "- Database writes: None.",
        "- Ground-truth modifications: None.",
        "- Evidence modifications: None.",
        "- Existing reports overwritten: None.",
        "",
        "## Interpretation",
        "",
        "The equivalent score measures recovery of annotated relationships "
        "after accounting for different process-start event representations "
        "across telemetry sources. It must be reported alongside, not instead "
        "of, strict event-level recall.",
        ""
    ])

    with MD_PATH.open("x", encoding="utf-8") as file:
        file.write("\n".join(lines))

    print("\n" + "=" * 70)
    print("EXP-09 COMPLETED")
    print("Expected relationships:", total_expected)
    print("Strict matches:", total_strict)
    print("Equivalent matches:", total_equivalent)
    print("Strict recall:", f"{summary['strict_event_id_recall']:.2%}")
    print(
        "Equivalent recall:",
        f"{summary['process_instance_equivalent_recall']:.2%}"
    )
    print("\nJSON REPORT:", JSON_PATH)
    print("MARKDOWN REPORT:", MD_PATH)
    print("\nDATABASE WRITES: NONE")
    print("GROUND-TRUTH CHANGES: NONE")
    print("EVIDENCE CHANGES: NONE")


if __name__ == "__main__":
    main()
