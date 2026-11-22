import csv
import json
import sys
import time
from pathlib import Path
from dataclasses import asdict, is_dataclass

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import BASE_DIR, logger
from correlation.correlation_engine import CorrelationEngine
from graph.graph_builder import EvidenceGraphBuilder
from scripts.test_heldout_correlation_readonly import CASES, load_case


OUTPUT_DIR = PROJECT_ROOT / "output" / "reports"

JSON_REPORT = OUTPUT_DIR / "EXP-05_provenance_traceability_audit.json"
CSV_REPORT = OUTPUT_DIR / "EXP-05_provenance_traceability_summary.csv"


def object_to_dict(obj):
    if isinstance(obj, dict):
        return dict(obj)

    if hasattr(obj, "to_dict"):
        return obj.to_dict()

    if is_dataclass(obj):
        return asdict(obj)

    if hasattr(obj, "__dict__"):
        return vars(obj).copy()

    raise TypeError(f"Unsupported object type: {type(obj).__name__}")


def get_value(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def percentage(numerator, denominator):
    if denominator == 0:
        return 0.0

    return round((numerator / denominator) * 100, 2)


def audit_case(case_id):
    print("\n" + "=" * 85)
    print(f"EXP-05 PROVENANCE AUDIT: {case_id}")
    print("=" * 85)

    events, expected = load_case(case_id)

    print(f"Normalized events: {len(events)}")
    print(f"Expected relationships: {len(expected)}")

    if not events:
        raise RuntimeError(f"No normalized events loaded for {case_id}")

    engine = CorrelationEngine(case_id=case_id)

    start_time = time.perf_counter()

    relationships = engine.run(
        events,
        save_to_db=False
    )

    runtime = time.perf_counter() - start_time

    if relationships is None:
        relationships = []

    print(f"Predicted relationships: {len(relationships)}")
    print(f"Correlation runtime: {runtime:.6f} seconds")

    event_dicts = [
        object_to_dict(event)
        for event in events
    ]

    relationship_dicts = [
        object_to_dict(relationship)
        for relationship in relationships
    ]

    builder = EvidenceGraphBuilder(case_id=case_id)

    graph = builder.build_graph(
        event_dicts,
        relationship_dicts
    )

    event_nodes = {
        node_id: attributes
        for node_id, attributes in graph.nodes(data=True)
        if attributes.get("node_type") == "event"
    }

    total_events = len(events)
    total_relationships = len(relationships)
    total_event_nodes = len(event_nodes)

    event_reference_count = 0
    evidence_file_count = 0
    evidence_row_count = 0
    event_source_count = 0

    for event in events:
        evidence_file = get_value(event, "evidence_file", "")
        evidence_reference = get_value(event, "evidence_reference", "")
        source = get_value(event, "source", "")

        if evidence_file or evidence_reference:
            event_reference_count += 1

        if evidence_file:
            evidence_file_count += 1

        if evidence_reference:
            evidence_row_count += 1

        if source:
            event_source_count += 1

    relationship_metrics = {
        "correlation_method": 0,
        "supporting_identifiers": 0,
        "evidence_sources": 0,
        "explanation": 0,
        "confidence": 0,
        "relationship_category": 0,
        "both_endpoint_event_nodes": 0
    }

    for relationship in relationships:
        method = get_value(relationship, "correlation_method", "")
        identifiers = get_value(
            relationship,
            "supporting_identifiers",
            []
        )
        sources = get_value(
            relationship,
            "evidence_sources",
            []
        )
        explanation = get_value(relationship, "explanation", "")
        confidence = get_value(
            relationship,
            "confidence_score",
            None
        )
        category = get_value(
            relationship,
            "relationship_category",
            ""
        )

        source_id = get_value(
            relationship,
            "source_event_id",
            ""
        )
        target_id = get_value(
            relationship,
            "target_event_id",
            ""
        )

        if method:
            relationship_metrics["correlation_method"] += 1

        if identifiers:
            relationship_metrics["supporting_identifiers"] += 1

        if sources:
            relationship_metrics["evidence_sources"] += 1

        if explanation:
            relationship_metrics["explanation"] += 1

        if confidence is not None:
            relationship_metrics["confidence"] += 1

        if category:
            relationship_metrics["relationship_category"] += 1

        if source_id in event_nodes and target_id in event_nodes:
            relationship_metrics["both_endpoint_event_nodes"] += 1

    event_metrics = {
        "total_events": total_events,
        "graph_event_nodes": total_event_nodes,
        "events_with_evidence_reference": event_reference_count,
        "events_with_evidence_file": evidence_file_count,
        "events_with_evidence_row_reference": evidence_row_count,
        "events_with_source": event_source_count,
        "event_reference_coverage_percent": percentage(
            event_reference_count,
            total_events
        ),
        "evidence_file_coverage_percent": percentage(
            evidence_file_count,
            total_events
        ),
        "evidence_row_reference_coverage_percent": percentage(
            evidence_row_count,
            total_events
        ),
        "event_source_coverage_percent": percentage(
            event_source_count,
            total_events
        )
    }

    relationship_coverage = {
        metric: {
            "count": count,
            "total": total_relationships,
            "coverage_percent": percentage(
                count,
                total_relationships
            )
        }
        for metric, count in relationship_metrics.items()
    }

    result = {
        "case_id": case_id,
        "dataset_type": "held_out_synthetic",
        "runtime_seconds": round(runtime, 6),
        "expected_relationship_count": len(expected),
        "predicted_relationship_count": total_relationships,
        "event_metrics": event_metrics,
        "relationship_provenance_metrics": relationship_coverage,
        "limitations": [
            "This audit measures the presence of provenance fields, not their independent correctness.",
            "A populated evidence reference does not independently verify the original evidence file.",
            "The cases are held-out synthetic validation cases, not real-world incident captures.",
            "Coverage percentages do not establish correlation accuracy.",
            "Unreviewed relationships must not automatically be classified as false positives."
        ]
    }

    print("\nEVENT PROVENANCE")
    print("-" * 60)

    for metric, value in event_metrics.items():
        print(f"{metric}: {value}")

    print("\nRELATIONSHIP PROVENANCE")
    print("-" * 60)

    for metric, values in relationship_coverage.items():
        print(
            f"{metric}: "
            f"{values['count']}/{values['total']} "
            f"({values['coverage_percent']}%)"
        )

    return result


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 85)
    print("U-15 EXP-05: PROVENANCE TRACEABILITY AUDIT")
    print("=" * 85)

    results = []

    for case_id in CASES:
        result = audit_case(case_id)
        results.append(result)

    report = {
        "experiment": "EXP-05",
        "title": "Provenance Traceability Audit",
        "dataset_type": "Held-out synthetic validation",
        "cases": results,
        "database_writes": False,
        "ground_truth_modifications": False,
        "evidence_ingestion": False
    }

    JSON_REPORT.write_text(
        json.dumps(report, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

    csv_rows = []

    for result in results:
        row = {
            "case_id": result["case_id"],
            "runtime_seconds": result["runtime_seconds"],
            "expected_relationships": result["expected_relationship_count"],
            "predicted_relationships": result["predicted_relationship_count"]
        }

        row.update(result["event_metrics"])

        for metric, values in result[
            "relationship_provenance_metrics"
        ].items():
            row[f"{metric}_count"] = values["count"]
            row[f"{metric}_coverage_percent"] = values["coverage_percent"]

        csv_rows.append(row)

    if csv_rows:
        with CSV_REPORT.open(
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(csv_rows[0].keys())
            )
            writer.writeheader()
            writer.writerows(csv_rows)

    print("\n" + "=" * 85)
    print("EXP-05 COMPLETE")
    print("=" * 85)

    print(f"\nJSON report: {JSON_REPORT}")
    print(f"CSV report:  {CSV_REPORT}")

    print("\nDATABASE WRITES: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")


if __name__ == "__main__":
    main()