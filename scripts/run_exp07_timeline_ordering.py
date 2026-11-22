import json
from pathlib import Path

from config.settings import BASE_DIR
from scripts.test_heldout_correlation_readonly import CASES, load_case
from reconstruction.timeline_generator import TimelineGenerator
from correlation.correlation_engine import CorrelationEngine
from evaluation.metrics import ForensicEvaluator


def main():
    results = []

    for case_id in CASES:
        events, expected_relationships = load_case(case_id)

        manifest_path = (
            BASE_DIR
            / "data"
            / "experiment_manifests"
            / f"{case_id}_manifest.json"
        )

        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        expected_order = manifest.get("expected_chronology", [])

        engine = CorrelationEngine(case_id=case_id)
        relationships = engine.run(events, save_to_db=False)

        timeline = TimelineGenerator(
            events,
            relationships
        ).generate_timeline()

        predicted_order = [
            item["event_id"] for item in timeline
        ]

        accuracy = ForensicEvaluator.calculate_timeline_ordering_accuracy(
            predicted_order,
            expected_order
        )

        expected_set = set(expected_order)
        predicted_set = set(predicted_order)

        coverage = (
            len(expected_set & predicted_set) / len(expected_set)
            if expected_set else 0.0
        )

        result = {
            "case_id": case_id,
            "expected_events": len(expected_order),
            "timeline_events": len(predicted_order),
            "chronology_coverage": round(coverage, 4),
            "normalized_kendall_tau": accuracy,
            "ordering_method": "Timestamp-sorted timeline"
        }

        results.append(result)

        print("\n" + "=" * 65)
        print(case_id)
        print("=" * 65)
        print(json.dumps(result, indent=2))

    report = {
        "experiment": "EXP-07",
        "title": "Held-Out Timeline Ordering Evaluation",
        "dataset_type": "Synthetic held-out cases",
        "ordering_method": "Timestamp-sorted timeline",
        "results": results,
        "database_writes": "NONE",
        "ground_truth_modifications": "NONE",
        "evidence_ingestion": "NONE"
    }

    output_dir = BASE_DIR / "output" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "EXP-07_timeline_ordering.json"

    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nREPORT:", output_path)
    print("DATABASE WRITES: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")


if __name__ == "__main__":
    main()