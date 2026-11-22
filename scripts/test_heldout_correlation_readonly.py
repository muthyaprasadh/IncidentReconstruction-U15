import json
from pathlib import Path

from config.settings import BASE_DIR
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.sysmon_parser import SysmonParser
from parsers.network_parser import NetworkParser
from correlation.correlation_engine import CorrelationEngine


CASES = [
    "CASE-20-20_HELD_OUT_MIXED",
    "CASE-21-21_HELD_OUT_PID_REUSE",
    "CASE-22-22_HELD_OUT_MISSING_REG_NOISE",
]

PARSER_SPECS = [
    ("procmon_events.csv", ProcmonParser),
    ("registry_export.reg", RegistryParser),
    ("sysmon_events.xml", SysmonParser),
    ("wireshark_packets.csv", NetworkParser),
]

BASE_DATE = "2026-11-10"


def load_case(case_id):
    case_dir = BASE_DIR / "data" / "test_cases" / case_id

    manifest_path = (
        BASE_DIR
        / "data"
        / "experiment_manifests"
        / f"{case_id}_manifest.json"
    )

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    events = []

    for filename, parser_type in PARSER_SPECS:
        path = case_dir / filename

        if not path.is_file():
            raise FileNotFoundError(path)

        parser = parser_type(case_id)

        parsed = parser.parse_file(
            str(path),
            base_date=BASE_DATE
        )

        if parser.errors:
            raise RuntimeError(
                f"{case_id}/{filename}: {parser.errors}"
            )

        events.extend(parsed)

        print(
            f"  {filename}: {len(parsed)} events, "
            f"{len(parser.warnings)} warnings"
        )

    event_ids = {event.event_id for event in events}

    if len(event_ids) != len(events):
        raise RuntimeError(f"Duplicate event IDs in {case_id}")

    expected = {
        tuple(item)
        for item in manifest["expected_event_relationships"]
    }

    missing_ids = {
        event_id
        for relationship in expected
        for event_id in relationship[:2]
        if event_id not in event_ids
    }

    if missing_ids:
        raise RuntimeError(
            f"Expected event IDs missing in {case_id}: {missing_ids}"
        )

    return events, expected


def relationship_key(rel):
    return (
        rel.source_event_id,
        rel.target_event_id,
        rel.relationship_type
    )


def main():
    print("=" * 75)
    print("U-15 READ-ONLY HELD-OUT CORRELATION VALIDATION")
    print("=" * 75)

    total_expected = 0
    total_matched = 0
    total_predicted = 0

    for case_id in CASES:
        print("\n" + "-" * 75)
        print(case_id)
        print("-" * 75)

        events, expected = load_case(case_id)

        print(f"\nTotal events: {len(events)}")
        print(f"Expected relationships: {len(expected)}")

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=5.0
        )

        predicted_objects = engine.run(
            events,
            save_to_db=False
        )

        predicted = {
            relationship_key(rel)
            for rel in predicted_objects
        }

        matched = expected & predicted
        missing = expected - predicted
        unexpected = predicted - expected

        recall = (
            len(matched) / len(expected)
            if expected else None
        )

        total_expected += len(expected)
        total_matched += len(matched)
        total_predicted += len(predicted)

        print(f"\nPredicted relationships: {len(predicted)}")
        print(f"Matched expected: {len(matched)}")
        print(f"Missing expected: {len(missing)}")
        print(f"Unexpected/unreviewed: {len(unexpected)}")

        if recall is not None:
            print(f"Expected-link recall: {recall:.2%}")

        if missing:
            print("\nMISSING RELATIONSHIPS:")

            for relationship in sorted(missing):
                print(relationship)

        print("\nPREDICTED SPAWNED RELATIONSHIPS:")

        for rel in predicted_objects:
            if rel.relationship_type == "SPAWNED":
                print(
                    rel.source_event_id,
                    "->",
                    rel.target_event_id,
                    "|",
                    rel.correlation_method
                )

    print("\n" + "=" * 75)
    print("OVERALL RESULTS")
    print("=" * 75)

    print(f"Expected relationships: {total_expected}")
    print(f"Matched relationships: {total_matched}")
    print(f"Predicted relationships: {total_predicted}")

    if total_expected:
        print(
            f"Micro expected-link recall: "
            f"{total_matched / total_expected:.2%}"
        )

    print("\nDATABASE WRITE OPERATIONS: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")


if __name__ == "__main__":
    main()