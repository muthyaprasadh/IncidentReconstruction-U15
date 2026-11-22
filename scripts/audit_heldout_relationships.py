from scripts.test_heldout_correlation_readonly import (
    CASES,
    load_case,
    relationship_key,
)
from correlation.correlation_engine import CorrelationEngine


def print_event_details(label, event):
    print(f"\n{label}")

    if event is None:
        print("Event not found")
        return

    print(f"Event ID: {event.event_id}")
    print(f"Timestamp: {event.timestamp}")
    print(f"Source: {event.source}")
    print(f"Event type: {event.event_type}")
    print(f"PID: {event.pid}")
    print(f"PPID: {event.ppid}")
    print(f"Process name: {event.process_name}")
    print(f"Process GUID: {event.process_guid}")
    print(f"Registry key: {event.registry_key}")
    print(f"Registry operation: {event.registry_operation}")
    print(f"Source IP: {event.src_ip}")
    print(f"Destination IP: {event.dst_ip}")
    print(f"Source port: {event.src_port}")
    print(f"Destination port: {event.dst_port}")
    print(f"Protocol: {event.protocol}")
    print(f"Evidence file: {event.evidence_file}")
    print(f"Evidence reference: {event.evidence_reference}")


def main():
    print("=" * 85)
    print("U-15 HELD-OUT RELATIONSHIP AUDIT")
    print("READ-ONLY - NO DATABASE MODIFICATIONS")
    print("=" * 85)

    total_expected = 0
    total_matched = 0
    total_unreviewed = 0

    for case_id in CASES:
        print("\n" + "=" * 85)
        print(case_id)
        print("=" * 85)

        events, expected = load_case(case_id)

        event_map = {
            event.event_id: event
            for event in events
        }

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=5.0
        )

        predicted_objects = engine.run(
            events,
            save_to_db=False
        )

        predicted_map = {
            relationship_key(rel): rel
            for rel in predicted_objects
        }

        predicted_keys = set(predicted_map)

        matched = expected & predicted_keys
        unreviewed = predicted_keys - expected
        missing = expected - predicted_keys

        total_expected += len(expected)
        total_matched += len(matched)
        total_unreviewed += len(unreviewed)

        print(f"\nEvents: {len(events)}")
        print(f"Expected relationships: {len(expected)}")
        print(f"Predicted relationships: {len(predicted_keys)}")
        print(f"Matched expected: {len(matched)}")
        print(f"Unmatched/unreviewed: {len(unreviewed)}")
        print(f"Missing expected: {len(missing)}")

        print("\nUNMATCHED / UNREVIEWED RELATIONSHIPS")

        if not unreviewed:
            print("None")

        for index, key in enumerate(sorted(unreviewed), 1):
            rel = predicted_map[key]

            print("\n" + "-" * 75)
            print(f"UNREVIEWED RELATIONSHIP {index}")
            print("-" * 75)

            print(f"Relationship type: {rel.relationship_type}")
            print(f"Source event ID: {rel.source_event_id}")
            print(f"Target event ID: {rel.target_event_id}")
            print(f"Confidence: {rel.confidence_score}")
            print(f"Category: {rel.relationship_category}")
            print(f"Correlation method: {rel.correlation_method}")
            print(f"Supporting identifiers: {rel.supporting_identifiers}")
            print(f"Evidence sources: {rel.evidence_sources}")
            print(f"Explanation: {rel.explanation}")

            print_event_details(
                "SOURCE EVENT DETAILS",
                event_map.get(rel.source_event_id)
            )

            print_event_details(
                "TARGET EVENT DETAILS",
                event_map.get(rel.target_event_id)
            )

        print("\nEXPECTED RELATIONSHIPS NOT PREDICTED")

        if not missing:
            print("None")
        else:
            for item in sorted(missing):
                print(item)

    print("\n" + "=" * 85)
    print("OVERALL AUDIT SUMMARY")
    print("=" * 85)

    print(f"Expected relationships: {total_expected}")
    print(f"Matched relationships: {total_matched}")
    print(f"Unmatched/unreviewed predictions: {total_unreviewed}")

    if total_expected:
        print(
            f"Expected-link recall: "
            f"{total_matched / total_expected:.2%}"
        )

    print("\nCLASSIFICATION GUIDANCE")
    print("1. Valid additional correlation")
    print("2. Duplicate cross-artifact representation")
    print("3. Unsupported correlation")
    print("4. Unresolved relationship")

    print("\nDATABASE WRITES: NONE")
    print("GROUND TRUTH MODIFICATIONS: NONE")
    print("EVIDENCE INGESTION: NONE")
    print("=" * 85)


if __name__ == "__main__":
    main()