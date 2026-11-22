import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from config.settings import BASE_DIR, DB_PATH
import database.db as db

from database.models import Case, EvidenceFile
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
    ("procmon_events.csv", "process", ProcmonParser),
    ("registry_export.reg", "registry", RegistryParser),
    ("sysmon_events.xml", "process", SysmonParser),
    ("wireshark_packets.csv", "network", NetworkParser),
]

BASE_DATE = "2026-11-10"
RESULTS_DIR = BASE_DIR / "output" / "reports"
RESULTS_PATH = RESULTS_DIR / "heldout_validation_results.json"


def count_records(case_id):
    conn = db.get_db_connection()
    try:
        result = {}
        for table in ("events", "evidence_files", "relationships",
                      "ground_truth_records", "evaluation_runs"):
            row = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE case_id = ?",
                (case_id,)
            ).fetchone()
            result[table] = row[0]
        return result
    finally:
        conn.close()


def load_case(case_id):
    manifest_path = (
        BASE_DIR / "data" / "experiment_manifests"
        / f"{case_id}_manifest.json"
    )

    case_dir = BASE_DIR / "data" / "test_cases" / case_id

    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)

    if not case_dir.is_dir():
        raise FileNotFoundError(case_dir)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("case_id") != case_id:
        raise ValueError(f"Manifest case ID mismatch: {case_id}")

    if manifest.get("dataset_type") != "held_out_test":
        raise ValueError(f"{case_id} is not marked held_out_test")

    if manifest.get("recorded_independently_of_correlation_engine") is not True:
        raise ValueError(f"{case_id} lacks independent-recording confirmation")

    events = []
    evidence_files = []

    for file_name, source_type, parser_type in PARSER_SPECS:
        path = case_dir / file_name

        if not path.is_file():
            raise FileNotFoundError(path)

        parser = parser_type(case_id)
        parsed = parser.parse_file(str(path), base_date=BASE_DATE)

        if parser.errors:
            raise RuntimeError(
                f"Parser errors in {case_id}/{file_name}: {parser.errors}"
            )

        events.extend(parsed)

        evidence_files.append(EvidenceFile(
            case_id=case_id,
            source_type=source_type,
            file_name=file_name,
            file_path=str(path.resolve()),
            file_size=path.stat().st_size,
            file_hash=hashlib.sha256(path.read_bytes()).hexdigest(),
            record_count=len(parsed),
            status="Parsed"
        ))

    event_ids = {event.event_id for event in events}

    if len(event_ids) != len(events):
        raise ValueError(f"Duplicate event IDs detected in {case_id}")

    expected = [
        tuple(item)
        for item in manifest.get("expected_event_relationships", [])
    ]

    missing_event_ids = sorted({
        event_id
        for relationship in expected
        for event_id in relationship[:2]
        if event_id not in event_ids
    })

    if missing_event_ids:
        raise ValueError(
            f"{case_id}: expected relationship event IDs missing: "
            f"{missing_event_ids}"
        )

    chronology_missing = [
        event_id for event_id in manifest.get("expected_chronology", [])
        if event_id not in event_ids
    ]

    if chronology_missing:
        raise ValueError(
            f"{case_id}: chronology event IDs missing: {chronology_missing}"
        )

    return manifest, events, evidence_files


def relationship_key(rel):
    return (
        rel.source_event_id,
        rel.target_event_id,
        rel.relationship_type
    )


def main():
    print("=" * 70)
    print("U-15 HELD-OUT SYNTHETIC VALIDATION")
    print("=" * 70)
    print(f"Database: {DB_PATH}")

    if not DB_PATH.is_file():
        raise FileNotFoundError(f"Runtime database not found: {DB_PATH}")

    db.init_db()

    prepared = {}

    print("\nPHASE 1: PREFLIGHT AND PARSER VALIDATION")

    for case_id in CASES:
        state = count_records(case_id)

        print(f"\n{case_id}")
        print(f"Existing records: {state}")

        if state["events"] != 0 or state["evidence_files"] != 0:
            raise RuntimeError(
                f"Refusing to overwrite existing evidence for {case_id}"
            )

        if state["relationships"] != 0:
            raise RuntimeError(
                f"Refusing to overwrite existing relationships for {case_id}"
            )

        ground_truth = db.get_ground_truth(case_id)

        if not ground_truth:
            raise RuntimeError(f"Ground truth missing for {case_id}")

        manifest, events, evidence_files = load_case(case_id)

        if len(ground_truth) == 0:
            raise RuntimeError(f"No ground-truth records for {case_id}")

        expected_count = len(manifest["expected_event_relationships"])

        print(f"Parsed events: {len(events)}")
        print(f"Evidence files: {len(evidence_files)}")
        print(f"Ground-truth records: {len(ground_truth)}")
        print(f"Expected relationships: {expected_count}")

        prepared[case_id] = {
            "manifest": manifest,
            "events": events,
            "evidence_files": evidence_files,
            "ground_truth_count": len(ground_truth),
            "initial_state": state
        }

    print("\nAll three cases passed preflight.")
    print("\nPHASE 2: ATOMIC INGESTION")

    for case_id in CASES:
        item = prepared[case_id]

        if db.get_case_by_id(case_id) is None:
            db.create_case(Case(
                case_id=case_id,
                name=item["manifest"].get("scenario", case_id),
                description="Held-out synthetic validation experiment",
                collection_date=BASE_DATE,
                status="Active"
            ))

        event_count, file_count = db.replace_case_ingestion(
            case_id,
            item["events"],
            item["evidence_files"]
        )

        after = count_records(case_id)

        if after["events"] != event_count:
            raise RuntimeError(f"Event count verification failed: {case_id}")

        if after["evidence_files"] != file_count:
            raise RuntimeError(f"Evidence count verification failed: {case_id}")

        if after["ground_truth_records"] != item["ground_truth_count"]:
            raise RuntimeError(f"Ground truth changed during ingestion: {case_id}")

        if after["evaluation_runs"] != item["initial_state"]["evaluation_runs"]:
            raise RuntimeError(f"Evaluation history changed: {case_id}")

        print(
            f"{case_id}: ingested {event_count} events, "
            f"{file_count} evidence files; ground truth preserved."
        )

    print("\nPHASE 3: CORRELATION AND EXPECTED-LINK EVALUATION")

    results = {
        "experiment": "U-15 Held-out Synthetic Validation",
        "database": str(DB_PATH),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Synthetic held-out cases; positive expected-link coverage only",
        "cases": []
    }

    for case_id in CASES:
        item = prepared[case_id]
        events = item["events"]
        expected = {
            tuple(x)
            for x in item["manifest"]["expected_event_relationships"]
        }

        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=5.0
        )

        predicted_objects = engine.run(events, save_to_db=False)
        predicted = {relationship_key(rel) for rel in predicted_objects}

        matched = expected & predicted
        missing = expected - predicted
        unexpected = predicted - expected

        recall = len(matched) / len(expected) if expected else None

        engine.run(events, save_to_db=True)

        persisted = count_records(case_id)

        if persisted["relationships"] != len(predicted):
            raise RuntimeError(
                f"Persisted relationship count mismatch for {case_id}"
            )

        result = {
            "case_id": case_id,
            "events": len(events),
            "expected_relationships": len(expected),
            "predicted_relationships": len(predicted),
            "matched_expected_relationships": len(matched),
            "missing_expected_relationships": [
                list(x) for x in sorted(missing)
            ],
            "unexpected_unreviewed_relationships": [
                list(x) for x in sorted(unexpected)
            ],
            "expected_link_recall": round(recall, 4) if recall is not None else None,
            "ground_truth_records": item["ground_truth_count"],
            "persisted_relationships": persisted["relationships"],
            "interpretation": (
                "Expected-link recall only. Unexpected relationships are "
                "unreviewed, not confirmed false positives."
            )
        }

        results["cases"].append(result)

        print(f"\n{case_id}")
        print(f"Events: {len(events)}")
        print(f"Expected links: {len(expected)}")
        print(f"Predicted links: {len(predicted)}")
        print(f"Matched expected links: {len(matched)}")
        print(f"Missing expected links: {len(missing)}")
        print(f"Unexpected/unreviewed links: {len(unexpected)}")
        print(f"Expected-link recall: {recall:.2%}" if recall is not None else "Recall: N/A")

        if missing:
            print("MISSING:")
            for relationship in sorted(missing):
                print(" ", relationship)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 70)
    print("VALIDATION COMPLETE")
    print(f"Results saved to: {RESULTS_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    main()