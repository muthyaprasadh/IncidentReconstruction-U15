"""
Automated unit and integration tests for SQLite atomic ingestion,
transaction rollback, multi-case isolation, and ground truth preservation.
"""
import unittest
import os
import sqlite3
import json
import hashlib
import tempfile
from pathlib import Path
from typing import List, Dict, Any

from database.db import (
    get_db_connection,
    init_db,
    create_case,
    replace_case_ingestion,
    get_events,
    get_evidence_files,
    get_case_by_id,
    save_ground_truth,
    get_ground_truth,
    save_evaluation_run,
    get_evaluation_runs
)
from database.models import NormalizedEvent, EvidenceFile, Case
import database.db as database_module
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.sysmon_parser import SysmonParser
from parsers.network_parser import NetworkParser
from experiments.dataset_catalog import (
    AVAILABLE_SCENARIOS,
    DEVELOPMENT_SCENARIOS,
    HELD_OUT_SCENARIOS
)


class TestAtomicIngestionAndIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary_directory = tempfile.TemporaryDirectory(prefix="u15-atomic-tests-")
        cls._original_db_path = database_module.DB_PATH
        database_module.DB_PATH = Path(cls._temporary_directory.name) / "test_forensics.db"
        init_db()
        cls._seed_diagnostic_case()

    @classmethod
    def tearDownClass(cls):
        database_module.DB_PATH = cls._original_db_path
        cls._temporary_directory.cleanup()

    @classmethod
    def _seed_diagnostic_case(cls):
        case_id = "CASE-06-DIAGNOSTIC"
        fixture_dir = Path(__file__).resolve().parents[1] / "data" / "test_cases" / case_id
        parser_specs = [
            ("procmon_events.csv", "process", ProcmonParser),
            ("registry_export.reg", "registry", RegistryParser),
            ("sysmon_events.xml", "process", SysmonParser),
            ("wireshark_packets.csv", "network", NetworkParser),
        ]
        events = []
        evidence_files = []
        for file_name, source_type, parser_type in parser_specs:
            path = fixture_dir / file_name
            parser = parser_type(case_id)
            parsed = parser.parse_file(str(path), base_date="2026-11-10")
            if parser.errors:
                raise AssertionError(f"Failed to parse {file_name}: {parser.errors}")
            events.extend(parsed)
            evidence_files.append(EvidenceFile(
                case_id=case_id,
                source_type=source_type,
                file_name=file_name,
                file_path=str(path),
                file_size=path.stat().st_size,
                file_hash=hashlib.sha256(path.read_bytes()).hexdigest(),
                record_count=len(parsed),
                status="Parsed",
            ))

        create_case(Case(
            case_id=case_id,
            name="CASE-06 Diagnostic Fixture",
            description="Deterministic parser and atomic-ingestion integration fixture",
        ))
        replace_case_ingestion(case_id, events, evidence_files)

        ground_truth_path = (
            Path(__file__).resolve().parents[1]
            / "data" / "ground_truth" / f"{case_id}_ground_truth.json"
        )
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        relationships_by_source = {}
        for source_id, target_id, relationship_type in ground_truth["expected_relationships"]:
            relationships_by_source.setdefault(source_id, []).append(
                [source_id, target_id, relationship_type]
            )
        records = [
            {
                "event_id": event_id,
                "is_incident_related": 1,
                "activity_type": "Diagnostic fixture event",
                "expected_relationships": relationships_by_source.get(event_id, []),
            }
            for event_id in ground_truth["incident_event_ids"]
        ]
        save_ground_truth(case_id, records)

    def test_01_case_06_diagnostic_counts(self):
        """Verify fixture parsing and ingestion produce 18 events, 4 files, and 10 GT records."""
        case_id = "CASE-06-DIAGNOSTIC"
        events = get_events(case_id)
        evidence_files = get_evidence_files(case_id)
        gt = get_ground_truth(case_id)

        self.assertEqual(len(events), 18, f"Expected 18 events in {case_id}, got {len(events)}")
        self.assertEqual(len(evidence_files), 4, f"Expected 4 evidence files in {case_id}, got {len(evidence_files)}")
        self.assertEqual(len(gt), 10, f"Expected 10 GT records in {case_id}, got {len(gt)}")

    def test_02_atomic_rollback_on_batch_error(self):
        """Verify transaction rolls back and preserves existing state when an insertion error occurs."""
        case_id = "CASE-TEST-ROLLBACK"
        create_case(Case(case_id=case_id, name="Test Rollback Case", description="Case created to test rollback integrity"))
        
        # 1. First initial valid ingestion
        initial_events = [
            NormalizedEvent(
                event_id="EVT-VALID-01",
                case_id=case_id,
                source="process",
                event_type="PROCESS_CREATE",
                timestamp="2026-11-11T10:00:00Z",
                original_timestamp="2026-11-11T10:00:00Z",
                process_name="cmd.exe",
                pid=1001,
                evidence_reference="sysmon.xml:1"
            ),
            NormalizedEvent(
                event_id="EVT-VALID-02",
                case_id=case_id,
                source="process",
                event_type="PROCESS_CREATE",
                timestamp="2026-11-11T10:00:01Z",
                original_timestamp="2026-11-11T10:00:01Z",
                process_name="powershell.exe",
                pid=1002,
                evidence_reference="sysmon.xml:2"
            )
        ]
        initial_files = [
            EvidenceFile(
                case_id=case_id,
                file_name="sysmon.xml",
                source_type="process",
                file_path="evidence/sysmon.xml",
                file_size=1024,
                record_count=2,
                status="Parsed"
            )
        ]
        
        ev_count, f_count = replace_case_ingestion(case_id, initial_events, initial_files)
        self.assertEqual(ev_count, 2)
        self.assertEqual(f_count, 1)
        self.assertEqual(len(get_events(case_id)), 2)

        # 2. Attempt invalid ingestion containing internal duplicate event IDs
        corrupt_events = [
            NormalizedEvent(
                event_id="EVT-DUP-01",
                case_id=case_id,
                source="process",
                event_type="PROCESS_ACTIVITY",
                timestamp="2026-11-11T10:05:00Z",
                original_timestamp="2026-11-11T10:05:00Z",
                process_name="evil.exe",
                pid=2001,
                evidence_reference="procmon.csv:1"
            ),
            NormalizedEvent(
                event_id="EVT-DUP-01",  # duplicate event ID within the batch!
                case_id=case_id,
                source="process",
                event_type="PROCESS_ACTIVITY",
                timestamp="2026-11-11T10:05:01Z",
                original_timestamp="2026-11-11T10:05:01Z",
                process_name="evil.exe",
                pid=2001,
                evidence_reference="procmon.csv:2"
            )
        ]
        with self.assertRaises(ValueError) as ctx:
            replace_case_ingestion(case_id, corrupt_events, initial_files)
        self.assertIn("Duplicate event IDs detected", str(ctx.exception))

        # Verify existing records were untouched due to transaction validation and rollback
        self.assertEqual(len(get_events(case_id)), 2, "State should be rolled back to original 2 events")

    def test_03_multi_case_isolation_under_composite_pk(self):
        """Verify two distinct cases can hold identically named event IDs without constraint failure."""
        case_a = "CASE-MULTI-A"
        case_b = "CASE-MULTI-B"
        create_case(Case(case_id=case_a, name="Multi Case A", description="Isolation testing A"))
        create_case(Case(case_id=case_b, name="Multi Case B", description="Isolation testing B"))

        shared_event_id = "EVT-SHARED-IDENTICAL-01"

        events_a = [
            NormalizedEvent(
                event_id=shared_event_id,
                case_id=case_a,
                source="network",
                event_type="PACKET",
                timestamp="2026-11-11T12:00:00Z",
                original_timestamp="2026-11-11T12:00:00Z",
                src_ip="192.168.1.10",
                dst_ip="10.0.0.1",
                src_port=4444,
                dst_port=80,
                protocol="TCP",
                evidence_reference="pcap:1"
            )
        ]
        events_b = [
            NormalizedEvent(
                event_id=shared_event_id,
                case_id=case_b,
                source="network",
                event_type="PACKET",
                timestamp="2026-11-11T12:00:00Z",
                original_timestamp="2026-11-11T12:00:00Z",
                src_ip="192.168.1.20",
                dst_ip="10.0.0.2",
                src_port=5555,
                dst_port=443,
                protocol="TCP",
                evidence_reference="pcap:1"
            )
        ]

        replace_case_ingestion(case_a, events_a, [])
        replace_case_ingestion(case_b, events_b, [])

        re_a = get_events(case_a)
        re_b = get_events(case_b)
        self.assertEqual(len(re_a), 1)
        self.assertEqual(len(re_b), 1)
        self.assertEqual(re_a[0]["src_ip"], "192.168.1.10")
        self.assertEqual(re_b[0]["src_ip"], "192.168.1.20")

    def test_04_preservation_of_ground_truth_and_eval_history(self):
        """Verify re-ingesting a case replaces events & evidence files but preserves GT and eval history."""
        case_id = "CASE-PRESERVE-TEST"
        create_case(Case(case_id=case_id, name="Preserve Test Case", description="Testing preservation of GT and evaluation runs"))

        # 1. Save ground truth
        gt_records = [
            {"event_id": "EVT-P1", "is_incident_related": 1, "activity_type": "Persistence", "expected_relationships": [["EVT-P1", "EVT-P2", "SPAWNED"]]},
            {"event_id": "EVT-P2", "is_incident_related": 1, "activity_type": "Command", "expected_relationships": []}
        ]
        save_ground_truth(case_id, gt_records)

        # 2. Save evaluation result
        save_evaluation_run(
            run_id="RUN-TEST-001",
            case_id=case_id,
            method="Method 4 - Proposed Graph",
            temporal_window=5.0,
            metrics={"precision": 0.95, "recall": 0.90, "f1": 0.92, "accuracy": 0.91, "fpr": 0.05, "tp": 9, "fp": 1, "fn": 1, "tn": 90},
            notes="Test run"
        )

        # 3. Perform atomic case re-ingestion
        new_events = [
            NormalizedEvent(
                event_id="EVT-P1",
                case_id=case_id,
                source="process",
                event_type="PROCESS_CREATE",
                timestamp="2026-11-11T09:00:00Z",
                original_timestamp="2026-11-11T09:00:00Z",
                process_name="test.exe",
                pid=999,
                evidence_reference="procmon:1"
            )
        ]
        ev_count, f_count = replace_case_ingestion(case_id, new_events, [])
        self.assertEqual(ev_count, 1)

        # 4. Check that GT and eval history remain intact
        gt_after = get_ground_truth(case_id)
        self.assertEqual(len(gt_after), 2)
        eids = {r["event_id"] for r in gt_after}
        self.assertEqual(eids, {"EVT-P1", "EVT-P2"})

        history = get_evaluation_runs(case_id)
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(history[0]["method"], "Method 4 - Proposed Graph")
        self.assertAlmostEqual(history[0]["metrics"]["f1"], 0.92)

    def test_05_held_out_partition_integrity(self):
        """Verify dataset catalog properly segregates development (1-19) from held-out (20-22) scenarios."""
        self.assertEqual(len(AVAILABLE_SCENARIOS), 22)
        self.assertEqual(len(DEVELOPMENT_SCENARIOS), 19)
        self.assertEqual(len(HELD_OUT_SCENARIOS), 3)

        expected_held_out = {
            "CASE-20-HELD-OUT-MIXED",
            "CASE-21-HELD-OUT-PID-REUSE",
            "CASE-22-HELD-OUT-MISSING-REG-NOISE"
        }
        self.assertEqual(set(HELD_OUT_SCENARIOS), expected_held_out)

        # Ensure no overlap
        overlap = set(DEVELOPMENT_SCENARIOS).intersection(expected_held_out)
        self.assertEqual(len(overlap), 0, f"Found unexpected overlap in splits: {overlap}")


if __name__ == "__main__":
    unittest.main()
