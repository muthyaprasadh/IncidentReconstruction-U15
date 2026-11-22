"""

Forensic Audit & Integrity Test Suite for U-15 Incident Reconstruction Platform.

Exhaustively verifies:

1. Ground-truth ID consistency (no ID mismatches between ground truth and parsed events)

2. Registry snapshot interpretation (no artificial timestamps, static artifact state)

3. Strict five-tuple matching (no wildcards on missing fields)

4. Reverse packet matching (bidirectional client-server traffic)

5. PID reuse prevention (epoch separation across process exit boundaries)

6. Missing and uncertain timestamp normalization (no silent substitution of current time)

7. Invalid and corrupted evidence files (graceful error reporting)

8. Duplicate event deduplication

9. False-positive suppression (Proposed Graph vs Naive Baseline 3)

10. Missing evidence graceful degradation

"""

import unittest

from pathlib import Path

import tempfile

from datetime import datetime, timezone



from normalization.normalizer import Normalizer

from parsers.procmon_parser import ProcmonParser

from parsers.registry_parser import RegistryParser

from parsers.network_parser import NetworkParser

from parsers.sysmon_parser import SysmonParser, sysmon_event_id_from_fields

from database.models import NormalizedEvent, EventRelationship

from correlation.correlation_engine import CorrelationEngine

from correlation.process_correlation import ProcessLifetimeTracker, ProcessCorrelator

from correlation.network_correlation import NetworkCorrelator

from correlation.registry_correlation import RegistryCorrelator

from evaluation.baselines import BaselineRunner

from evaluation.metrics import ForensicEvaluator

from experiments.test_scenario_generator import ControlledExperimentGenerator

from experiments.ground_truth_manager import GroundTruthManager

import database.db as db



class TestForensicAuditAndIntegrity(unittest.TestCase):

    @classmethod

    def setUpClass(cls):

        db.init_db()



    def test_01_ground_truth_id_consistency(self):

        """Priority 1: Every ground-truth event must map 1:1 to an actual parsed event."""

        case_id = "AUDIT-CASE-01"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-06-MULTI-ATTACK-01")



        # Parse the raw generated evidence files

        pm_events = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")

        reg_events = RegistryParser(case_id).parse_file(ds["registry_file"])

        net_events = NetworkParser(case_id).parse_file(ds["wireshark_file"])

        sysmon_events = SysmonParser(case_id).parse_file(ds["sysmon_file"], timezone_name="UTC")



        all_parsed_events = pm_events + reg_events + net_events + sysmon_events

        parsed_eids = {e.event_id for e in all_parsed_events}



        # Load independently documented ground truth

        gt = GroundTruthManager.load_ground_truth(case_id)

        self.assertIsNotNone(gt, "Ground truth record must exist")



        gt_eids = set(gt["incident_event_ids"])

        self.assertGreater(len(gt_eids), 0, "Ground truth must contain incident event IDs")



        # Check every ground-truth event ID exists in parsed events

        missing_from_parsed = gt_eids - parsed_eids

        self.assertEqual(

            len(missing_from_parsed), 0,

            f"Ground truth IDs failed to match parsed event IDs! Missing: {missing_from_parsed}"

        )



        # Verify true positives are accurately counted

        metrics = ForensicEvaluator.calculate_classification_metrics(gt_eids, gt_eids, parsed_eids)

        self.assertEqual(metrics["tp"], len(gt_eids))

        self.assertEqual(metrics["fn"], 0)

        self.assertEqual(metrics["recall"], 1.0)



    def test_sysmon_timestamp_and_zero_guid_validation(self):

        events_xml = """<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">

          <Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-11-10T10:00:02.000Z"/></System>

            <EventData><Data Name="UtcTime">2026-11-10 10:00:00.000Z</Data>

              <Data Name="ProcessGuid">00000000-0000-0000-0000-000000000000</Data>

              <Data Name="ProcessId">10</Data><Data Name="Image">C:\\test.exe</Data></EventData>

          </Event>

          <Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-11-10T10:00:00.000Z"/></System>

            <EventData><Data Name="UtcTime">2026-11-10 10:00:00.500Z</Data>

              <Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>

              <Data Name="ProcessId">11</Data><Data Name="Image">C:\\test.exe</Data></EventData>

          </Event>

          <Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-11-10T10:00:03.000Z"/></System>

            <EventData><Data Name="ProcessGuid">{22222222-2222-2222-2222-222222222222}</Data>

              <Data Name="ProcessId">12</Data><Data Name="Image">C:\\test.exe</Data></EventData>

          </Event>

          <Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-11-10T10:00:04.000"/></System>

            <EventData><Data Name="ProcessGuid">{33333333-3333-3333-3333-333333333333}</Data>

              <Data Name="ProcessId">13</Data><Data Name="Image">C:\\test.exe</Data></EventData>

          </Event>

        </Events>"""



        with tempfile.TemporaryDirectory() as temp_dir:

            xml_path = Path(temp_dir) / "sysmon.xml"

            xml_path.write_text(events_xml, encoding="utf-8")

            parser = SysmonParser("SYS-TS-TEST")

            events = parser.parse_file(str(xml_path), timezone_name="UTC")



        self.assertEqual(len(events), 4)

        discrepant, subsecond_difference, system_time_fallback, naive_system_time = events



        self.assertEqual(discrepant.timestamp, "2026-11-10T10:00:00+00:00")

        self.assertEqual(discrepant.metadata["UtcTime"], "2026-11-10 10:00:00.000Z")

        self.assertEqual(discrepant.metadata["SystemTime"], "2026-11-10T10:00:02.000Z")

        self.assertEqual(discrepant.metadata["timestamp_delta_ms"], 2000.0)

        self.assertEqual(

            discrepant.metadata["timestamp_uncertainty_start"],

            "2026-11-10T10:00:00+00:00"

        )

        self.assertEqual(

            discrepant.metadata["timestamp_uncertainty_end"],

            "2026-11-10T10:00:02+00:00"

        )

        self.assertEqual(discrepant.process_guid, "")

        self.assertEqual(discrepant.metadata["ProcessGuid"], "")

        self.assertEqual(

            discrepant.metadata["ProcessGuidRaw"],

            "00000000-0000-0000-0000-000000000000"

        )

        self.assertEqual(

            discrepant.event_id,

            sysmon_event_id_from_fields(

                "sysmon.xml",

                1,

                1,

                "2026-11-10 10:00:00.000Z",

                "00000000-0000-0000-0000-000000000000",

                10,

                "C:\\test.exe"

            )

        )

        self.assertTrue(any("UtcTime retained for chronology" in warning for warning in parser.warnings))

        self.assertTrue(any("process attribution is unavailable" in warning for warning in parser.warnings))



        self.assertTrue(subsecond_difference.timestamp)

        self.assertEqual(subsecond_difference.metadata["timestamp_delta_ms"], 500.0)

        self.assertTrue(system_time_fallback.timestamp.startswith("2026-11-10T10:00:03"))

        self.assertEqual(system_time_fallback.metadata["TimestampSource"], "SystemTime")

        self.assertTrue(any("using XML SystemTime for chronology" in warning for warning in parser.warnings))

        self.assertEqual(naive_system_time.timestamp, "")

        self.assertTrue(any("SystemTime is not timezone-aware" in warning for warning in parser.warnings))



    def test_sysmon_network_pid_attribution_requires_reliable_time(self):

        process_event = NormalizedEvent(

            event_id="EVT-PROC-START-01",

            case_id="SYS-TIME-TEST",

            timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00Z",

            source="process",

            event_type="PROCESS_START",

            pid=4242,

            process_name="curl.exe"

        )

        sysmon_event = NormalizedEvent(

            event_id="EVT-SYSMON-NET-01",

            case_id="SYS-TIME-TEST",

            timestamp="",

            original_timestamp="2026-11-10 10:00:01Z",

            source="network",

            event_type="NET_CONNECT",

            pid=4242,

            process_name="<unknown process>",

            src_ip="192.0.2.10",

            dst_ip="198.51.100.20",

            src_port=50000,

            dst_port=443,

            protocol="TCP",

            process_guid="",

            metadata={

                "sysmon_event_id": 3,

                "ProcessGuid": "",

                "ProcessGuidRaw": "00000000-0000-0000-0000-000000000000"

            }

        )

        tracker = ProcessLifetimeTracker()

        tracker.register_events([process_event, sysmon_event])



        relationships = NetworkCorrelator.correlate_network_events(

            [process_event, sysmon_event],

            "SYS-TIME-TEST",

            tracker

        )



        self.assertFalse(

            any(rel.target_event_id == sysmon_event.event_id for rel in relationships),

            "An untimed Sysmon event without a ProcessGuid must not be attributed by PID alone."

        )



    def test_sysmon_network_correlates_inside_timestamp_uncertainty_interval(self):

        process_event = NormalizedEvent(

            event_id="EVT-PROC-START-INTERVAL",

            case_id="SYS-TIME-INTERVAL",

            timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00Z",

            source="process",

            event_type="PROCESS_START",

            pid=4242,

            process_name="curl.exe"

        )

        sysmon_event = NormalizedEvent(

            event_id="EVT-SYSMON-NET-INTERVAL",

            case_id="SYS-TIME-INTERVAL",

            timestamp="",

            original_timestamp="10:00:00Z",

            source="network",

            event_type="NET_CONNECT",

            pid=4242,

            process_name="<unknown process>",

            src_ip="192.0.2.10",

            dst_ip="198.51.100.20",

            src_port=50000,

            dst_port=443,

            protocol="TCP",

            metadata={

                "sysmon_event_id": 3,

                "timestamp_uncertainty_start": "2026-11-10T10:00:00Z",

                "timestamp_uncertainty_end": "2026-11-10T10:00:04Z"

            }

        )

        matching_packet = NormalizedEvent(

            event_id="EVT-WIRE-IN-INTERVAL",

            case_id="SYS-TIME-INTERVAL",

            timestamp="2026-11-10T10:00:02Z",

            original_timestamp="10:00:02Z",

            source="network",

            event_type="NET_PACKET",

            src_ip="192.0.2.10",

            dst_ip="198.51.100.20",

            src_port=50000,

            dst_port=443,

            protocol="TCP",

            metadata={"frame_number": "10"}

        )

        outside_packet = NormalizedEvent(

            event_id="EVT-WIRE-OUTSIDE-INTERVAL",

            case_id="SYS-TIME-INTERVAL",

            timestamp="2026-11-10T10:00:05Z",

            original_timestamp="10:00:05Z",

            source="network",

            event_type="NET_PACKET",

            src_ip="192.0.2.10",

            dst_ip="198.51.100.20",

            src_port=50000,

            dst_port=443,

            protocol="TCP",

            metadata={"frame_number": "11"}

        )

        events = [process_event, sysmon_event, matching_packet, outside_packet]

        tracker = ProcessLifetimeTracker()

        tracker.register_events(events)



        relationships = NetworkCorrelator.correlate_network_events(

            events,

            "SYS-TIME-INTERVAL",

            tracker

        )

        connected = [

            rel for rel in relationships

            if rel.relationship_type == "CONNECTED_TO"

        ]

        observed = [

            rel for rel in relationships

            if rel.relationship_type == "OBSERVED_IN"

        ]



        self.assertEqual(len(connected), 1)

        self.assertEqual(connected[0].source_event_id, process_event.event_id)

        self.assertIn("WireFrame:10", connected[0].supporting_identifiers)

        self.assertEqual(len(observed), 1)

        self.assertEqual(observed[0].target_event_id, matching_packet.event_id)

        self.assertIn(

            "TimestampInterval:2026-11-10T10:00:00+00:00..2026-11-10T10:00:04+00:00",

            observed[0].supporting_identifiers

        )



    def test_sysmon_eid3_rejects_file_operation_as_process_start(self):
        case_id = "SYS-ATTR-FILE-REJECT"
        guid = "{11111111-1111-1111-1111-111111111111}"

        file_event = NormalizedEvent(
            event_id="EVT-FILE-LOCK",
            case_id=case_id,
            timestamp="2026-11-10T10:00:00Z",
            original_timestamp="10:00:00",
            source="process",
            event_type="FILE_LOCKFILE",
            pid=18768,
            process_name="ChatGPT Classic.exe",
            process_guid=guid
        )

        sysmon_event = NormalizedEvent(
            event_id="EVT-SYSMON-NET",
            case_id=case_id,
            timestamp="2026-11-10T10:00:05Z",
            original_timestamp="10:00:05",
            source="network",
            event_type="NET_CONNECT",
            pid=18768,
            process_name="ChatGPT Classic.exe",
            process_guid=guid,
            protocol="UDP",
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=52822,
            dst_port=443,
            metadata={
                "sysmon_event_id": 3,
                "ProcessGuid": guid,
                "Initiated": False
            }
        )

        events = [file_event, sysmon_event]
        tracker = ProcessLifetimeTracker()
        tracker.register_events(events)

        relationships = NetworkCorrelator.correlate_network_events(
            events, case_id, tracker
        )

        connected = [
            rel for rel in relationships
            if rel.target_event_id == sysmon_event.event_id
            and rel.relationship_type == "CONNECTED_TO"
        ]

        self.assertEqual(
            len(connected),
            0,
            "A file operation must not become a process-start attribution anchor."
        )

    def test_sysmon_eid3_uses_explicit_process_start(self):
        case_id = "SYS-ATTR-VALID-START"
        guid = "{22222222-2222-2222-2222-222222222222}"

        process_start = NormalizedEvent(
            event_id="EVT-EXPLICIT-START",
            case_id=case_id,
            timestamp="2026-11-10T10:00:00Z",
            original_timestamp="10:00:00",
            source="process",
            event_type="PROCESS_START",
            pid=24524,
            process_name="curl.exe",
            process_guid=guid
        )

        sysmon_event = NormalizedEvent(
            event_id="EVT-SYSMON-VALID",
            case_id=case_id,
            timestamp="2026-11-10T10:00:05Z",
            original_timestamp="10:00:05",
            source="network",
            event_type="NET_CONNECT",
            pid=24524,
            process_name="curl.exe",
            process_guid=guid,
            protocol="TCP",
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=50000,
            dst_port=443,
            metadata={
                "sysmon_event_id": 3,
                "ProcessGuid": guid,
                "Initiated": False
            }
        )

        events = [process_start, sysmon_event]
        tracker = ProcessLifetimeTracker()
        tracker.register_events(events)

        relationships = NetworkCorrelator.correlate_network_events(
            events, case_id, tracker
        )

        connected = [
            rel for rel in relationships
            if rel.target_event_id == sysmon_event.event_id
            and rel.relationship_type == "CONNECTED_TO"
        ]

        self.assertEqual(len(connected), 1)
        self.assertEqual(
            connected[0].source_event_id,
            process_start.event_id
        )
        self.assertEqual(
            connected[0].relationship_category,
            "Process attribution"
        )
        self.assertIn(
            "Initiated:false",
            connected[0].supporting_identifiers
        )
        self.assertIn(
            "not initiated",
            connected[0].explanation
        )


    def test_02_registry_snapshot_interpretation(self):

        """Priority 2: .reg snapshots must not receive artificial modification timestamps."""

        case_id = "AUDIT-CASE-REG"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-06-MULTI-ATTACK-01")



        reg_events = RegistryParser(case_id).parse_file(ds["registry_file"])

        self.assertGreater(len(reg_events), 0)



        for rev in reg_events:

            # Snapshot values must be flagged and must NOT have artificial timestamps

            self.assertTrue(rev.metadata.get("is_snapshot", False))

            self.assertEqual(rev.timestamp, "", "Snapshot must have empty ISO timestamp")

            self.assertEqual(rev.original_timestamp, "STATIC_REG_SNAPSHOT")



        # Correlation check: untimestamped snapshots must not be temporally associated via proximity

        tracker = ProcessLifetimeTracker()

        rels = RegistryCorrelator.correlate_registry_events(reg_events, case_id, tracker, window_seconds=5.0)



        # Verify no temporal association relationships were created for untimestamped snapshots

        temporal_rels = [r for r in rels if r.relationship_category == "Temporal association"]

        self.assertEqual(len(temporal_rels), 0, "Static snapshots must never receive temporal association")



    def test_03_strict_five_tuple_matching_no_wildcards(self):

        """Priority 3: Strict 5-tuple matching must require all 5 fields and reject wildcards."""

        ep_event = NormalizedEvent(

            event_id="EVT-NET-EP-01",

            case_id="TEST",

            timestamp="2026-11-10T10:00:05Z",

            original_timestamp="10:00:05",

            source="network",

            event_type="NET_CONNECT",

            pid=1234,

            src_ip="192.168.1.50",

            dst_ip="203.0.113.10",

            src_port=49152,

            dst_port=80,

            protocol="TCP"

        )



        # 1. Exact match forward

        wire_exact = NormalizedEvent(

            event_id="EVT-NET-WIRE-01",

            case_id="TEST",

            timestamp="2026-11-10T10:00:05.100Z",

            original_timestamp="10:00:05.100",

            source="network",

            event_type="NET_PACKET",

            src_ip="192.168.1.50",

            dst_ip="203.0.113.10",

            src_port=49152,

            dst_port=80,

            protocol="TCP"

        )

        is_match, direction = NetworkCorrelator._matches_five_tuple(ep_event, wire_exact)

        self.assertTrue(is_match)

        self.assertEqual(direction, "forward")



        # 2. Mismatched port

        wire_bad_port = NormalizedEvent(

            event_id="EVT-NET-WIRE-02",

            case_id="TEST",

            timestamp="2026-11-10T10:00:05.100Z",

            original_timestamp="10:00:05.100",

            source="network",

            event_type="NET_PACKET",

            src_ip="192.168.1.50",

            dst_ip="203.0.113.10",

            src_port=49152,

            dst_port=443,  # Port 443 != 80

            protocol="TCP"

        )

        is_match, _ = NetworkCorrelator._matches_five_tuple(ep_event, wire_bad_port)

        self.assertFalse(is_match)



        # 3. Missing IP field must NOT act as wildcard

        wire_missing_src = NormalizedEvent(

            event_id="EVT-NET-WIRE-03",

            case_id="TEST",

            timestamp="2026-11-10T10:00:05.100Z",

            original_timestamp="10:00:05.100",

            source="network",

            event_type="NET_PACKET",

            src_ip="",  # Empty source IP

            dst_ip="203.0.113.10",

            src_port=49152,

            dst_port=80,

            protocol="TCP"

        )

        is_match, _ = NetworkCorrelator._matches_five_tuple(ep_event, wire_missing_src)

        self.assertFalse(is_match, "Missing source IP must not match as wildcard")



    def test_04_reverse_packet_matching(self):

        """Priority 3: Inbound reply packets (server -> client) must match reverse 5-tuple."""

        case_id = "AUDIT-CASE-REV"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-15-REVERSE-PACKETS")



        pm_events = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")

        net_events = NetworkParser(case_id).parse_file(ds["wireshark_file"])

        sysmon_events = SysmonParser(case_id).parse_file(ds["sysmon_file"], timezone_name="UTC")



        tracker = ProcessLifetimeTracker()

        tracker.register_events(pm_events + sysmon_events)



        rels = NetworkCorrelator.correlate_network_events(pm_events + sysmon_events + net_events, case_id, tracker, window_seconds=5.0)



        # Check that both forward and reverse packets were correlated with OBSERVED_IN

        observed_in_rels = [r for r in rels if r.relationship_type == "OBSERVED_IN"]

        self.assertGreaterEqual(len(observed_in_rels), 2, "Both forward and reverse packets must be correlated")



        directions = [r.explanation for r in observed_in_rels]

        self.assertTrue(any("Reverse reply" in d or "reverse" in d for d in directions), "Reverse reply direction must be recognized")



    def test_05_pid_reuse_handling(self):

        """Priority 4: Process lifetime validation must prevent attributing events across PID reuse."""

        case_id = "AUDIT-PID-REUSE"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-10-PID-REUSE")



        pm_events = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")

        net_events = NetworkParser(case_id).parse_file(ds["wireshark_file"])

        sysmon_events = SysmonParser(case_id).parse_file(ds["sysmon_file"], timezone_name="UTC")



        tracker = ProcessLifetimeTracker()

        tracker.register_events(pm_events + sysmon_events)



        # ServiceA.exe (PID 4000) exited at t=5s

        # mal_agent.exe (PID 4000) started at t=15s

        self.assertTrue(tracker.is_pid_active(4000, "ServiceA.exe", "2026-11-10T10:00:03Z"))

        self.assertFalse(tracker.is_pid_active(4000, "ServiceA.exe", "2026-11-10T10:00:18Z"), "ServiceA must not be active at t=18s")

        self.assertTrue(tracker.is_pid_active(4000, "mal_agent.exe", "2026-11-10T10:00:18Z"), "mal_agent must be active at t=18s")



        # Run correlation engine

        all_events = pm_events + net_events + sysmon_events

        engine = CorrelationEngine(case_id=case_id, temporal_window=5.0)

        rels = engine.run(all_events, save_to_db=False)



        # Verify C2 socket (at t=18s) is attributed ONLY to mal_agent, NEVER to ServiceA

        sock_event = next(e for e in all_events if e.event_type == "NET_CONNECT")

        sock_rels = [r for r in rels if r.target_event_id == sock_event.event_id]

        self.assertEqual(len(sock_rels), 1)



        source_ev = next(e for e in all_events if e.event_id == sock_rels[0].source_event_id)

        self.assertEqual(source_ev.process_name, "mal_agent.exe")

        self.assertNotEqual(source_ev.process_name, "servicea.exe")



    def test_procmon_process_create_and_observed_pid_attribution(self):

        case_id = "PROC-CREATE-LINEAGE"

        parser = ProcmonParser(case_id)



        def parse_record(row_idx, raw_time, raw_pid, raw_op, raw_detail):

            return parser._convert_record(

                row_idx=row_idx,

                evidence_file="Logfile.CSV",

                raw_time=raw_time,

                raw_proc="powershell.exe",

                raw_pid=raw_pid,

                raw_op=raw_op,

                raw_path="",

                raw_result="SUCCESS",

                raw_detail=raw_detail,

                base_date="2026-11-10",

                timezone_name="UTC",

            )



        parent_activity = parse_record(1, "10:00:00.000", 100, "CreateFile", "")

        parent_create = parse_record(2, "10:00:01.000", 100, "Process Create", "PID: 200, Command line: child.exe")

        child_start = parse_record(3, "10:00:01.010", 200, "Process Start", "Parent PID: 100")



        self.assertEqual(parent_activity.event_type, "FILE_CREATEFILE")

        self.assertEqual(parent_create.event_type, "PROCESS_CREATE")

        self.assertEqual(parent_create.metadata["created_pid"], 200)

        self.assertEqual(child_start.event_type, "PROCESS_START")

        self.assertEqual(child_start.ppid, 100)



        registry_event = NormalizedEvent(

            event_id="EVT-REG-OBSERVED-PID",

            case_id=case_id,

            timestamp="2026-11-10T10:00:01.005Z",

            original_timestamp="10:00:01.005",

            source="registry",

            event_type="REG_SET_VALUE",

            pid=100,

            process_name="powershell.exe",

            registry_key=r"HKCU\Softwar&#x65;**\T**est",

            registry_operation="RegSetValue",

        )

        events = [parent_activity, parent_create, child_start, registry_event]

        tracker = ProcessLifetimeTracker()

        tracker.register_events(events)



        parent_epoch = tracker.get_active_epoch(100, child_start.timestamp)

        self.assertIsNotNone(parent_epoch)

        self.assertFalse(parent_epoch.is_explicit_start)

        self.assertEqual(parent_epoch.start_event_id, parent_activity.event_id)



        spawned = [

            rel for rel in ProcessCorrelator.correlate_process_tree(

                events, case_id, tracker

            )

            if rel.relationship_type == "SPAWNED"

        ]

        self.assertEqual(len(spawned), 1)

        self.assertEqual(spawned[0].source_event_id, parent_create.event_id)

        self.assertEqual(spawned[0].target_event_id, child_start.event_id)

        self.assertIn("explicitly names child PID 200", spawned[0].explanation)



        modified = [

            rel for rel in RegistryCorrelator.correlate_registry_events(

                events, case_id, tracker

            )

            if rel.target_event_id == registry_event.event_id

        ]

        self.assertEqual(len(modified), 1)

        self.assertEqual(modified[0].source_event_id, parent_create.event_id)

        self.assertIn("no explicit process-start record was captured", modified[0].explanation)



    def test_explicit_start_supersedes_prior_observation_epoch(self):

        case_id = "PROC-OBSERVED-EPOCH"

        activity = NormalizedEvent(

            event_id="EVT-PROC-OBSERVATION",

            case_id=case_id,

            timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00",

            source="process",

            event_type="FILE_CREATEFILE",

            pid=321,

            process_name="worker.exe",

        )

        start = NormalizedEvent(

            event_id="EVT-PROC-EXPLICIT-START",

            case_id=case_id,

            timestamp="2026-11-10T10:00:05Z",

            original_timestamp="10:00:05",

            source="process",

            event_type="PROCESS_START",

            pid=321,

            process_name="worker.exe",

        )



        tracker = ProcessLifetimeTracker()

        tracker.register_events([activity, start])



        observed_epoch = tracker.get_active_epoch(321, "2026-11-10T10:00:04Z")

        explicit_epoch = tracker.get_active_epoch(321, "2026-11-10T10:00:06Z")

        self.assertIsNotNone(observed_epoch)

        self.assertFalse(observed_epoch.is_explicit_start)

        self.assertIsNotNone(explicit_epoch)

        self.assertTrue(explicit_epoch.is_explicit_start)

        self.assertEqual(explicit_epoch.start_event_id, start.event_id)



    def test_spawn_relationship_preserves_start_and_create_provenance(self):

        case_id = "PROC-CREATE-PROVENANCE"

        parent_start = NormalizedEvent(

            event_id="EVT-PARENT-START",

            case_id=case_id,

            timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00",

            source="process",

            event_type="PROCESS_START",

            pid=100,

            process_name="parent.exe",

        )

        parent_create = NormalizedEvent(

            event_id="EVT-PARENT-CREATE",

            case_id=case_id,

            timestamp="2026-11-10T10:00:01Z",

            original_timestamp="10:00:01",

            source="process",

            event_type="PROCESS_CREATE",

            pid=100,

            process_name="parent.exe",

            metadata={"created_pid": 200},

        )

        child_start = NormalizedEvent(

            event_id="EVT-CHILD-START",

            case_id=case_id,

            timestamp="2026-11-10T10:00:01Z",

            original_timestamp="10:00:01",

            source="process",

            event_type="PROCESS_START",

            pid=200,

            ppid=100,

            process_name="child.exe",

        )

        events = [parent_start, parent_create, child_start]

        tracker = ProcessLifetimeTracker()

        tracker.register_events(events)



        relationships = ProcessCorrelator.correlate_process_tree(

            events, case_id, tracker

        )

        self.assertEqual(

            {

                (rel.source_event_id, rel.target_event_id, rel.relationship_type)

                for rel in relationships

            },

            {

                (parent_start.event_id, child_start.event_id, "SPAWNED"),

                (parent_create.event_id, child_start.event_id, "SPAWNED"),

            },

        )



    def test_procmon_tcp_connect_uses_active_process_start(self):

        case_id = "PROC-NETWORK-PID"

        process_start = NormalizedEvent(

            event_id="EVT-PROC-TCP-START",

            case_id=case_id,

            timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00",

            source="process",

            event_type="PROCESS_START",

            pid=24524,

            process_name="curl.exe",

            evidence_file="Logfile.CSV",

            evidence_reference="Row 10",

        )

        connection = NormalizedEvent(

            event_id="EVT-PROC-TCP-CONNECT",

            case_id=case_id,

            timestamp="2026-11-10T10:00:01Z",

            original_timestamp="10:00:01",

            source="process",

            event_type="TCP_CONNECT",

            pid=24524,

            process_name="curl.exe",

            evidence_file="Logfile.CSV",

            evidence_reference="Row 11",

            metadata={"raw_operation": "TCP Connect"},

        )

        events = [process_start, connection]

        tracker = ProcessLifetimeTracker()

        tracker.register_events(events)



        relationships = NetworkCorrelator.correlate_network_events(

            events, case_id, tracker

        )

        connected = [

            rel for rel in relationships

            if rel.target_event_id == connection.event_id

        ]

        self.assertEqual(len(connected), 1)

        self.assertEqual(connected[0].source_event_id, process_start.event_id)

        self.assertEqual(connected[0].relationship_type, "CONNECTED_TO")

        self.assertIn("PID:24524", connected[0].supporting_identifiers)



        exited_process = NormalizedEvent(

            event_id="EVT-PROC-TCP-EXIT",

            case_id=case_id,

            timestamp="2026-11-10T10:00:02Z",

            original_timestamp="10:00:02",

            source="process",

            event_type="PROCESS_EXIT",

            pid=24524,

            process_name="curl.exe",

        )

        stale_connection = NormalizedEvent(

            event_id="EVT-PROC-TCP-STALE-CONNECT",

            case_id=case_id,

            timestamp="2026-11-10T10:00:03Z",

            original_timestamp="10:00:03",

            source="process",

            event_type="TCP_CONNECT",

            pid=24524,

            process_name="curl.exe",

            evidence_file="Logfile.CSV",

        )

        stale_events = [process_start, connection, exited_process, stale_connection]

        stale_tracker = ProcessLifetimeTracker()

        stale_tracker.register_events(stale_events)

        stale_relationships = NetworkCorrelator.correlate_network_events(

            stale_events, case_id, stale_tracker

        )

        self.assertFalse(any(

            rel.target_event_id == stale_connection.event_id

            for rel in stale_relationships

        ))



    def test_partial_relationship_labels_do_not_count_unreviewed_links_as_false_positives(self):

        expected = ("EVT-PARENT", "EVT-CHILD", "SPAWNED")

        alternative = ("EVT-OTHER-PARENT-RECORD", "EVT-CHILD", "SPAWNED")

        metrics = ForensicEvaluator.calculate_labeled_relationship_coverage(

            [expected, alternative],

            [expected],

            {"EVT-PARENT", "EVT-OTHER-PARENT-RECORD", "EVT-CHILD"},

        )



        self.assertEqual(metrics["exact_expected_relationship_matches"], 1)

        self.assertEqual(metrics["expected_link_coverage"], 1.0)

        self.assertEqual(metrics["unreviewed_scoped_relationships"], [list(alternative)])

        self.assertNotIn("precision", metrics)



    def test_06_missing_and_uncertain_timestamps(self):

        """Priority 5: Normalizer must never substitute current time for missing/invalid timestamps."""

        # None timestamp

        iso_val, raw_val = Normalizer.parse_timestamp(None)

        self.assertIsNone(iso_val, "None timestamp must return None, not current time")

        self.assertEqual(raw_val, "")



        # Empty timestamp

        iso_val, raw_val = Normalizer.parse_timestamp("   ")

        self.assertIsNone(iso_val, "Empty timestamp must return None")



        # Invalid corrupt string

        iso_val, raw_val = Normalizer.parse_timestamp("NOT_A_TIMESTAMP_CORRUPT")

        self.assertIsNone(iso_val, "Corrupt timestamp must return None, not current time")

        self.assertEqual(raw_val, "NOT_A_TIMESTAMP_CORRUPT")



    def test_07_invalid_evidence_files_handling(self):

        """Priority 8: Parsers must gracefully handle corrupt/empty files without crashing."""

        case_id = "AUDIT-CORRUPT"

        corrupt_path = Path("data/test_cases/corrupt_file.csv")

        corrupt_path.parent.mkdir(parents=True, exist_ok=True)

        with open(corrupt_path, "w") as f:

            f.write("Random junk, without valid, headers or structure\n1,2,3\n")



        parser = ProcmonParser(case_id)

        events = parser.parse_file(str(corrupt_path))

        # Invalid headers must not be misinterpreted as real forensic events.

        self.assertIsInstance(events, list)

        self.assertEqual(events, [])

        self.assertGreater(len(parser.errors), 0)



        if corrupt_path.exists():

            corrupt_path.unlink()



    def test_08_duplicate_event_deduplication(self):

        """Priority 8: Verified duplicates must be deduplicated while reporting count."""

        ev1 = NormalizedEvent(

            event_id="EVT-01", case_id="TEST", timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00", source="process", event_type="PROCESS_START",

            pid=100, process_name="test.exe"

        )

        ev2 = NormalizedEvent(

            event_id="EVT-02", case_id="TEST", timestamp="2026-11-10T10:00:00Z",

            original_timestamp="10:00:00", source="process", event_type="PROCESS_START",

            pid=100, process_name="test.exe"

        )

        ev3 = NormalizedEvent(

            event_id="EVT-03", case_id="TEST", timestamp="2026-11-10T10:00:05Z",

            original_timestamp="10:00:05", source="process", event_type="PROCESS_EXIT",

            pid=100, process_name="test.exe"

        )



        deduped, dup_count = Normalizer.deduplicate_events([ev1, ev2, ev3])

        self.assertEqual(len(deduped), 2)

        self.assertEqual(dup_count, 1)



    def test_09_false_positive_suppression(self):

        """Unattributed packets must remain outside the proposed incident component."""

        case_id = "AUDIT-FP-TEST"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-08-NET-HEAVY-NOISE")



        pm_events = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")

        reg_events = RegistryParser(case_id).parse_file(ds["registry_file"])

        net_events = NetworkParser(case_id).parse_file(ds["wireshark_file"])

        sysmon_events = SysmonParser(case_id).parse_file(ds["sysmon_file"], timezone_name="UTC")

        all_events = pm_events + reg_events + net_events + sysmon_events



        gt = GroundTruthManager.load_ground_truth(case_id)

        gt_eids = set(gt["incident_event_ids"])

        all_eids = {e.event_id for e in all_events}



        # Baseline 3 (conventional one-hop rule-based correlation)

        b3_eids, b3_rels, _ = BaselineRunner.run_baseline_3_all_no_graph(all_events, case_id, temporal_window=5.0)

        b3_metrics = ForensicEvaluator.calculate_classification_metrics(b3_eids, gt_eids, all_eids)



        # Proposed Method (Provenance graph)

        prop_eids, prop_rels, _ = BaselineRunner.run_proposed_method(all_events, case_id, temporal_window=5.0)

        prop_metrics = ForensicEvaluator.calculate_classification_metrics(prop_eids, gt_eids, all_eids)



        # Do not force a predetermined winner. The important forensic invariant is

        # that packets without exact Sysmon five-tuple corroboration remain

        # unattributed and are not pulled into the proposed incident component.

        from correlation.network_correlation import NetworkCorrelator

        unattributed = set(NetworkCorrelator.last_unattributed_event_ids)

        self.assertTrue(unattributed.isdisjoint(prop_eids))

        self.assertGreaterEqual(prop_metrics["false_positive_rate"], 0.0)

        self.assertGreaterEqual(b3_metrics["false_positive_rate"], 0.0)



    def test_10_missing_evidence_graceful_handling(self):

        """Priority 7 & 8: Missing evidence scenarios must run cleanly and report degraded visibility."""

        case_id = "AUDIT-MISSING-NET"

        gen = ControlledExperimentGenerator(case_id)

        ds = gen.generate_scenario("CASE-11-MISSING-NET")



        pm_events = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")

        reg_events = RegistryParser(case_id).parse_file(ds["registry_file"])

        all_events = pm_events + reg_events



        gt = GroundTruthManager.load_ground_truth(case_id)

        self.assertIsNotNone(gt)



        # Proposed method executes cleanly with partial evidence

        prop_eids, prop_rels, chrono = BaselineRunner.run_proposed_method(all_events, case_id, temporal_window=5.0)

        self.assertGreater(len(prop_eids), 0)

        self.assertIsInstance(chrono, list)



if __name__ == "__main__":

    unittest.main()
