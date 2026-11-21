"""
Unit and Integration Tests for U-15 Incident Reconstruction Platform.
"""
import unittest
from pathlib import Path
import json
import networkx as nx

from config.settings import TEST_CASES_DIR, GROUND_TRUTH_DIR
import database.db as db
from database.models import Case, EvidenceFile, NormalizedEvent, EventRelationship
from normalization.normalizer import Normalizer
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.network_parser import NetworkParser
from parsers.sysmon_parser import SysmonParser
from parsers.sysmon_parser import SysmonParser
from correlation.correlation_engine import CorrelationEngine
from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer
from app.components.graph_visualizer import render_plotly_network, render_pyvis_network
from reconstruction.timeline_generator import TimelineGenerator
from reconstruction.incident_narrative import IncidentNarrativeGenerator
from evaluation.baselines import BaselineRunner
from evaluation.ablation import AblationStudy
from evaluation.sensitivity import SensitivityAnalysis
from evaluation.metrics import ForensicEvaluator
from experiments.test_scenario_generator import ControlledExperimentGenerator
from experiments.ground_truth_manager import GroundTruthManager

class TestIncidentReconstructionBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case_id = "CASE-UNITTEST-01"
        # Create Case in DB
        case = Case(
            case_id=cls.case_id,
            name="Unit Test Investigation Case",
            description="Automated forensic test case verification",
            collection_date="2026-11-10"
        )
        db.create_case(case)

        # Generate controlled test dataset
        generator = ControlledExperimentGenerator(cls.case_id)
        cls.dataset = generator.generate_synthetic_incident_dataset(scenario_name="UnitTestAttackChain")

    def test_01_database_case_creation(self):
        c = db.get_case_by_id(self.case_id)
        self.assertIsNotNone(c)
        self.assertEqual(c["name"], "Unit Test Investigation Case")

    def test_02_normalization_routines(self):
        # Timestamp normalization
        iso_ts, orig_ts = Normalizer.parse_timestamp("10:15:30.500 AM")
        self.assertIsNone(iso_ts)
        self.assertEqual(orig_ts, "10:15:30.500 AM")
        complete_ts, _ = Normalizer.parse_timestamp(
            "10:15:30.500 AM", base_date="2026-11-10", timezone_name="UTC"
        )
        self.assertIn("10:15:30.500", complete_ts)

        # Process name normalization
        p_name = Normalizer.normalize_process_name(r"C:\Windows\System32\CMD.EXE")
        self.assertEqual(p_name, "cmd.exe")

        # Registry path normalization
        reg_p = Normalizer.normalize_registry_path(r"HKEY_CURRENT_USER\Software\IncidentLab\\")
        self.assertEqual(reg_p, r"HKCU\Software\IncidentLab")

        # IP and protocol normalization
        self.assertEqual(Normalizer.normalize_ip(" 192.168.1.1 "), "192.168.1.1")
        self.assertEqual(Normalizer.normalize_protocol("tcp_packet"), "TCP")

    def test_03_parsers(self):
        pm_parser = ProcmonParser(self.case_id)
        pm_events = pm_parser.parse_file(self.dataset["procmon_file"], base_date="2026-11-10", timezone_name="UTC")
        self.assertGreater(len(pm_events), 5)
        self.assertEqual(len(pm_parser.errors), 0)

        reg_parser = RegistryParser(self.case_id)
        reg_events = reg_parser.parse_file(self.dataset["registry_file"])
        self.assertGreater(len(reg_events), 0)
        self.assertEqual(len(reg_parser.errors), 0)

        net_parser = NetworkParser(self.case_id)
        net_events = net_parser.parse_file(self.dataset["wireshark_file"])
        self.assertGreater(len(net_events), 2)
        self.assertEqual(len(net_parser.errors), 0)

        sysmon_parser = SysmonParser(self.case_id)
        sysmon_events = sysmon_parser.parse_file(self.dataset["sysmon_file"], timezone_name="UTC")
        self.assertGreater(len(sysmon_events), 0)
        self.assertEqual(len(sysmon_parser.errors), 0)

        # Ingest every evidence source, including Sysmon process/socket telemetry.
        all_events = pm_events + reg_events + net_events + sysmon_events
        inserted = db.insert_events_batch(all_events)
        self.assertEqual(inserted, len(all_events))

    def test_04_cross_artifact_correlation(self):
        events_dicts = db.get_events(self.case_id)
        events = [NormalizedEvent(**{k: v for k, v in d.items() if k in NormalizedEvent.__annotations__}) for d in events_dicts]
        
        engine = CorrelationEngine(case_id=self.case_id, temporal_window=5.0)
        rels = engine.run(events, save_to_db=True)
        self.assertGreater(len(rels), 0)

        # Check for presence of SPAWNED, CONNECTED_TO, and MODIFIED
        rel_types = {r.relationship_type for r in rels}
        self.assertIn("SPAWNED", rel_types)
        self.assertIn("MODIFIED", rel_types)
        self.assertIn("CONNECTED_TO", rel_types)

        # Verify DB persistence of relationships
        db_rels = db.get_relationships(self.case_id)
        self.assertEqual(len(db_rels), len(rels))

    def test_05_evidence_graph(self):
        events = db.get_events(self.case_id)
        relationships = db.get_relationships(self.case_id)

        builder = EvidenceGraphBuilder(case_id=self.case_id)
        graph = builder.build_graph(events, relationships)
        self.assertGreater(graph.number_of_nodes(), 5)
        self.assertGreater(graph.number_of_edges(), 3)

        analyzer = EvidenceGraphAnalyzer(graph)
        stats = analyzer.get_summary_statistics()
        self.assertGreaterEqual(stats["node_count"], 5)
        self.assertGreater(stats["connected_clusters"], 0)
        directly_observed = analyzer.filter_subgraph(
            allowed_categories=["Directly observed"],
            allowed_node_types=["process", "registry", "network", "file", "event"],
        )
        self.assertGreater(directly_observed.number_of_nodes(), 0)

    def test_graph_path_limit_and_explanation_rendering(self):
        stored_events = db.get_events(self.case_id)
        stored_relationships = db.get_relationships(self.case_id)
        self.assertTrue(stored_relationships)
        scoped_relationships = db.get_relationships(
            self.case_id,
            event_ids=[
                stored_relationships[0]["source_event_id"],
                stored_relationships[0]["target_event_id"],
            ],
        )
        endpoint_ids = {
            stored_relationships[0]["source_event_id"],
            stored_relationships[0]["target_event_id"],
        }
        self.assertTrue(scoped_relationships)
        self.assertTrue(
            all(
                rel["source_event_id"] in endpoint_ids
                and rel["target_event_id"] in endpoint_ids
                for rel in scoped_relationships
            )
        )
        self.assertEqual(db.get_relationships(self.case_id, event_ids=[]), [])
        self.assertEqual(db.get_event_count(self.case_id), len(stored_events))
        correlated_events = db.get_most_correlated_events(self.case_id, limit=10)
        self.assertTrue(correlated_events)
        with self.assertRaises(ValueError):
            db.get_most_correlated_events(self.case_id, limit=0)
        latest_events = db.get_events(self.case_id, limit=10, newest_first=True)
        self.assertEqual(
            [event["timestamp"] for event in latest_events],
            sorted((event["timestamp"] for event in latest_events), reverse=True),
        )

        graph = nx.MultiDiGraph()
        graph.add_node("process:1", label="worker.exe")
        graph.add_node("network:1", label="192.0.2.1:443")
        graph.add_edge(
            "process:1",
            "network:1",
            relationship_type="CONNECTED_TO",
            relationship_category="Strongly supported",
            confidence_score=0.9,
            correlation_method="five_tuple",
            explanation="Matched Sysmon and packet evidence.",
            supporting_identifiers=["WireFrame:7"],
            title="Matched Sysmon and packet evidence. WireFrame:7",
        )
        graph.add_node("registry:1", label="HKCU\\Software\\Test")
        graph.add_node("orphan:1", label="unconnected.exe")
        graph.add_edge(
            "process:1",
            "registry:1",
            relationship_type="MODIFIED",
            relationship_category="Inferred",
            confidence_score=0.6,
        )
        graph.add_edge(
            "network:1",
            "registry:1",
            relationship_type="OBSERVED_IN",
            relationship_category="Inferred",
            confidence_score=0.6,
        )

        analyzer = EvidenceGraphAnalyzer(graph)
        paths = analyzer.find_causal_paths("process:1", "registry:1", max_paths=1)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][0], "process:1")
        self.assertEqual(paths[0][-1], "registry:1")
        self.assertEqual(analyzer.find_causal_paths("orphan:1", "registry:1"), [])
        with self.assertRaises(ValueError):
            analyzer.find_causal_paths("process:1", "registry:1", max_paths=0)

        figure = render_plotly_network(graph)
        edge_hover_text = figure.data[0].text
        self.assertTrue(any("Matched Sysmon and packet evidence." in text for text in edge_hover_text))
        self.assertTrue(any("WireFrame:7" in text for text in edge_hover_text))
        self.assertIn("Matched Sysmon and packet evidence.", render_pyvis_network(graph))

    def test_06_timeline_and_narrative(self):
        events = db.get_events(self.case_id)
        relationships = db.get_relationships(self.case_id)

        timeline_gen = TimelineGenerator(events, relationships)
        timeline = timeline_gen.generate_timeline()
        self.assertEqual(len(timeline), len(events))

        narrative_gen = IncidentNarrativeGenerator(timeline, relationships)
        narrative = narrative_gen.generate_narrative()
        self.assertIn("chronological_story", narrative)
        self.assertTrue(len(narrative["story_lines"]) > 0)
        self.assertIn("FORENSIC OBJECTIVITY DISCLAIMER", narrative["forensic_disclaimer"])

    def test_07_evaluation_and_ground_truth(self):
        gt = GroundTruthManager.load_ground_truth(self.case_id)
        self.assertIsNotNone(gt)
        self.assertGreater(len(gt["incident_event_ids"]), 0)

        events_dicts = db.get_events(self.case_id)
        events = [NormalizedEvent(**{k: v for k, v in d.items() if k in NormalizedEvent.__annotations__}) for d in events_dicts]
        gt_eids = set(gt["incident_event_ids"])
        gt_rels = [tuple(r) for r in gt["expected_relationships"]]

        # 1. Baselines
        b1_eids, b1_rels, _ = BaselineRunner.run_baseline_1_process_only(events, self.case_id)
        b1_metrics = ForensicEvaluator.calculate_classification_metrics(b1_eids, gt_eids, {e.event_id for e in events})

        prop_eids, prop_rels, _ = BaselineRunner.run_proposed_method(events, self.case_id)
        prop_metrics = ForensicEvaluator.calculate_classification_metrics(prop_eids, gt_eids, {e.event_id for e in events})

        # Multi-source proposed method must have higher or equal recall than isolated process analysis
        self.assertGreaterEqual(prop_metrics["recall"], b1_metrics["recall"])

        # 2. Ablation (5 ablations A-E + Full Proposed Method baseline = 6 configurations)
        ablation_results = AblationStudy.run_ablation(events, self.case_id, gt_eids, gt_rels)
        self.assertGreaterEqual(len(ablation_results), 4)

        # 3. Sensitivity
        sensitivity_results = SensitivityAnalysis.run_sensitivity(events, self.case_id, gt_eids, gt_rels)
        self.assertGreater(len(sensitivity_results), 0)

if __name__ == "__main__":
    unittest.main()
