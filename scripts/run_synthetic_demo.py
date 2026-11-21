"""Run a clearly labelled synthetic end-to-end U-15 demonstration.

This script validates the software pipeline. It does NOT create real Windows
Procmon, Sysmon or Wireshark captures and its metrics must not be reported as
real-world research findings.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database.db as db
from config.settings import OUTPUT_DIR, GRAPHS_DIR, CHARTS_DIR
from experiments.test_scenario_generator import ControlledExperimentGenerator
from experiments.ground_truth_manager import GroundTruthManager
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.network_parser import NetworkParser
from parsers.sysmon_parser import SysmonParser
from correlation.correlation_engine import CorrelationEngine
from correlation.network_correlation import NetworkCorrelator
from graph.graph_builder import EvidenceGraphBuilder
from graph.graph_analyzer import EvidenceGraphAnalyzer
from reconstruction.timeline_generator import TimelineGenerator
from evaluation.baselines import BaselineRunner


def main() -> None:
    db.init_db()
    case_id = "DEMO-SYNTHETIC-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    generated = ControlledExperimentGenerator(case_id).generate_scenario("CASE-06-MULTI-ATTACK-01")

    proc = ProcmonParser(case_id).parse_file(generated["procmon_file"], base_date="2026-11-10", timezone_name="UTC")
    reg = RegistryParser(case_id).parse_file(generated["registry_file"])
    wire = NetworkParser(case_id).parse_file(generated["wireshark_file"])
    sysmon = SysmonParser(case_id).parse_file(generated["sysmon_file"], timezone_name="UTC")
    events = proc + reg + wire + sysmon

    relationships = CorrelationEngine(case_id, temporal_window=5.0).run(events, save_to_db=False)
    event_dicts = [asdict(e) for e in events]
    relationship_dicts = [asdict(r) for r in relationships]

    graph_builder = EvidenceGraphBuilder(case_id)
    graph = graph_builder.build_graph(event_dicts, relationship_dicts)
    graph_json = graph_builder.to_json_dict()
    graph_stats = EvidenceGraphAnalyzer(graph).get_summary_statistics()
    timeline = TimelineGenerator(event_dicts, relationship_dicts).generate_timeline()

    ground_truth = GroundTruthManager.load_ground_truth(case_id) or {}
    evaluation = BaselineRunner.evaluate_all_methods(
        events=events,
        case_id=case_id,
        ground_truth_incident_ids=set(ground_truth.get("incident_event_ids", [])),
        ground_truth_relationships=[tuple(x) for x in ground_truth.get("expected_relationships", [])],
        ground_truth_chronology=ground_truth.get("ground_truth_chronology", []),
        temporal_window=5.0,
    )

    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "demo").mkdir(parents=True, exist_ok=True)
    outputs = {
        "case_id": case_id,
        "dataset_type": "SYNTHETIC_DEMONSTRATION_ONLY",
        "warning": "Generated evidence is synthetic. Do not report these metrics as real Windows experiment results.",
        "counts": {
            "procmon_events": len(proc),
            "registry_snapshot_entities": len(reg),
            "wireshark_packets": len(wire),
            "sysmon_events": len(sysmon),
            "total_events": len(events),
            "relationships": len(relationships),
            "unattributed_packets": len(NetworkCorrelator.last_unattributed_event_ids),
        },
        "graph_statistics": graph_stats,
        "evaluation": evaluation,
    }
    (OUTPUT_DIR / "demo" / f"{case_id}_summary.json").write_text(json.dumps(outputs, indent=2), encoding="utf-8")
    (GRAPHS_DIR / f"{case_id}_graph.json").write_text(json.dumps(graph_json, indent=2, default=str), encoding="utf-8")
    (OUTPUT_DIR / "demo" / f"{case_id}_timeline.json").write_text(json.dumps(timeline, indent=2, default=str), encoding="utf-8")

    import csv
    with (CHARTS_DIR / f"{case_id}_evaluation.csv").open("w", newline="", encoding="utf-8") as f:
        if evaluation:
            writer = csv.DictWriter(f, fieldnames=list(evaluation[0].keys()))
            writer.writeheader()
            writer.writerows(evaluation)

    print(json.dumps(outputs, indent=2))
    print("\nSynthetic demo completed. Review output/demo, output/graphs and output/charts.")


if __name__ == "__main__":
    main()
