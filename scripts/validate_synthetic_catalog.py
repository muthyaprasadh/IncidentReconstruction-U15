"""Generate and validate all 22 synthetic scenario templates.

This is a software-validation utility, not a real-world forensic dataset
collection tool. It writes synthetic evidence and independent scenario labels.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database.db as db
from experiments.dataset_catalog import AVAILABLE_SCENARIOS, dataset_type_for_scenario
from experiments.test_scenario_generator import ControlledExperimentGenerator
from experiments.ground_truth_manager import GroundTruthManager
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.network_parser import NetworkParser
from parsers.sysmon_parser import SysmonParser


def main() -> None:
    db.init_db()
    rows = []
    for index, scenario in enumerate(AVAILABLE_SCENARIOS, 1):
        case_id = f"CATALOG-{index:02d}"
        ds = ControlledExperimentGenerator(case_id).generate_scenario(scenario)
        proc = ProcmonParser(case_id).parse_file(ds["procmon_file"], base_date="2026-11-10", timezone_name="UTC")
        reg = RegistryParser(case_id).parse_file(ds["registry_file"])
        wire = NetworkParser(case_id).parse_file(ds["wireshark_file"])
        sysmon = SysmonParser(case_id).parse_file(ds["sysmon_file"], timezone_name="UTC")
        events = proc + reg + wire + sysmon
        gt = GroundTruthManager.load_ground_truth(case_id) or {}
        parsed_ids = {e.event_id for e in events}
        gt_ids = set(gt.get("incident_event_ids", []))
        missing = sorted(gt_ids - parsed_ids)
        row = {
            "case_id": case_id,
            "scenario": scenario,
            "split": dataset_type_for_scenario(scenario),
            "synthetic": True,
            "procmon_events": len(proc),
            "registry_snapshot_entities": len(reg),
            "wireshark_packets": len(wire),
            "sysmon_events": len(sysmon),
            "parsed_events": len(events),
            "ground_truth_events": len(gt_ids),
            "unmatched_ground_truth_ids": missing,
            "validation_passed": not missing and bool(events),
        }
        rows.append(row)
        print(f"[{index:02d}/{len(AVAILABLE_SCENARIOS)}] {scenario}: {'PASS' if row['validation_passed'] else 'FAIL'}")

    dev = {r["case_id"] for r in rows if r["split"] == "development"}
    test = {r["case_id"] for r in rows if r["split"] == "held_out_test"}
    summary = {
        "dataset_type": "SYNTHETIC_SCENARIO_TEMPLATES_ONLY",
        "total_scenarios": len(rows),
        "development_scenarios": len(dev),
        "held_out_scenarios": len(test),
        "split_overlap": sorted(dev & test),
        "all_ground_truth_ids_mapped": all(r["validation_passed"] for r in rows),
        "scenarios": rows,
        "warning": "These are generated synthetic scenarios, not independently captured real Windows forensic traces.",
    }
    out = ROOT / "output" / "demo" / "synthetic_catalog_validation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "scenarios"}, indent=2))
    print(f"Detailed report: {out}")
    if not summary["all_ground_truth_ids_mapped"] or summary["split_overlap"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
