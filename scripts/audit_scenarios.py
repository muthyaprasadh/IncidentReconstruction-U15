import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from experiments.test_scenario_generator import ControlledExperimentGenerator, AVAILABLE_SCENARIOS
from experiments.dataset_catalog import dataset_type_for_scenario
from parsers.procmon_parser import ProcmonParser
from parsers.registry_parser import RegistryParser
from parsers.network_parser import NetworkParser
from parsers.sysmon_parser import SysmonParser
from pathlib import Path
import json

print(f"Auditing all {len(AVAILABLE_SCENARIOS)} scenarios:")
header = f"{'Scenario':<36} | {'Split':<12} | {'P':<3} {'R':<3} {'W':<3} {'S':<3} {'Tot':<4} | {'Dups':<4} | {'GT_Ev':<5} {'GT_Rel':<6}"
print(header)
print("-" * len(header))

for sc in AVAILABLE_SCENARIOS:
    case_id = f"AUDIT-{sc}"
    gen = ControlledExperimentGenerator(case_id)
    ds = gen.generate_scenario(sc)

    parsed = {}
    for fk, st, pc in [
        ("procmon_file", "process", ProcmonParser),
        ("registry_file", "registry", RegistryParser),
        ("wireshark_file", "network", NetworkParser),
        ("sysmon_file", "sysmon", SysmonParser),
    ]:
        fpath = ds.get(fk)
        if fpath and Path(fpath).exists():
            parser = pc(case_id)
            if st == "process":
                evs = parser.parse_file(str(fpath), base_date="2026-11-10", timezone_name="UTC")
            elif st == "network":
                evs = parser.parse_file(str(fpath), base_date="2026-11-10")
            elif st == "sysmon":
                evs = parser.parse_file(str(fpath), timezone_name="UTC")
            else:
                evs = parser.parse_file(str(fpath))
            parsed[st] = evs
        else:
            parsed[st] = []

    all_evs = [e for grp in parsed.values() for e in grp]
    eids = [e.event_id for e in all_evs]
    dups = len(eids) - len(set(eids))

    gt_path = gen.case_dir.parent.parent / "ground_truth" / f"{case_id}_ground_truth.json"
    gt_ev_count = 0
    gt_rel_count = 0
    if gt_path.exists():
        with open(gt_path, "r", encoding="utf-8") as f:
            gt_data = json.load(f)
            gt_ev_count = len(gt_data.get("incident_event_ids", []))
            gt_rel_count = len(gt_data.get("expected_relationships", []))

    dtype = dataset_type_for_scenario(sc)
    p_cnt = len(parsed["process"])
    r_cnt = len(parsed["registry"])
    w_cnt = len(parsed["network"])
    s_cnt = len(parsed["sysmon"])
    tot_cnt = len(all_evs)
    print(f"{sc:<36} | {dtype:<12} | {p_cnt:<3} {r_cnt:<3} {w_cnt:<3} {s_cnt:<3} {tot_cnt:<4} | {dups:<4} | {gt_ev_count:<5} {gt_rel_count:<6}")
