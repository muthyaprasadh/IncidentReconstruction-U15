"""
Research dataset split for U-15.
Cases are independent controlled experiments. Events from one case are never
split across development and held-out sets.
"""

DEVELOPMENT_SCENARIOS = [
    "CASE-01-BENIGN-PROC",
    "CASE-02-BENIGN-NET",
    "CASE-03-BENIGN-REG",
    "CASE-04-PROC-REG-BENIGN",
    "CASE-05-PROC-NET-BENIGN",
    "CASE-06-MULTI-ATTACK-01",
    "CASE-07-MULTI-ATTACK-02",
    "CASE-08-NET-HEAVY-NOISE",
    "CASE-09-REG-HEAVY-NOISE",
    "CASE-10-PID-REUSE",
    "CASE-11-MISSING-NET",
    "CASE-12-MISSING-REG",
    "CASE-13-MISSING-SOCK-TELEMETRY",
    "CASE-14-UNATTRIBUTED-WIRE",
    "CASE-15-REVERSE-PACKETS",
    "CASE-16-DEEP-PROCESS-TREE",
    "CASE-17-STAGED-PERSISTENCE",
    "CASE-18-DISCONNECTED-TEMPORAL",
    "CASE-19-CONCURRENT-PROCESSES",
]

HELD_OUT_SCENARIOS = [
    "CASE-20-HELD-OUT-MIXED",
    "CASE-21-HELD-OUT-PID-REUSE",
    "CASE-22-HELD-OUT-MISSING-REG-NOISE",
]

AVAILABLE_SCENARIOS = DEVELOPMENT_SCENARIOS + HELD_OUT_SCENARIOS


def dataset_type_for_scenario(scenario_id: str) -> str:
    if scenario_id in HELD_OUT_SCENARIOS:
        return "held_out_test"
    return "development"


def assert_no_cross_split(dev_case_ids, held_out_case_ids) -> None:
    overlap = set(dev_case_ids) & set(held_out_case_ids)
    if overlap:
        raise ValueError(f"Development and held-out case IDs overlap: {overlap}")
