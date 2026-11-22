import json
from config.settings import DB_PATH
import database.db as db

CASES = [
    "CASE-20-20_HELD_OUT_MIXED",
    "CASE-22-22_HELD_OUT_MISSING_REG_NOISE"
]

EXPECTED_IDS = {
    "CASE-20-20_HELD_OUT_MIXED": [
        "EVT-PROC-procmon_events-R00006-301e18",
        "EVT-PROC-procmon_events-R00009-439fad",
        "EVT-REG-procmon_events-R00008-a915e9"
    ],
    "CASE-22-22_HELD_OUT_MISSING_REG_NOISE": [
        "EVT-PROC-procmon_events-R00006-301e18",
        "EVT-PROC-procmon_events-R00008-439fad"
    ]
}

for case_id in CASES:
    print("\n" + "=" * 90)
    print(case_id)
    print("=" * 90)

    events = db.get_events(case_id)
    relationships = db.get_relationships(case_id)

    selected = EXPECTED_IDS[case_id]

    print("\nRELEVANT EVENTS")

    for event in events:
        if event["event_id"] in selected:
            print(json.dumps(event, indent=2, default=str))

    print("\nALL PROCESS EVENTS")

    for event in events:
        if event["source"] == "process":
            print({
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "event_type": event["event_type"],
                "pid": event["pid"],
                "ppid": event["ppid"],
                "process_name": event["process_name"],
                "process_guid": event.get("process_guid"),
                "evidence_reference": event["evidence_reference"]
            })

    print("\nPREDICTED RELATIONSHIPS")

    for rel in relationships:
        print({
            "source": rel["source_event_id"],
            "target": rel["target_event_id"],
            "type": rel["relationship_type"],
            "category": rel["relationship_category"],
            "method": rel["correlation_method"],
            "explanation": rel["explanation"]
        })