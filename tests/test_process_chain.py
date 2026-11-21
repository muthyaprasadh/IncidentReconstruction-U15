import pytest

from app.pages.incident_timeline import _build_process_chain


def make_event(event_id, name, pid):
    return {
        "event_id": event_id,
        "process_name": name,
        "pid": pid,
    }


def make_relationship(source, target, confidence=0.95, method="PID Match"):
    return {
        "relationship_type": "SPAWNED",
        "source_event_id": source,
        "target_event_id": target,
        "confidence_score": confidence,
        "correlation_method": method,
        "explanation": f"{source} spawned {target}",
    }


@pytest.fixture
def events():
    return {
        "A": make_event("A", "explorer.exe", 1000),
        "B": make_event("B", "powershell.exe", 2000),
        "C": make_event("C", "cmd.exe", 3000),
        "D": make_event("D", "conhost.exe", 4000),
        "E": make_event("E", "notepad.exe", 5000),
    }


def test_multiple_parent_relationships(events):
    relationships = [
        make_relationship("B", "C"),
        make_relationship("A", "C"),
    ]

    result = _build_process_chain("C", events, relationships)

    parents = [row for row in result if row["Direction"] == "Parent"]

    assert len(parents) == 2
    assert {row["Parent Process"] for row in parents} == {
        "explorer.exe",
        "powershell.exe",
    }


def test_multilevel_parent_and_child_traversal(events):
    relationships = [
        make_relationship("A", "B"),
        make_relationship("B", "C"),
        make_relationship("C", "D"),
        make_relationship("D", "E"),
    ]

    result = _build_process_chain("C", events, relationships)

    assert len(result) == 4
    assert sum(row["Direction"] == "Parent" for row in result) == 2
    assert sum(row["Direction"] == "Child" for row in result) == 2
    assert max(row["Depth"] for row in result) == 2


def test_cycle_prevention(events):
    relationships = [
        make_relationship("A", "B"),
        make_relationship("B", "A"),
    ]

    result = _build_process_chain("A", events, relationships)

    assert len(result) == 2
    assert {row["Depth"] for row in result} == {1, 2}
    assert len({(row["Source Event ID"], row["Target Event ID"]) for row in result}) == 2


def test_duplicate_relationships_are_not_repeated(events):
    relationships = [
        make_relationship("A", "B", 0.95, "Method One"),
        make_relationship("A", "B", 0.98, "Method Two"),
    ]

    result = _build_process_chain("A", events, relationships)

    assert len(result) == 1
    assert result[0]["Source Event ID"] == "A"
    assert result[0]["Target Event ID"] == "B"


@pytest.mark.parametrize(
    "confidence, expected_band",
    [
        (0.95, "High"),
        (0.90, "High"),
        (0.75, "Moderate"),
        (0.70, "Moderate"),
        (0.50, "Low"),
        (0.0, "Low"),
        (None, "Unavailable"),
        ("invalid", "Unavailable"),
    ],
)
def test_confidence_band_classification(events, confidence, expected_band):
    relationships = [make_relationship("A", "B", confidence)]

    result = _build_process_chain("A", events, relationships)

    assert len(result) == 1
    assert result[0]["Confidence Band"] == expected_band


def test_non_spawned_relationships_are_ignored(events):
    relationships = [
        {
            "relationship_type": "NETWORK_CONNECTION",
            "source_event_id": "A",
            "target_event_id": "B",
            "confidence_score": 0.99,
        }
    ]

    result = _build_process_chain("A", events, relationships)

    assert result == []


def test_missing_event_endpoints_are_ignored(events):
    relationships = [
        make_relationship("A", "UNKNOWN"),
        make_relationship("UNKNOWN", "B"),
    ]

    result = _build_process_chain("A", events, relationships)

    assert result == []


def test_max_depth_is_respected(events):
    relationships = [
        make_relationship("A", "B"),
        make_relationship("B", "C"),
        make_relationship("C", "D"),
    ]

    result = _build_process_chain(
        "A",
        events,
        relationships,
        max_depth=1,
    )

    assert len(result) == 1
    assert result[0]["Target Event ID"] == "B"
    assert result[0]["Depth"] == 1

