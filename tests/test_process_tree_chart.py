import pytest
from app.components.charts import create_process_tree_chart


def make_event(event_id, name, pid, event_type="PROCESS_START"):
    return {
        "event_id": event_id,
        "source": "process",
        "process_name": name,
        "pid": pid,
        "event_type": event_type,
        "timestamp": "2026-11-21T10:00:00"
    }


def make_relationship(source_id, target_id, confidence=0.9):
    return {
        "relationship_type": "SPAWNED",
        "source_event_id": source_id,
        "target_event_id": target_id,
        "confidence_score": confidence,
        "correlation_method": "test",
        "explanation": "Test relationship"
    }


def test_empty_events():
    fig = create_process_tree_chart([], [])
    assert len(fig.data) == 0
    assert len(fig.layout.annotations) > 0


def test_empty_relationships():
    events = [make_event("E1", "parent.exe", 100)]
    fig = create_process_tree_chart(events, [])
    assert len(fig.data) == 0


def test_single_parent_child_relationship():
    events = [
        make_event("E1", "parent.exe", 100),
        make_event("E2", "child.exe", 200)
    ]
    relationships = [make_relationship("E1", "E2")]

    fig = create_process_tree_chart(events, relationships)

    assert fig.data[0].type == "sankey"
    assert len(fig.data[0].node.label) == 2
    assert len(fig.data[0].link.source) == 1


def test_multiple_parents_for_one_child():
    events = [
        make_event("E1", "parent_a.exe", 100),
        make_event("E2", "parent_b.exe", 200),
        make_event("E3", "child.exe", 300)
    ]
    relationships = [
        make_relationship("E1", "E3"),
        make_relationship("E2", "E3")
    ]

    fig = create_process_tree_chart(events, relationships)

    assert len(fig.data[0].node.label) == 3
    assert len(fig.data[0].link.source) == 2


def test_duplicate_process_names_remain_distinct_nodes():
    events = [
        make_event("E1", "worker.exe", 100),
        make_event("E2", "worker.exe", 200),
        make_event("E3", "child.exe", 300)
    ]
    relationships = [
        make_relationship("E1", "E3"),
        make_relationship("E2", "E3")
    ]

    fig = create_process_tree_chart(events, relationships)

    assert len(fig.data[0].node.label) == 3
    assert len(fig.data[0].link.source) == 2
    assert fig.data[0].link.source[0] != fig.data[0].link.source[1]


def test_relationships_with_missing_endpoints_are_ignored():
    events = [
        make_event("E1", "parent.exe", 100),
        make_event("E2", "child.exe", 200)
    ]
    relationships = [
        make_relationship("E1", "E2"),
        make_relationship("E1", "MISSING_EVENT"),
        make_relationship("MISSING_EVENT", "E2")
    ]

    fig = create_process_tree_chart(events, relationships)

    assert len(fig.data[0].link.source) == 1
    assert len(fig.data[0].link.target) == 1
