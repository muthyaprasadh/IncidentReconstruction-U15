from streamlit.testing.v1 import AppTest

from app.pages import incident_timeline


def test_source_selection_survives_page_navigation_and_filters_reset_page(monkeypatch):
    observed_counts = []
    observed_events = []
    source_counts = {
        None: 386_379,
        "process": 99_172,
        "registry": 267_237,
        "network": 19_970,
    }
    monkeypatch.setattr(
        incident_timeline.db,
        "get_case_by_id",
        lambda case_id: {"case_id": case_id, "name": "Test Case"},
    )

    def get_event_count(case_id, source=None, search=None):
        observed_counts.append((case_id, source, search))
        return 42 if search else source_counts[source]

    def get_events(case_id, source=None, search=None, limit=None, offset=0):
        observed_events.append((case_id, source, search, limit, offset))
        return []

    monkeypatch.setattr(incident_timeline.db, "get_event_count", get_event_count)
    monkeypatch.setattr(incident_timeline.db, "get_events", get_events)
    app = AppTest.from_string(
        """
import streamlit as st
from app.pages.incident_timeline import render_incident_timeline_page

page = st.radio("Route", ["Timeline", "Other"])
if page == "Timeline":
    render_incident_timeline_page()
"""
    )
    app.session_state["current_case_id"] = "CASE"
    app.run()

    def assert_filter(label, source, search, expected_count):
        assert app.selectbox[0].value == label
        assert app.session_state[incident_timeline.SOURCE_SELECTION_STATE_KEY] == label
        assert ("CASE", source, search) in observed_counts
        assert any(
            metric.label == "Matching Events"
            and metric.value == f"{expected_count:,}"
            for metric in app.metric
        )
        assert observed_events[-1][:3] == ("CASE", source, search)

    assert_filter("All Sources", None, "", 386_379)
    app.session_state["timeline_page"] = 4
    app.session_state[incident_timeline.DETAILS_STATE_KEY] = "previous-event"
    for label, source, expected_count in [
        ("Network", "network", 19_970),
        ("Process", "process", 99_172),
        ("Registry", "registry", 267_237),
        ("All Sources", None, 386_379),
        ("Network", "network", 19_970),
    ]:
        app.selectbox[0].select(label).run()
        assert_filter(label, source, "", expected_count)
        assert app.session_state["timeline_page"] == 0
        assert incident_timeline.DETAILS_STATE_KEY not in app.session_state

    app.text_input[0].set_value("chrome.exe").run()
    assert_filter("Network", "network", "chrome.exe", 42)

    app.radio[0].set_value("Other").run()
    assert incident_timeline.SOURCE_WIDGET_KEY not in app.session_state
    app.radio[0].set_value("Timeline").run()
    assert_filter("Network", "network", "", 19_970)

    app.selectbox[0].select("Registry").run()
    assert_filter("Registry", "registry", "", 267_237)
    app.selectbox[0].select("Process").run()
    assert_filter("Process", "process", "", 99_172)

    app.run()
    app.selectbox[0].select("Network").run()
    assert_filter("Network", "network", "", 19_970)


def test_page_query_and_csv_use_the_same_source_and_search(monkeypatch):
    calls = []

    def get_events(case_id, source=None, search=None, limit=None, offset=0):
        calls.append({
            "case_id": case_id,
            "source": source,
            "search": search,
            "limit": limit,
            "offset": offset,
        })
        return []

    monkeypatch.setattr(incident_timeline.db, "get_events", get_events)

    events, relationships, entries = incident_timeline._generate_page_timeline(
        "CASE", "network", "chrome.exe", 2
    )
    csv_data, exported_count = incident_timeline._generate_full_case_csv(
        "CASE", "network", "chrome.exe"
    )

    assert (events, relationships, entries) == ([], [], [])
    assert exported_count == 0
    assert calls == [
        {
            "case_id": "CASE",
            "source": "network",
            "search": "chrome.exe",
            "limit": incident_timeline.PAGE_SIZE,
            "offset": 2 * incident_timeline.PAGE_SIZE,
        },
        {
            "case_id": "CASE",
            "source": "network",
            "search": "chrome.exe",
            "limit": incident_timeline.EXPORT_BATCH_SIZE,
            "offset": 0,
        },
    ]
    assert csv_data.decode("utf-8-sig").startswith("Timestamp (UTC),Source,")


def test_invalid_saved_or_widget_source_is_reported_without_fallback(monkeypatch):
    monkeypatch.setattr(
        incident_timeline.db,
        "get_case_by_id",
        lambda case_id: {"case_id": case_id, "name": "Test Case"},
    )
    script = """
import streamlit as st
from app.pages.incident_timeline import render_incident_timeline_page
render_incident_timeline_page()
"""

    for key, value in [
        (incident_timeline.SOURCE_SELECTION_STATE_KEY, "Unknown Source"),
        (incident_timeline.SOURCE_WIDGET_KEY, "Unknown Source"),
    ]:
        app = AppTest.from_string(script)
        app.session_state["current_case_id"] = "CASE"
        app.session_state[key] = value
        app.run()
        assert any("Invalid" in error.value for error in app.error)


def test_timeline_relationship_details_render_only_when_opened():
    app = AppTest.from_string(
        """
import streamlit as st
from app.components.timeline import render_timeline_view
render_timeline_view(st.session_state["entries"])
"""
    )
    app.session_state["entries"] = [{
        "event_id": "event-1",
        "source": "process",
        "display_time": "2026-11-21T00:00:00Z",
        "description": "Test process event",
        "process_name": "test.exe",
        "pid": 42,
        "event_type": "PROCESS_START",
        "evidence_provenance": "test evidence",
        "link_count": 1,
        "related_links": [{
            "category": "Directly observed",
            "type": "SPAWNED",
            "confidence": 1.0,
            "explanation": "Deferred relationship detail",
        }],
        "raw_metadata": {"marker": "Deferred metadata"},
    }]
    app.run()

    assert not any(
        "Deferred relationship detail" in markdown.value
        for markdown in app.markdown
    )
    app.button[0].click().run()
    assert any(
        "Deferred relationship detail" in markdown.value
        for markdown in app.markdown
    )
    assert any(
        "Deferred metadata" in json_element.value
        for json_element in app.json
    )
