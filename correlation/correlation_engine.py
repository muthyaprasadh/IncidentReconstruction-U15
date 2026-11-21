"""
Cross-Artifact Correlation Engine for U-15 Incident Reconstruction.
Coordinates process, registry, and network correlators to construct explainable,
provenance-aware relationships across forensic artifacts.
"""
from typing import List, Dict, Any, Optional
from database.models import NormalizedEvent, EventRelationship
from correlation.process_correlation import ProcessLifetimeTracker, ProcessCorrelator
from correlation.registry_correlation import RegistryCorrelator
from correlation.network_correlation import NetworkCorrelator
from config.settings import DEFAULT_TIME_WINDOW_SECONDS, logger
import database.db as db

class CorrelationEngine:
    def __init__(
        self,
        case_id: str,
        temporal_window: float = DEFAULT_TIME_WINDOW_SECONDS,
        use_process_guid: bool = True,
        use_timestamp_matching: bool = True,
        use_registry_evidence: bool = True,
        use_five_tuple_matching: bool = True,
        use_lifetime_validation: bool = True,
    ):
        self.case_id = case_id
        self.temporal_window = temporal_window
        self.use_process_guid = use_process_guid
        self.use_timestamp_matching = use_timestamp_matching
        self.use_registry_evidence = use_registry_evidence
        self.use_five_tuple_matching = use_five_tuple_matching
        self.use_lifetime_validation = use_lifetime_validation
        self.tracker = ProcessLifetimeTracker(
            use_process_guid=use_process_guid,
            use_lifetime_validation=use_lifetime_validation,
        )

    def run(self, events: List[NormalizedEvent], save_to_db: bool = True) -> List[EventRelationship]:
        logger.info(
            "Starting cross-artifact correlation for case '%s' with %d events (window=%.1fs)",
            self.case_id, len(events), self.temporal_window
        )

        # 1. Register process lifetimes for PID reuse tracking
        self.tracker.register_events(events)

        all_relationships: List[EventRelationship] = []

        # 2. Process-to-Process correlation (SPAWNED)
        effective_process_window = (
            max(self.temporal_window, 30.0)
            if self.use_timestamp_matching
            else 100000.0
        )
        proc_rels = ProcessCorrelator.correlate_process_tree(
            events=events,
            case_id=self.case_id,
            tracker=self.tracker,
            window_seconds=effective_process_window
        )
        all_relationships.extend(proc_rels)

        # 3. Process-to-Registry correlation (MODIFIED, ACCESSED)
        if self.use_registry_evidence:
            reg_rels = RegistryCorrelator.correlate_registry_events(
                events=events,
                case_id=self.case_id,
                tracker=self.tracker,
                window_seconds=self.temporal_window
            )
            all_relationships.extend(reg_rels)

        # 4. Process-to-Network and Endpoint-to-Wire correlation (CONNECTED_TO, OBSERVED_IN, TEMPORALLY_ASSOCIATED_WITH)
        effective_window = self.temporal_window if self.use_timestamp_matching else 100000.0
        net_rels = NetworkCorrelator.correlate_network_events(
            events=events,
            case_id=self.case_id,
            tracker=self.tracker,
            window_seconds=effective_window,
            use_five_tuple_matching=self.use_five_tuple_matching,
        )
        all_relationships.extend(net_rels)

        # Deduplicate relationships by (source_event_id, target_event_id, relationship_type)
        deduped: List[EventRelationship] = []
        seen = set()
        for rel in all_relationships:
            key = (rel.source_event_id, rel.target_event_id, rel.relationship_type)
            if key not in seen:
                seen.add(key)
                deduped.append(rel)

        logger.info("Correlation finished: generated %d unique relationships", len(deduped))

        if save_to_db:
            db.clear_relationships_for_case(self.case_id)
            db.insert_relationships_batch(deduped)

        return deduped
