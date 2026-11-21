"""
Ablation Study Module for U-15 Incident Reconstruction.
Evaluates the impact of removing individual forensic correlation features:
A. Remove ProcessGuid matching.
B. Remove timestamp matching.
C. Remove Registry evidence.
D. Remove network five-tuple matching.
E. Remove process lifetime validation.
"""
from typing import List, Dict, Any, Set, Tuple
import copy
from database.models import NormalizedEvent, EventRelationship
from evaluation.baselines import BaselineRunner
from evaluation.metrics import ForensicEvaluator
from correlation.correlation_engine import CorrelationEngine
from correlation.process_correlation import ProcessLifetimeTracker
import networkx as nx


class AblationStudy:
    @staticmethod
    def run_ablation(
        events: List[NormalizedEvent],
        case_id: str,
        ground_truth_incident_ids: Set[str],
        ground_truth_relationships: List[Tuple[str, str, str]],
        temporal_window: float = 5.0
    ) -> List[Dict[str, Any]]:
        all_eids = {e.event_id for e in events}
        results = []

        # 1. Full Proposed Method
        pred_eids, pred_rels, _ = BaselineRunner.run_method_4_proposed_graph(
            events=events,
            case_id=case_id,
            temporal_window=temporal_window
        )
        c_m = ForensicEvaluator.calculate_classification_metrics(pred_eids, ground_truth_incident_ids, all_eids)
        r_m = ForensicEvaluator.calculate_relationship_metrics(pred_rels, ground_truth_relationships)
        results.append({
            "configuration": "Full Proposed Graph Method",
            "feature_ablated": "None (Full System)",
            "event_count": len(events),
            **c_m,
            **r_m
        })

        # 2. Ablation A: Remove ProcessGuid matching
        evs_no_guid = events

        pred_eids_a, pred_rels_a, _ = BaselineRunner.run_method_4_proposed_graph(
            events=evs_no_guid,
            case_id=case_id,
            temporal_window=temporal_window,
            correlation_options={"use_process_guid": False}
        )
        c_a = ForensicEvaluator.calculate_classification_metrics(pred_eids_a, ground_truth_incident_ids, all_eids)
        r_a = ForensicEvaluator.calculate_relationship_metrics(pred_rels_a, ground_truth_relationships)
        results.append({
            "configuration": "Ablation A: Remove ProcessGuid",
            "feature_ablated": "ProcessGuid Matching",
            "event_count": len(evs_no_guid),
            **c_a,
            **r_a
        })

        # 3. Ablation B: Remove timestamp matching (unbounded temporal window)
        pred_eids_b, pred_rels_b, _ = BaselineRunner.run_method_4_proposed_graph(
            events=events,
            case_id=case_id,
            temporal_window=temporal_window,
            correlation_options={"use_timestamp_matching": False}
        )
        c_b = ForensicEvaluator.calculate_classification_metrics(pred_eids_b, ground_truth_incident_ids, all_eids)
        r_b = ForensicEvaluator.calculate_relationship_metrics(pred_rels_b, ground_truth_relationships)
        results.append({
            "configuration": "Ablation B: Remove Timestamp Window",
            "feature_ablated": "Timestamp Temporal Windowing",
            "event_count": len(events),
            **c_b,
            **r_b
        })

        # 4. Ablation C: Remove Registry evidence
        evs_no_reg = [e for e in events if e.source != "registry"]
        pred_eids_c, pred_rels_c, _ = BaselineRunner.run_method_4_proposed_graph(
            events=evs_no_reg,
            case_id=case_id,
            temporal_window=temporal_window,
            correlation_options={"use_registry_evidence": False}
        )
        c_c = ForensicEvaluator.calculate_classification_metrics(pred_eids_c, ground_truth_incident_ids, all_eids)
        r_c = ForensicEvaluator.calculate_relationship_metrics(pred_rels_c, ground_truth_relationships)
        results.append({
            "configuration": "Ablation C: Remove Registry Evidence",
            "feature_ablated": "Registry Evidence Source",
            "event_count": len(evs_no_reg),
            **c_c,
            **r_c
        })

        # 5. Ablation D: Remove network five-tuple matching
        evs_no_net_tuples = []
        for e in events:
            cloned = copy.copy(e)
            if cloned.source == "network":
                cloned.src_port = None
                cloned.dst_port = None
                cloned.protocol = "UNKNOWN"
            evs_no_net_tuples.append(cloned)

        pred_eids_d, pred_rels_d, _ = BaselineRunner.run_method_4_proposed_graph(
            events=evs_no_net_tuples,
            case_id=case_id,
            temporal_window=temporal_window,
            correlation_options={"use_five_tuple_matching": False}
        )
        c_d = ForensicEvaluator.calculate_classification_metrics(pred_eids_d, ground_truth_incident_ids, all_eids)
        r_d = ForensicEvaluator.calculate_relationship_metrics(pred_rels_d, ground_truth_relationships)
        results.append({
            "configuration": "Ablation D: Remove 5-Tuple Matching",
            "feature_ablated": "Direction-Aware 5-Tuple Matching",
            "event_count": len(evs_no_net_tuples),
            **c_d,
            **r_d
        })

        # 6. Ablation E: Remove process lifetime validation
        # Create an engine that bypasses active epoch checks
        pred_eids_e, pred_rels_e, _ = BaselineRunner.run_method_4_proposed_graph(
            events=events,
            case_id=case_id,
            temporal_window=temporal_window,
            correlation_options={"use_lifetime_validation": False}
        )
        c_e = ForensicEvaluator.calculate_classification_metrics(pred_eids_e, ground_truth_incident_ids, all_eids)
        r_e = ForensicEvaluator.calculate_relationship_metrics(pred_rels_e, ground_truth_relationships)
        results.append({
            "configuration": "Ablation E: Remove Process Lifetime Validation",
            "feature_ablated": "Process Lifetime / Epoch Validation",
            "event_count": len(events),
            **c_e,
            **r_e
        })

        return results
