"""
Sensitivity Analysis Module for U-15 Incident Reconstruction.
Evaluates the impact of:
- Different temporal correlation windows (±1s, ±5s, ±10s, ±30s)
- Missing evidence (network, registry, socket telemetry)
- PID reuse
- Concurrent processes
- Network noise
"""
from typing import List, Dict, Any, Set, Tuple
from database.models import NormalizedEvent
from evaluation.baselines import BaselineRunner
from evaluation.metrics import ForensicEvaluator
from config.settings import SENSITIVITY_WINDOWS


class SensitivityAnalysis:
    @staticmethod
    def run_sensitivity(
        events: List[NormalizedEvent],
        case_id: str,
        ground_truth_incident_ids: Set[str],
        ground_truth_relationships: List[Tuple[str, str, str]],
        windows: List[float] = SENSITIVITY_WINDOWS
    ) -> List[Dict[str, Any]]:
        all_eids = {e.event_id for e in events}
        results = []

        for w in windows:
            # 1. Baseline 3 (Rule-Based, No Graph)
            b3_eids, b3_rels, _ = BaselineRunner.run_method_3_rule_based(events, case_id, temporal_window=w)
            b3_class = ForensicEvaluator.calculate_classification_metrics(b3_eids, ground_truth_incident_ids, all_eids)
            b3_rel = ForensicEvaluator.calculate_relationship_metrics(b3_rels, ground_truth_relationships)

            results.append({
                "method": "Method 3: Rule-Based (No Graph)",
                "window_seconds": w,
                "window_label": f"±{w:.0f}s",
                "condition": f"Temporal Window ±{w:.0f}s",
                **b3_class,
                **b3_rel
            })

            # 2. Proposed Method (Graph Provenance)
            prop_eids, prop_rels, _ = BaselineRunner.run_method_4_proposed_graph(events, case_id, temporal_window=w)
            prop_class = ForensicEvaluator.calculate_classification_metrics(prop_eids, ground_truth_incident_ids, all_eids)
            prop_rel = ForensicEvaluator.calculate_relationship_metrics(prop_rels, ground_truth_relationships)

            results.append({
                "method": "Method 4: Proposed Graph",
                "window_seconds": w,
                "window_label": f"±{w:.0f}s",
                "condition": f"Temporal Window ±{w:.0f}s",
                **prop_class,
                **prop_rel
            })

        return results

    @staticmethod
    def run_stress_sensitivity(
        stress_scenarios_data: List[Dict[str, Any]],
        temporal_window: float = 5.0
    ) -> List[Dict[str, Any]]:
        """
        Evaluates Proposed Method vs Baseline 3 across forensic stress conditions:
        - Missing evidence (net, reg, socket)
        - PID reuse
        - Concurrent processes
        - Network noise
        """
        results = []
        for item in stress_scenarios_data:
            scenario_name = item["scenario_name"]
            condition_type = item.get("condition_type", "Stress Condition")
            events = item["events"]
            case_id = item.get("case_id", scenario_name)
            gt_eids = set(item.get("ground_truth_incident_ids", []))
            gt_rels = item.get("ground_truth_relationships", [])
            all_eids = {e.event_id for e in events}

            # Method 3
            m3_eids, m3_rels, _ = BaselineRunner.run_method_3_rule_based(events, case_id, temporal_window)
            m3_c = ForensicEvaluator.calculate_classification_metrics(m3_eids, gt_eids, all_eids)
            m3_r = ForensicEvaluator.calculate_relationship_metrics(m3_rels, gt_rels)
            results.append({
                "scenario": scenario_name,
                "condition": condition_type,
                "method": "Method 3: Rule-Based",
                **m3_c,
                **m3_r
            })

            # Method 4 (Proposed)
            m4_eids, m4_rels, _ = BaselineRunner.run_method_4_proposed_graph(events, case_id, temporal_window)
            m4_c = ForensicEvaluator.calculate_classification_metrics(m4_eids, gt_eids, all_eids)
            m4_r = ForensicEvaluator.calculate_relationship_metrics(m4_rels, gt_rels)
            results.append({
                "scenario": scenario_name,
                "condition": condition_type,
                "method": "Method 4: Proposed Graph",
                **m4_c,
                **m4_r
            })

        return results
