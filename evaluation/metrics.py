"""
Evaluation Metrics Module for U-15 Incident Reconstruction.
Calculates rigorous forensic performance metrics:
- Precision, Recall, F1-score, False Positive Rate (FPR)
- Relationship attribution accuracy
- Incident reconstruction accuracy
- Timeline ordering accuracy (Kendall's Tau rank correlation)
"""
from typing import Dict, Any, List, Set, Tuple
import numpy as np

class ForensicEvaluator:
    @staticmethod
    def calculate_classification_metrics(
        predicted_event_ids: Set[str],
        ground_truth_incident_ids: Set[str],
        all_event_ids: Set[str]
    ) -> Dict[str, float]:
        """
        Calculates event detection performance against documented ground truth.
        """
        tp = len(predicted_event_ids.intersection(ground_truth_incident_ids))
        fp = len(predicted_event_ids - ground_truth_incident_ids)
        fn = len(ground_truth_incident_ids - predicted_event_ids)
        
        benign_events = all_event_ids - ground_truth_incident_ids
        tn = len(benign_events - predicted_event_ids)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4)
        }

    @staticmethod
    def calculate_relationship_metrics(
        predicted_relationships: List[Tuple[str, str, str]],
        ground_truth_relationships: List[Tuple[str, str, str]]
    ) -> Dict[str, float]:
        """
        Evaluates relationship attribution: (source_id, target_id, type)
        """
        pred_set = set(predicted_relationships)
        gt_set = set(ground_truth_relationships)

        tp = len(pred_set.intersection(gt_set))
        fp = len(pred_set - gt_set)
        fn = len(gt_set - pred_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        accuracy = tp / len(gt_set) if len(gt_set) > 0 else (1.0 if len(pred_set) == 0 else 0.0)

        return {
            "rel_tp": tp,
            "rel_fp": fp,
            "rel_fn": fn,
            "rel_precision": round(precision, 4),
            "rel_recall": round(recall, 4),
            "rel_f1": round(f1, 4),
            "relationship_attribution_accuracy": round(accuracy, 4)
        }

    @staticmethod
    def calculate_labeled_relationship_coverage(
        predicted_relationships: List[Tuple[str, str, str]],
        ground_truth_relationships: List[Tuple[str, str, str]],
        labeled_event_ids: Set[str],
    ) -> Dict[str, Any]:
        """Measure exact expected-link coverage without treating unlabeled links as negatives."""
        expected = set(ground_truth_relationships)
        scoped_predictions = {
            relationship
            for relationship in predicted_relationships
            if relationship[0] in labeled_event_ids
            and relationship[1] in labeled_event_ids
        }
        matches = scoped_predictions & expected

        return {
            "expected_relationship_count": len(expected),
            "scoped_unique_prediction_count": len(scoped_predictions),
            "exact_expected_relationship_matches": len(matches),
            "expected_link_coverage": round(
                len(matches) / len(expected) if expected else 1.0,
                4,
            ),
            "unreviewed_scoped_relationships": [
                list(item) for item in sorted(scoped_predictions - expected)
            ],
            "missed_expected_relationships": [
                list(item) for item in sorted(expected - scoped_predictions)
            ],
        }

    @staticmethod
    def calculate_timeline_ordering_accuracy(
        predicted_ordered_ids: List[str],
        ground_truth_ordered_ids: List[str]
    ) -> float:
        """
        Calculates Kendall's Tau concordance between predicted timeline order
        and true ground truth execution chronology for incident events.
        """
        # Filter to events present in both
        common = [eid for eid in ground_truth_ordered_ids if eid in predicted_ordered_ids]
        if not common:
            return 0.0
        if len(common) <= 1:
            return 1.0

        pred_positions = {eid: idx for idx, eid in enumerate(predicted_ordered_ids)}
        y_pred = [pred_positions[eid] for eid in common]
        y_true = list(range(len(common)))

        # Calculate concordant and discordant pairs
        concordant = 0
        discordant = 0
        n = len(common)
        for i in range(n):
            for j in range(i + 1, n):
                sign_true = np.sign(y_true[i] - y_true[j])
                sign_pred = np.sign(y_pred[i] - y_pred[j])
                if sign_true * sign_pred > 0:
                    concordant += 1
                elif sign_true * sign_pred < 0:
                    discordant += 1

        total_pairs = n * (n - 1) / 2
        tau = (concordant - discordant) / total_pairs if total_pairs > 0 else 1.0
        # Normalize tau from [-1, 1] to [0, 1]
        normalized_accuracy = max(0.0, (tau + 1.0) / 2.0)
        return round(float(normalized_accuracy), 4)
