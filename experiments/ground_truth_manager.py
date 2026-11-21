"""
Ground Truth Manager for U-15 Incident Reconstruction.
Manages independently recorded ground-truth incident events, causal relationships,
and true chronological execution order.
Ensures ground truth is maintained strictly separate from parser and reconstruction outputs.
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional
from config.settings import GROUND_TRUTH_DIR, logger
from experiments.experiment_manifest import ExperimentManifest
import database.db as db

class GroundTruthManager:
    @staticmethod
    def get_ground_truth_path(case_id: str) -> Path:
        return GROUND_TRUTH_DIR / f"{case_id}_ground_truth.json"

    @classmethod
    def save_ground_truth(
        cls,
        case_id: str,
        scenario_name: str,
        incident_event_ids: List[str],
        expected_relationships: List[Tuple[str, str, str]],
        ground_truth_chronology: Optional[List[str]] = None,
        evidence_mappings: Optional[List[Dict[str, Any]]] = None,
        incident_phases: Optional[List[Dict[str, Any]]] = None,
        dataset_type: str = "development",  # 'development' or 'held_out_test'
        notes: str = "",
        origin: str = "experiment_manifest",
    ) -> Path:
        """
        Saves independent ground truth record to both JSON and SQLite.
        Maintains 100% reproducible mapping between evidence files, records, and ground truth.
        """
        if ground_truth_chronology is None:
            ground_truth_chronology = list(incident_event_ids)

        gt_data = {
            "case_id": case_id,
            "scenario_name": scenario_name,
            "dataset_type": dataset_type,
            "incident_event_ids": incident_event_ids,
            "expected_relationships": expected_relationships,
            "ground_truth_chronology": ground_truth_chronology,
            "evidence_mappings": evidence_mappings or [],
            "incident_phases": incident_phases or [],
            "notes": notes,
            "origin": origin,
            "independent_of_correlation_engine": True,
        }
        if origin == "proposed_method_predictions":
            raise ValueError("Ground truth must not be generated from proposed-method predictions.")

        # 1. Save JSON
        file_path = cls.get_ground_truth_path(case_id)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(gt_data, f, indent=2)

        # 2. Save SQLite
        db_records = []
        for eid in incident_event_ids:
            rel_matches = [
                {"source": r[0], "target": r[1], "type": r[2]}
                for r in expected_relationships if r[0] == eid or r[1] == eid
            ]
            db_records.append({
                "event_id": eid,
                "is_incident_related": 1,
                "activity_type": scenario_name,
                "expected_relationships": rel_matches
            })
        db.save_ground_truth(case_id, db_records)

        logger.info(
            "Ground truth saved for case '%s' (%d incident events, %d relationships, dataset=%s)",
            case_id, len(incident_event_ids), len(expected_relationships), dataset_type
        )
        return file_path

    @classmethod
    def load_ground_truth(cls, case_id: str) -> Optional[Dict[str, Any]]:
        """Loads ground truth from JSON file or SQLite fallback."""
        file_path = cls.get_ground_truth_path(case_id)
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Error loading ground truth file: %s", e)

        # Fallback to DB
        db_records = db.get_ground_truth(case_id)
        if db_records:
            incident_ids = [r["event_id"] for r in db_records if r.get("is_incident_related", 1) == 1]
            rels = []
            for r in db_records:
                for exp in r.get("expected_relationships", []):
                    tup = (exp["source"], exp["target"], exp["type"])
                    if tup not in rels:
                        rels.append(tup)
            return {
                "case_id": case_id,
                "scenario_name": db_records[0].get("activity_type", "Database Recorded"),
                "dataset_type": "development",
                "incident_event_ids": incident_ids,
                "expected_relationships": rels,
                "ground_truth_chronology": incident_ids,
                "evidence_mappings": []
            }
        return None
