"""
Experiment execution manifests recorded independently of the correlation engine.
Ground-truth labels are never derived from proposed-method predictions.
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from config.settings import EXPERIMENT_MANIFEST_DIR, logger


class ExperimentManifest:
    @staticmethod
    def path_for(case_id: str) -> Path:
        return EXPERIMENT_MANIFEST_DIR / f"{case_id}_manifest.json"

    @classmethod
    def save(
        cls,
        case_id: str,
        scenario: str,
        experiment_start: str,
        experiment_end: str,
        actual_process_actions: List[Dict[str, Any]],
        actual_registry_actions: List[Dict[str, Any]],
        actual_network_actions: List[Dict[str, Any]],
        expected_event_relationships: List[Any],
        expected_chronology: List[str],
        evidence_file_references: List[Dict[str, Any]],
        dataset_type: str,
        notes: str = "",
    ) -> Path:
        payload = {
            "case_id": case_id,
            "scenario": scenario,
            "experiment_start": experiment_start,
            "experiment_end": experiment_end,
            "actual_process_actions": actual_process_actions,
            "actual_registry_actions": actual_registry_actions,
            "actual_network_actions": actual_network_actions,
            "expected_event_relationships": expected_event_relationships,
            "expected_chronology": expected_chronology,
            "evidence_file_references": evidence_file_references,
            "dataset_type": dataset_type,
            "recorded_independently_of_correlation_engine": True,
            "notes": notes,
        }
        path = cls.path_for(case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info("Experiment manifest saved for case '%s' at %s", case_id, path)
        return path

    @classmethod
    def load(cls, case_id: str) -> Optional[Dict[str, Any]]:
        path = cls.path_for(case_id)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
