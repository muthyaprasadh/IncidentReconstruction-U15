"""
Validate independently collected real Windows forensic evidence before using it
as a research dataset. Synthetic evidence is not accepted by this validator.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GROUND_TRUTH_DIR = ROOT / "data" / "ground_truth"
RAW_REAL_DIR = ROOT / "data" / "raw" / "real_windows"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_case(case_dir: Path) -> dict:
    case_id = case_dir.name
    ground_truth_path = GROUND_TRUTH_DIR / f"{case_id}_ground_truth.json"
    if not ground_truth_path.exists():
        return {"case_id": case_id, "validation_passed": False, "error": "Independent ground truth JSON missing"}

    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    if ground_truth.get("independent_of_correlation_engine") is not True:
        return {"case_id": case_id, "validation_passed": False, "error": "Ground truth independence flag missing"}
    if ground_truth.get("dataset_type") not in ("real_world", "held_out_real_world"):
        return {"case_id": case_id, "validation_passed": False, "error": "dataset_type is not real_world"}

    required = ground_truth.get("evidence_mappings")
    if not isinstance(required, list) or not required:
        return {"case_id": case_id, "validation_passed": False, "error": "evidence_mappings is missing"}

    missing_hashes = []
    missing_files = []
    hashes = []
    for mapping in required:
        artifact = mapping.get("file_path")
        if not artifact:
            missing_files.append("<unspecified>")
            continue
        path = Path(artifact)
        if not path.is_absolute():
            path = ROOT / artifact
        if not path.exists():
            missing_files.append(str(path))
            continue
        actual = sha256(path)
        declared = mapping.get("sha256")
        hashes.append({"file": str(path), "sha256": actual})
        if declared and declared.lower() != actual.lower():
            missing_hashes.append(str(path))

    if missing_files or missing_hashes:
        return {
            "case_id": case_id,
            "validation_passed": False,
            "missing_files": missing_files,
            "hash_mismatches": missing_hashes,
        }

    incident_ids = ground_truth.get("incident_event_ids", [])
    chronology = ground_truth.get("ground_truth_chronology", [])
    relationships = ground_truth.get("expected_relationships", [])
    if not isinstance(incident_ids, list) or not isinstance(chronology, list) or not isinstance(relationships, list):
        return {"case_id": case_id, "validation_passed": False, "error": "Ground-truth fields have invalid types"}

    if set(chronology) - set(incident_ids):
        return {"case_id": case_id, "validation_passed": False, "error": "Chronology contains event IDs outside incident_event_ids"}

    return {
        "case_id": case_id,
        "validation_passed": True,
        "evidence_artifacts": len(hashes),
        "artifact_hashes": hashes,
        "ground_truth_event_count": len(incident_ids),
        "ground_truth_relationship_count": len(relationships),
    }


def main() -> int:
    RAW_REAL_DIR.mkdir(parents=True, exist_ok=True)
    case_dirs = [path for path in RAW_REAL_DIR.iterdir() if path.is_dir()] if RAW_REAL_DIR.exists() else []
    results = [validate_case(path) for path in case_dirs]

    output = ROOT / "output" / "demo" / "real_windows_validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "dataset_type": "REAL_WINDOWS_VALIDATION",
        "warning": "No case is valid until an independent ground-truth manifest and original artifact hashes pass.",
        "cases": results,
        "valid_case_count": sum(r["validation_passed"] for r in results),
    }, indent=2), encoding="utf-8")

    print(json.dumps({"valid_case_count": sum(r["validation_passed"] for r in results), "case_count": len(results), "report": str(output)}, indent=2))
    return 0 if all(r["validation_passed"] for r in results) else (1 if results else 0)


if __name__ == "__main__":
    raise SystemExit(main())
