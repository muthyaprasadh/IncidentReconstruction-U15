"""
Configuration and settings for U-15 Cross-Artifact Incident Reconstruction platform.
"""
from pathlib import Path
import os
import logging

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
GROUND_TRUTH_DIR = DATA_DIR / "ground_truth"
TEST_CASES_DIR = DATA_DIR / "test_cases"
EXPERIMENT_MANIFEST_DIR = DATA_DIR / "experiment_manifests"

OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"
GRAPHS_DIR = OUTPUT_DIR / "graphs"
CHARTS_DIR = OUTPUT_DIR / "charts"

DATABASE_DIR = BASE_DIR / "database"
DB_PATH = DATABASE_DIR / "forensics.db"

# Ensure all primary runtime directories exist
for directory in [
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    GROUND_TRUTH_DIR,
    TEST_CASES_DIR,
    EXPERIMENT_MANIFEST_DIR,
    REPORTS_DIR,
    GRAPHS_DIR,
    CHARTS_DIR,
    DATABASE_DIR,
]:
    directory.mkdir(parents=True, exist_ok=True)

# Forensic Schema Definitions
NORMALIZED_EVENT_SCHEMA = {
    "event_id": str,
    "case_id": str,
    "timestamp": str,            # ISO-8601 UTC string
    "original_timestamp": str,   # Raw original string from artifact
    "source": str,               # 'process', 'registry', 'network'
    "event_type": str,           # 'PROCESS_START', 'REG_SET_VALUE', 'NET_CONNECT', etc.
    "pid": (int, type(None)),
    "ppid": (int, type(None)),
    "process_name": str,
    "process_guid": str,
    "registry_key": str,
    "registry_operation": str,
    "src_ip": str,
    "dst_ip": str,
    "src_port": (int, type(None)),
    "dst_port": (int, type(None)),
    "protocol": str,
    "file_path": str,
    "evidence_file": str,
    "evidence_reference": str,   # e.g., line number, packet index
    "metadata": dict
}

# Relationship Categories as specified in research criteria
RELATIONSHIP_CATEGORIES = [
    "Directly observed",
    "Strongly supported",
    "Temporal association",
    "Unattributed",
    "Inferred",
    "Unknown"
]

RELATIONSHIP_TYPES = [
    "SPAWNED",
    "MODIFIED",
    "ACCESSED",
    "CONNECTED_TO",
    "OBSERVED_IN",
    "TEMPORALLY_ASSOCIATED_WITH"
]

# Evaluation Configuration
DEFAULT_TIME_WINDOW_SECONDS = 5.0
SENSITIVITY_WINDOWS = [1.0, 5.0, 10.0, 30.0]

# Safe test environment registry path for controlled experiments
TEST_REGISTRY_SUBKEY = r"Software\IncidentLab"

# Logging setup
LOG_FORMAT = "%(asctime)s - [%(levelname)s] - %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("IncidentReconstruction")
