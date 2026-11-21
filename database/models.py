"""
Data models and schemas for U-15 Incident Reconstruction platform.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
import json
from datetime import datetime, timezone

@dataclass
class Case:
    case_id: str
    name: str
    description: str = ""
    collection_date: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "Active"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class EvidenceFile:
    case_id: str
    source_type: str  # 'process', 'registry', 'network'
    file_name: str
    file_path: str
    file_size: int
    file_hash: str = ""
    uploaded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    record_count: int = 0
    status: str = "Uploaded"
    errors: str = ""
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class NormalizedEvent:
    event_id: str
    case_id: str
    timestamp: str  # ISO-8601 UTC string
    original_timestamp: str
    source: str     # 'process', 'registry', 'network'
    event_type: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: str = ""
    process_guid: str = ""
    registry_key: str = ""
    registry_operation: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = ""
    file_path: str = ""
    evidence_file: str = ""
    evidence_reference: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

@dataclass
class EventRelationship:
    source_event_id: str
    target_event_id: str
    relationship_type: str  # SPAWNED, MODIFIED, ACCESSED, CONNECTED_TO, OBSERVED_IN, TEMPORALLY_ASSOCIATED_WITH
    confidence_score: float  # 0.0 - 1.0
    correlation_method: str
    supporting_identifiers: List[str] = field(default_factory=list)
    evidence_sources: List[str] = field(default_factory=list)
    explanation: str = ""
    relationship_category: str = "Unknown"  # Directly observed, Strongly supported, Temporal association, Unattributed, Inferred, Unknown
    case_id: str = ""
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
