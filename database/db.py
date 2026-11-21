"""
hai
Database access and management module for U-15 Incident Reconstruction.
Uses SQLite for zero-configuration, robust local forensic evidence persistence.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import hashlib

from config.settings import DB_PATH, logger
from database.models import Case, EvidenceFile, NormalizedEvent, EventRelationship

def get_db_connection() -> sqlite3.Connection:
    """Creates a connection with Row factory enabled."""
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Initializes all database tables, indexes, and ensures composite primary key migration."""
    conn = get_db_connection()
    try:
        # Schema migration check: ensure events table has composite PRIMARY KEY (case_id, event_id)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events';")
        if cursor.fetchone():
            cursor = conn.execute("PRAGMA table_info(events);")
            cols = cursor.fetchall()
            pk_cols = [c["name"] for c in cols if c["pk"] > 0]
            if pk_cols != ["case_id", "event_id"] and pk_cols != ["event_id", "case_id"]:
                logger.info("Migrating events and relationships tables to composite primary key (case_id, event_id)...")
                conn.execute("PRAGMA foreign_keys = OFF;")
                with conn:
                    conn.execute("""
                    CREATE TABLE IF NOT EXISTS events_migrated (
                        event_id TEXT NOT NULL,
                        case_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        original_timestamp TEXT,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        pid INTEGER,
                        ppid INTEGER,
                        process_name TEXT,
                        registry_key TEXT,
                        registry_operation TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        file_path TEXT,
                        evidence_file TEXT,
                        evidence_reference TEXT,
                        metadata_json TEXT,
                        process_guid TEXT,
                        PRIMARY KEY (case_id, event_id),
                        FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE
                    );
                    """)
                    conn.execute("""
                    INSERT OR IGNORE INTO events_migrated (
                        event_id, case_id, timestamp, original_timestamp, source, event_type,
                        pid, ppid, process_name, registry_key, registry_operation,
                        src_ip, dst_ip, src_port, dst_port, protocol, file_path,
                        evidence_file, evidence_reference, metadata_json, process_guid
                    ) SELECT 
                        event_id, case_id, timestamp, original_timestamp, source, event_type,
                        pid, ppid, process_name, registry_key, registry_operation,
                        src_ip, dst_ip, src_port, dst_port, protocol, file_path,
                        evidence_file, evidence_reference, metadata_json, process_guid
                    FROM events;
                    """)

                    conn.execute("""
                    CREATE TABLE IF NOT EXISTS relationships_migrated (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT NOT NULL,
                        source_event_id TEXT NOT NULL,
                        target_event_id TEXT NOT NULL,
                        relationship_type TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        correlation_method TEXT NOT NULL,
                        supporting_identifiers TEXT,
                        evidence_sources TEXT,
                        explanation TEXT,
                        relationship_category TEXT NOT NULL,
                        FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE,
                        FOREIGN KEY (case_id, source_event_id) REFERENCES events (case_id, event_id) ON DELETE CASCADE,
                        FOREIGN KEY (case_id, target_event_id) REFERENCES events (case_id, event_id) ON DELETE CASCADE
                    );
                    """)
                    conn.execute("""
                    INSERT INTO relationships_migrated (
                        id, case_id, source_event_id, target_event_id, relationship_type,
                        confidence_score, correlation_method, supporting_identifiers,
                        evidence_sources, explanation, relationship_category
                    ) SELECT 
                        id, case_id, source_event_id, target_event_id, relationship_type,
                        confidence_score, correlation_method, supporting_identifiers,
                        evidence_sources, explanation, relationship_category
                    FROM relationships;
                    """)

                    conn.execute("DROP TABLE relationships;")
                    conn.execute("ALTER TABLE relationships_migrated RENAME TO relationships;")
                    conn.execute("DROP TABLE events;")
                    conn.execute("ALTER TABLE events_migrated RENAME TO events;")
                conn.execute("PRAGMA foreign_keys = ON;")
                logger.info("Composite primary key migration completed successfully.")

        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                collection_date TEXT,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'Active'
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT,
                uploaded_at TEXT NOT NULL,
                record_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'Uploaded',
                errors TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                original_timestamp TEXT,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                pid INTEGER,
                ppid INTEGER,
                process_name TEXT,
                registry_key TEXT,
                registry_operation TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                file_path TEXT,
                evidence_file TEXT,
                evidence_reference TEXT,
                metadata_json TEXT,
                process_guid TEXT,
                PRIMARY KEY (case_id, event_id),
                FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE
            );
            """)
            try:
                conn.execute("ALTER TABLE events ADD COLUMN process_guid TEXT;")
            except sqlite3.OperationalError:
                pass

            conn.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                source_event_id TEXT NOT NULL,
                target_event_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                correlation_method TEXT NOT NULL,
                supporting_identifiers TEXT,
                evidence_sources TEXT,
                explanation TEXT,
                relationship_category TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (case_id, source_event_id) REFERENCES events (case_id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (case_id, target_event_id) REFERENCES events (case_id, event_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_runs (
                run_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                method TEXT NOT NULL,
                temporal_window REAL NOT NULL,
                metrics_json TEXT NOT NULL,
                run_timestamp TEXT NOT NULL,
                notes TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS ground_truth_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                is_incident_related INTEGER DEFAULT 1,
                activity_type TEXT,
                expected_relationships_json TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE CASCADE
            );
            """)

            # Performance indexes for fast forensic filtering and graph correlation queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON events (case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events (timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events (source);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_pid ON events (pid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_process ON events (process_name);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_case ON relationships (case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships (source_event_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships (target_event_id);")
        logger.info("Database initialized successfully at %s", DB_PATH)
    finally:
        conn.close()

# Case CRUD operations
def create_case(case: Case) -> bool:
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, name, description, collection_date, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case.case_id, case.name, case.description, case.collection_date, case.created_at, case.status)
            )
        return True
    except sqlite3.IntegrityError as e:
        logger.error("Failed to create case: %s", e)
        return False
    finally:
        conn.close()

def get_all_cases() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM cases ORDER BY created_at DESC;")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def delete_case(case_id: str) -> bool:
    conn = get_db_connection()
    try:
        with conn:
            # Foreign key cascade handles children when PRAGMA foreign_keys = ON
            conn.execute("DELETE FROM cases WHERE case_id = ?;", (case_id,))
        return True
    except Exception as e:
        logger.error("Error deleting case %s: %s", case_id, e)
        return False
    finally:
        conn.close()

# Evidence File operations
def add_evidence_file(ev: EvidenceFile) -> int:
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO evidence_files (case_id, source_type, file_name, file_path, file_size, file_hash, uploaded_at, record_count, status, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ev.case_id, ev.source_type, ev.file_name, ev.file_path, ev.file_size, ev.file_hash, ev.uploaded_at, ev.record_count, ev.status, ev.errors)
            )
            return cursor.lastrowid or 0
    finally:
        conn.close()

def get_evidence_files(case_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM evidence_files WHERE case_id = ? ORDER BY uploaded_at ASC;", (case_id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def update_evidence_file_stats(file_id: int, record_count: int, status: str, errors: str = ""):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE evidence_files SET record_count = ?, status = ?, errors = ? WHERE id = ?;",
                (record_count, status, errors, file_id)
            )
    finally:
        conn.close()

# Events batch operations
def insert_events_batch(events: List[NormalizedEvent]) -> int:
    if not events:
        return 0
    conn = get_db_connection()
    inserted = 0
    try:
        with conn:
            for ev in events:
                try:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO events (
                            event_id, case_id, timestamp, original_timestamp, source, event_type,
                            pid, ppid, process_name, registry_key, registry_operation,
                            src_ip, dst_ip, src_port, dst_port, protocol, file_path,
                            evidence_file, evidence_reference, metadata_json, process_guid
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ev.event_id, ev.case_id, ev.timestamp, ev.original_timestamp, ev.source, ev.event_type,
                            ev.pid, ev.ppid, ev.process_name, ev.registry_key, ev.registry_operation,
                            ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port, ev.protocol, ev.file_path,
                            ev.evidence_file, ev.evidence_reference, json.dumps(ev.metadata or {}),
                            getattr(ev, "process_guid", "") or (ev.metadata or {}).get("ProcessGuid", "")
                        )
                    )
                    inserted += 1
                except sqlite3.Error as e:
                    logger.warning("Could not insert event %s: %s", ev.event_id, e)
        return inserted
    finally:
        conn.close()


def replace_case_ingestion(
    case_id: str,
    events: List[NormalizedEvent],
    evidence_files: List[EvidenceFile]
) -> Tuple[int, int]:
    """
    Atomically replace a case's ingested events and evidence-file records.
    Ground-truth records and evaluation history are deliberately untouched.
    Any database error rolls the entire replacement back.
    """
    if not case_id or not isinstance(case_id, str):
        raise ValueError("A valid non-empty case_id must be provided.")

    if any(ev.case_id != case_id for ev in events):
        raise ValueError(f"Every event must belong to target case '{case_id}'.")

    if any(ev.case_id != case_id for ev in evidence_files):
        raise ValueError(f"Every evidence file must belong to target case '{case_id}'.")

    # Pre-validate events and check for duplicate event IDs before altering database state
    seen_ids = set()
    duplicates = []
    for ev in events:
        if not ev.event_id or not isinstance(ev.event_id, str):
            raise ValueError(f"Invalid or missing event_id in event record: {ev}")
        if ev.event_id in seen_ids:
            duplicates.append(ev.event_id)
        seen_ids.add(ev.event_id)

    if duplicates:
        raise ValueError(
            f"Duplicate event IDs detected before database insertion ({len(duplicates)} duplicates): {duplicates[:5]}"
        )

    # Pre-validate evidence-file metadata
    for ef in evidence_files:
        if not ef.file_name or not ef.file_path:
            raise ValueError(f"Evidence file missing file_name or file_path: {ef}")
        if ef.file_size < 0:
            raise ValueError(f"Invalid negative file_size for evidence file: {ef.file_name}")

    conn = get_db_connection()
    try:
        with conn:
            # 1. Clear previous case evidence records atomically
            conn.execute("DELETE FROM relationships WHERE case_id = ?;", (case_id,))
            conn.execute("DELETE FROM events WHERE case_id = ?;", (case_id,))
            conn.execute("DELETE FROM evidence_files WHERE case_id = ?;", (case_id,))

            # 2. Insert new normalized events
            event_tuples = [
                (
                    ev.event_id, ev.case_id, ev.timestamp, ev.original_timestamp,
                    ev.source, ev.event_type, ev.pid, ev.ppid, ev.process_name,
                    ev.registry_key, ev.registry_operation, ev.src_ip, ev.dst_ip,
                    ev.src_port, ev.dst_port, ev.protocol, ev.file_path,
                    ev.evidence_file, ev.evidence_reference,
                    json.dumps(ev.metadata or {}),
                    getattr(ev, "process_guid", "") or (ev.metadata or {}).get("ProcessGuid", "")
                )
                for ev in events
            ]

            conn.executemany(
                """
                INSERT INTO events (
                    event_id, case_id, timestamp, original_timestamp, source, event_type,
                    pid, ppid, process_name, registry_key, registry_operation,
                    src_ip, dst_ip, src_port, dst_port, protocol, file_path,
                    evidence_file, evidence_reference, metadata_json, process_guid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                event_tuples
            )

            # 3. Insert new evidence files
            file_tuples = [
                (
                    ef.case_id, ef.source_type, ef.file_name, ef.file_path,
                    ef.file_size, ef.file_hash, ef.uploaded_at,
                    ef.record_count, ef.status, ef.errors
                )
                for ef in evidence_files
            ]

            conn.executemany(
                """
                INSERT INTO evidence_files (
                    case_id, source_type, file_name, file_path, file_size,
                    file_hash, uploaded_at, record_count, status, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                file_tuples
            )

        logger.info(
            "Case '%s' ingestion committed atomically: %d events, %d evidence files.",
            case_id, len(events), len(evidence_files)
        )
        return len(events), len(evidence_files)
    except Exception as e:
        logger.error(
            "replace_case_ingestion failed for case '%s': %s",
            case_id, e, exc_info=True
        )
        raise
    finally:
        conn.close()

def get_events(case_id: str, source: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        query = "SELECT * FROM events WHERE case_id = ?"
        params: List[Any] = [case_id]
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY timestamp ASC"
        if limit:
            query += f" LIMIT {int(limit)}"
        cursor = conn.execute(query, tuple(params))
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            d["metadata"] = json.loads(d["metadata_json"]) if d.get("metadata_json") else {}
            if not d.get("process_guid"):
                d["process_guid"] = d["metadata"].get("ProcessGuid") or d["metadata"].get("process_guid") or ""
            results.append(d)
        return results
    finally:
        conn.close()

def get_event_by_id(event_id: str, case_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        if case_id:
            cursor = conn.execute("SELECT * FROM events WHERE event_id = ? AND case_id = ?;", (event_id, case_id))
        else:
            cursor = conn.execute("SELECT * FROM events WHERE event_id = ?;", (event_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d["metadata_json"]) if d.get("metadata_json") else {}
        if not d.get("process_guid"):
            d["process_guid"] = d["metadata"].get("ProcessGuid") or d["metadata"].get("process_guid") or ""
        return d
    finally:
        conn.close()

def clear_events_for_case(case_id: str):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM events WHERE case_id = ?;", (case_id,))
            conn.execute("DELETE FROM relationships WHERE case_id = ?;", (case_id,))
    finally:
        conn.close()

# Relationships batch operations
def insert_relationships_batch(relationships: List[EventRelationship]) -> int:
    if not relationships:
        return 0
    conn = get_db_connection()
    inserted = 0
    try:
        with conn:
            for rel in relationships:
                conn.execute(
                    """
                    INSERT INTO relationships (
                        case_id, source_event_id, target_event_id, relationship_type,
                        confidence_score, correlation_method, supporting_identifiers,
                        evidence_sources, explanation, relationship_category
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rel.case_id, rel.source_event_id, rel.target_event_id, rel.relationship_type,
                        rel.confidence_score, rel.correlation_method, json.dumps(rel.supporting_identifiers or []),
                        json.dumps(rel.evidence_sources or []), rel.explanation, rel.relationship_category
                    )
                )
                inserted += 1
        return inserted
    finally:
        conn.close()

def get_relationships(case_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM relationships WHERE case_id = ?;", (case_id,))
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            d["supporting_identifiers"] = json.loads(d["supporting_identifiers"]) if d.get("supporting_identifiers") else []
            d["evidence_sources"] = json.loads(d["evidence_sources"]) if d.get("evidence_sources") else []
            results.append(d)
        return results
    finally:
        conn.close()

def clear_relationships_for_case(case_id: str):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM relationships WHERE case_id = ?;", (case_id,))
    finally:
        conn.close()

# Evaluation runs
def save_evaluation_run(run_id: str, case_id: str, method: str, temporal_window: float, metrics: Dict[str, Any], notes: str = ""):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evaluation_runs (run_id, case_id, method, temporal_window, metrics_json, run_timestamp, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, case_id, method, temporal_window, json.dumps(metrics), datetime.now(timezone.utc).isoformat(), notes)
            )
    finally:
        conn.close()

def get_evaluation_runs(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        if case_id:
            cursor = conn.execute("SELECT * FROM evaluation_runs WHERE case_id = ? ORDER BY run_timestamp DESC;", (case_id,))
        else:
            cursor = conn.execute("SELECT * FROM evaluation_runs ORDER BY run_timestamp DESC;")
        runs = []
        for row in cursor.fetchall():
            d = dict(row)
            d["metrics"] = json.loads(d["metrics_json"]) if d.get("metrics_json") else {}
            runs.append(d)
        return runs
    finally:
        conn.close()

# Ground truth records
def save_ground_truth(case_id: str, records: List[Dict[str, Any]]):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM ground_truth_records WHERE case_id = ?;", (case_id,))
            for rec in records:
                conn.execute(
                    """
                    INSERT INTO ground_truth_records (case_id, event_id, is_incident_related, activity_type, expected_relationships_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (case_id, rec["event_id"], rec.get("is_incident_related", 1), rec.get("activity_type", ""), json.dumps(rec.get("expected_relationships", [])))
                )
    finally:
        conn.close()

def get_ground_truth(case_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM ground_truth_records WHERE case_id = ?;", (case_id,))
        records = []
        for row in cursor.fetchall():
            d = dict(row)
            d["expected_relationships"] = json.loads(d["expected_relationships_json"]) if d.get("expected_relationships_json") else []
            records.append(d)
        return records
    finally:
        conn.close()

# Global forensics dashboard metrics
def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cases_count = conn.execute("SELECT COUNT(*) FROM cases;").fetchone()[0]
        files_count = conn.execute("SELECT COUNT(*) FROM evidence_files;").fetchone()[0]
        proc_count = conn.execute("SELECT COUNT(*) FROM events WHERE source = 'process';").fetchone()[0]
        reg_count = conn.execute("SELECT COUNT(*) FROM events WHERE source = 'registry';").fetchone()[0]
        net_count = conn.execute("SELECT COUNT(*) FROM events WHERE source = 'network';").fetchone()[0]
        rel_count = conn.execute("SELECT COUNT(*) FROM relationships;").fetchone()[0]

        # Count anomalies (e.g., suspicious persistence, unauthorized network sockets, cross-source discrepancies)
        # We classify relationships with high confidence or unexpected child spawns/persistence as potential anomalies
        anomalies_count = conn.execute(
            """
            SELECT COUNT(*) FROM relationships 
            WHERE relationship_type IN ('MODIFIED', 'CONNECTED_TO', 'SPAWNED') 
            AND (explanation LIKE '%Run Key%' OR explanation LIKE '%Persistence%' OR explanation LIKE '%C2%' OR confidence_score >= 0.85);
            """
        ).fetchone()[0]

        # Recent investigations
        recent_cases = conn.execute("SELECT case_id, name, created_at, status FROM cases ORDER BY created_at DESC LIMIT 5;").fetchall()

        return {
            "total_cases": cases_count,
            "total_files": files_count,
            "total_process_events": proc_count,
            "total_registry_events": reg_count,
            "total_network_events": net_count,
            "total_relationships": rel_count,
            "total_anomalies": anomalies_count,
            "source_distribution": {
                "Process": proc_count,
                "Registry": reg_count,
                "Network": net_count
            },
            "recent_cases": [dict(r) for r in recent_cases]
        }
    finally:
        conn.close()

# Initialize DB on module import
init_db()
