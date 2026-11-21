"""
Windows Registry Evidence Parser for U-15 Incident Reconstruction.
Parses:
- Standard Windows .reg export files
- Forensic Registry CSV exports (e.g. RECmd, RegShot, forensic triage tables)
- Standalone Registry snapshot/audit logs
"""
import csv
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from database.models import NormalizedEvent
from normalization.normalizer import Normalizer
from config.settings import logger

class RegistryParser:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse_file(self, file_path: str, base_date: Optional[str] = None) -> List[NormalizedEvent]:
        path = Path(file_path)
        if not path.exists():
            self.errors.append(f"File not found: {file_path}")
            return []

        suffix = path.suffix.lower()
        if suffix == ".csv":
            return self.parse_csv(path, base_date)
        elif suffix == ".reg":
            return self.parse_reg_file(path, base_date)
        else:
            # Check content for .reg header
            try:
                with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    first_line = f.readline()
                    if "Windows Registry Editor" in first_line:
                        return self.parse_reg_file(path, base_date)
            except Exception:
                pass
            return self.parse_csv(path, base_date)

    def parse_csv(self, path: Path, base_date: Optional[str] = None) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        encodings = ['utf-8-sig', 'utf-16', 'latin-1', 'cp1252']
        f = None
        for enc in encodings:
            try:
                test_f = open(path, "r", encoding=enc)
                header = test_f.readline()
                if any(k in header.lower() for k in ["key", "path", "hive", "reg", "timestamp", "value"]):
                    test_f.seek(0)
                    f = test_f
                    break
                test_f.close()
            except Exception:
                continue

        if not f:
            f = open(path, "r", encoding="utf-8", errors="replace")

        try:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                self.errors.append(f"Empty or headerless CSV: {path.name}")
                return []

            field_map = {col.strip().lower(): col for col in reader.fieldnames if col}
            
            col_key = (field_map.get("registry_key") or field_map.get("keypath") or 
                       field_map.get("key") or field_map.get("path") or field_map.get("registry path"))
            col_time = (field_map.get("timestamp") or field_map.get("lastwritetime") or 
                        field_map.get("last write time") or field_map.get("time of day") or field_map.get("time"))
            col_op = (field_map.get("operation") or field_map.get("registry_operation") or 
                      field_map.get("action") or field_map.get("event"))
            col_val_name = (field_map.get("valuename") or field_map.get("value name") or 
                            field_map.get("value") or field_map.get("name"))
            col_val_data = (field_map.get("valuedata") or field_map.get("value data") or 
                            field_map.get("data") or field_map.get("detail"))
            col_proc = field_map.get("process_name") or field_map.get("process name") or field_map.get("process")
            col_pid = field_map.get("pid") or field_map.get("process id")

            row_idx = 0
            for row in reader:
                row_idx += 1
                try:
                    raw_key = row.get(col_key, "") if col_key else ""
                    raw_time = row.get(col_time, "") if col_time else ""
                    raw_op = (row.get(col_op, "") if col_op else "RegSetValue").strip()
                    raw_val_name = row.get(col_val_name, "") if col_val_name else ""
                    raw_val_data = row.get(col_val_data, "") if col_val_data else ""
                    raw_proc = row.get(col_proc, "") if col_proc else ""
                    raw_pid = row.get(col_pid, None) if col_pid else None

                    norm_key = Normalizer.normalize_registry_path(raw_key)
                    iso_ts, orig_ts = Normalizer.parse_timestamp(raw_time, base_date=base_date)
                    proc_norm = Normalizer.normalize_process_name(raw_proc)

                    pid_int: Optional[int] = None
                    if raw_pid and str(raw_pid).isdigit():
                        pid_int = int(str(raw_pid))

                    event_type = "REG_SET_VALUE"
                    op_up = raw_op.upper()
                    if "CREATE" in op_up:
                        event_type = "REG_CREATE_KEY"
                    elif "DELETE" in op_up:
                        event_type = "REG_DELETE"
                    elif "QUERY" in op_up:
                        event_type = "REG_QUERY"

                    evidence_ref = f"Row {row_idx}"
                    event_id = Normalizer.generate_event_id(
                        source="registry",
                        evidence_file=path.name,
                        record_reference=evidence_ref,
                        raw_payload=f"{raw_key}|{raw_val_name}|{raw_val_data}"
                    )

                    is_snap = (iso_ts is None or iso_ts == "")
                    ev = NormalizedEvent(
                        event_id=event_id,
                        case_id=self.case_id,
                        timestamp=iso_ts or "",
                        original_timestamp=orig_ts,
                        source="registry",
                        event_type="REG_SNAPSHOT_VALUE" if is_snap else event_type,
                        pid=pid_int,
                        ppid=None,
                        process_name=proc_norm,
                        registry_key=norm_key,
                        registry_operation=raw_op,
                        evidence_file=path.name,
                        evidence_reference=evidence_ref,
                        metadata={
                            "value_name": raw_val_name,
                            "value_data": raw_val_data,
                            "raw_operation": raw_op,
                            "is_snapshot": is_snap
                        }
                    )
                    events.append(ev)
                except Exception as ex:
                    self.warnings.append(f"Row {row_idx}: {str(ex)}")

        except Exception as e:
            self.errors.append(f"Error parsing Registry CSV {path.name}: {str(e)}")
        finally:
            if f:
                f.close()

        logger.info("Registry CSV parsed: %d events, %d warnings, %d errors", len(events), len(self.warnings), len(self.errors))
        return events

    def parse_reg_file(self, path: Path, base_date: Optional[str] = None) -> List[NormalizedEvent]:
        r"""
        Parses Windows Registry .reg export script.
        Format:
        Windows Registry Editor Version 5.00
        [HKEY_CURRENT_USER\Software\IncidentLab]
        "Payload"="calc.exe"

        Strict Forensic Integrity (Priority 2):
        - A .reg file is a static state snapshot exported at a single point in time.
        - Does NOT contain individual modification timestamps.
        - Never assign artificial or current timestamps to .reg snapshot values.
        - Explicitly marks events as REG_SNAPSHOT_VALUE / REG_SNAPSHOT_KEY with is_snapshot=True.
        """
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        current_key = ""
        line_num = 0

        try:
            with open(path, "r", encoding="utf-16", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                lines = f.readlines()

        for line in lines:
            line_num += 1
            line_str = line.strip()
            if not line_str or line_str.startswith(";") or line_str.startswith("#") or "Windows Registry Editor" in line_str:
                continue

            # Detect key header: [HKEY_...]
            key_match = re.match(r"^\[([-\w\\]+)\]$", line_str)
            if key_match:
                current_key = Normalizer.normalize_registry_path(key_match.group(1))
                evidence_ref = f"Line {line_num}"
                event_id = Normalizer.generate_event_id(
                    source="registry",
                    evidence_file=path.name,
                    record_reference=evidence_ref,
                    raw_payload=f"{current_key}|KEY"
                )
                events.append(NormalizedEvent(
                    event_id=event_id,
                    case_id=self.case_id,
                    timestamp="",  # No artificial modification timestamp!
                    original_timestamp="STATIC_REG_SNAPSHOT",
                    source="registry",
                    event_type="REG_SNAPSHOT_KEY",
                    registry_key=current_key,
                    registry_operation="ExportedKeySnapshot",
                    evidence_file=path.name,
                    evidence_reference=evidence_ref,
                    metadata={"key": current_key, "is_snapshot": True, "raw_line": line_str}
                ))
                continue

            # Detect value definition: "ValueName"="Data" or "ValueName"=dword:...
            val_match = re.match(r'^"([^"]*)"=(.+)$', line_str)
            if val_match and current_key:
                val_name = val_match.group(1)
                val_data = val_match.group(2).strip('"')
                evidence_ref = f"Line {line_num}"
                event_id = Normalizer.generate_event_id(
                    source="registry",
                    evidence_file=path.name,
                    record_reference=evidence_ref,
                    raw_payload=f"{current_key}|{val_name}|{val_data}"
                )
                events.append(NormalizedEvent(
                    event_id=event_id,
                    case_id=self.case_id,
                    timestamp="",  # No artificial timestamp
                    original_timestamp="STATIC_REG_SNAPSHOT",
                    source="registry",
                    event_type="REG_SNAPSHOT_VALUE",
                    registry_key=current_key,
                    registry_operation="ExportedValueSnapshot",
                    evidence_file=path.name,
                    evidence_reference=evidence_ref,
                    metadata={
                        "value_name": val_name,
                        "value_data": val_data,
                        "raw_line": line_str,
                        "is_snapshot": True
                    }
                ))

        logger.info("Registry .reg parsed: %d snapshot entities (no artificial timestamps)", len(events))
        return events
