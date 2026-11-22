"""
Procmon (Process Monitor) Evidence Parser for U-15 Incident Reconstruction.
Parses CSV and XML exports from Microsoft Sysinternals Process Monitor, extracting:
- Process lifecycle (Process Create, Start, Exit, PPID, Command line)
- File system activity (CreateFile, WriteFile, SetDisposition)
- Registry operations (RegCreateKey, RegSetValue, RegDeleteValue)
- Does not treat TCP/UDP operations as Sysmon-equivalent network connection telemetry.
"""
import csv
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from database.models import NormalizedEvent
from normalization.normalizer import Normalizer
from config.settings import logger


class ProcmonParser:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse_file(self, file_path: str, base_date: Optional[str] = None, timezone_name: Optional[str] = None) -> List[NormalizedEvent]:
        path = Path(file_path)
        if not path.exists():
            self.errors.append(f"File not found: {file_path}")
            return []

        suffix = path.suffix.lower()
        if suffix == ".csv":
            return self.parse_csv(path, base_date, timezone_name)
        elif suffix == ".xml":
            return self.parse_xml(path, base_date, timezone_name)
        else:
            return self.parse_csv(path, base_date, timezone_name)

    def parse_csv(self, path: Path, base_date: Optional[str] = None, timezone_name: Optional[str] = None) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        encodings = ['utf-8-sig', 'utf-16', 'latin-1', 'cp1252']
        f = None

        for enc in encodings:
            try:
                with open(path, "r", encoding=enc, newline="") as probe:
                    header_line = probe.readline()

                normalized_header = header_line.strip().lower()
                has_process = "process name" in normalized_header or "image path" in normalized_header
                has_operation = "operation" in normalized_header or "event" in normalized_header

                if has_process and has_operation:
                    f = open(path, "r", encoding=enc, newline="")
                    break

            except (UnicodeError, OSError):
                continue

        if f is None:
            self.errors.append(f"Unsupported or invalid Procmon CSV header: {path.name}")
            return []

        try:
            reader = csv.DictReader(f)

            if not reader.fieldnames:
                self.errors.append(f"Empty or headerless CSV file: {path.name}")
                return []

            field_map = {col.strip().lower(): col for col in reader.fieldnames if col}

            col_time = field_map.get("time of day") or field_map.get("time") or field_map.get("timestamp")
            col_proc = field_map.get("process name") or field_map.get("image path") or field_map.get("process")
            col_pid = field_map.get("pid") or field_map.get("process id")
            col_op = field_map.get("operation") or field_map.get("event")
            col_path = field_map.get("path") or field_map.get("target") or field_map.get("object")
            col_result = field_map.get("result") or field_map.get("status")
            col_detail = field_map.get("detail") or field_map.get("details") or field_map.get("extra")

            row_idx = 0

            for row in reader:
                row_idx += 1

                try:
                    raw_time = row.get(col_time, "") if col_time else ""
                    raw_proc = row.get(col_proc, "") if col_proc else ""
                    raw_pid = row.get(col_pid, "") if col_pid else None
                    raw_op = (row.get(col_op, "") if col_op else "").strip()
                    raw_path = row.get(col_path, "") if col_path else ""
                    raw_result = row.get(col_result, "") if col_result else ""
                    raw_detail = row.get(col_detail, "") if col_detail else ""

                    ev = self._convert_record(
                        row_idx=row_idx,
                        evidence_file=path.name,
                        raw_time=raw_time,
                        raw_proc=raw_proc,
                        raw_pid=raw_pid,
                        raw_op=raw_op,
                        raw_path=raw_path,
                        raw_result=raw_result,
                        raw_detail=raw_detail,
                        base_date=base_date,
                        timezone_name=timezone_name
                    )

                    if ev:
                        events.append(ev)

                except Exception as ex:
                    self.warnings.append(f"Row {row_idx}: Parsing warning - {str(ex)}")

        except Exception as e:
            self.errors.append(f"Fatal error reading CSV {path.name}: {str(e)}")

        finally:
            if f:
                f.close()

        logger.info(
            "Procmon CSV parsed: %d events, %d warnings, %d errors",
            len(events),
            len(self.warnings),
            len(self.errors)
        )

        return events

    def parse_xml(self, path: Path, base_date: Optional[str] = None, timezone_name: Optional[str] = None) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        try:
            tree = ET.parse(str(path))
            root = tree.getroot()
            row_idx = 0

            event_nodes = root.findall(".//event") or root.findall("./event")

            for node in event_nodes:
                row_idx += 1

                try:
                    raw_time = node.findtext("Time_of_Day") or node.findtext("Time") or ""
                    raw_proc = node.findtext("Process_Name") or node.findtext("Process") or ""
                    raw_pid = node.findtext("PID")
                    raw_op = node.findtext("Operation") or ""
                    raw_path = node.findtext("Path") or ""
                    raw_result = node.findtext("Result") or ""
                    raw_detail = node.findtext("Detail") or ""

                    ev = self._convert_record(
                        row_idx=row_idx,
                        evidence_file=path.name,
                        raw_time=raw_time,
                        raw_proc=raw_proc,
                        raw_pid=raw_pid,
                        raw_op=raw_op,
                        raw_path=raw_path,
                        raw_result=raw_result,
                        raw_detail=raw_detail,
                        base_date=base_date,
                        timezone_name=timezone_name
                    )

                    if ev:
                        events.append(ev)

                except Exception as ex:
                    self.warnings.append(f"XML Node {row_idx}: {str(ex)}")

        except Exception as e:
            self.errors.append(f"Fatal XML parse error {path.name}: {str(e)}")

        return events

    def _convert_record(
        self,
        row_idx: int,
        evidence_file: str,
        raw_time: str,
        raw_proc: str,
        raw_pid: Any,
        raw_op: str,
        raw_path: str,
        raw_result: str,
        raw_detail: str,
        base_date: Optional[str],
        timezone_name: Optional[str] = None,
    ) -> Optional[NormalizedEvent]:

        iso_ts, orig_ts = Normalizer.parse_timestamp(
            raw_time,
            base_date=base_date,
            timezone_name=timezone_name
        )

        pid_int: Optional[int] = None

        if raw_pid is not None and str(raw_pid).strip().isdigit():
            pid_int = int(str(raw_pid).strip())

        proc_norm = Normalizer.normalize_process_name(raw_proc)

        op_upper = raw_op.upper()
        event_source = "process"
        event_type = "PROCESS_ACTIVITY"
        ppid: Optional[int] = None
        reg_key = ""
        reg_op = ""
        file_path = ""
        src_ip = ""
        dst_ip = ""
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = ""
        created_pid: Optional[int] = None

        if "PROCESS" in op_upper:
            if op_upper == "PROCESS CREATE":
                event_type = "PROCESS_CREATE"

                created_pid_match = re.search(
                    r"\bPID:\s*(\d+)",
                    raw_detail,
                    re.IGNORECASE
                )

                ppid_match = re.search(
                    r"\bParent\s*PID:\s*(\d+)",
                    raw_detail,
                    re.IGNORECASE
                )

                if created_pid_match:
                    created_pid = int(created_pid_match.group(1))

                if ppid_match:
                    ppid = int(ppid_match.group(1))

            elif op_upper == "PROCESS START":
                event_type = "PROCESS_START"

                ppid_match = re.search(
                    r"\bParent\s*PID:\s*(\d+)",
                    raw_detail,
                    re.IGNORECASE
                )

                if ppid_match:
                    ppid = int(ppid_match.group(1))

            elif op_upper == "PROCESS EXIT":
                event_type = "PROCESS_EXIT"

            file_path = raw_path

        elif op_upper.startswith("REG"):
            event_source = "registry"
            event_type = "REG_OPERATION"
            reg_op = raw_op
            reg_key = Normalizer.normalize_registry_path(raw_path)

            if "SETVALUE" in op_upper:
                event_type = "REG_SET_VALUE"
            elif "CREATEKEY" in op_upper:
                event_type = "REG_CREATE_KEY"
            elif "DELETE" in op_upper:
                event_type = "REG_DELETE"

        elif "TCP" in op_upper or "UDP" in op_upper or "NETWORK" in op_upper:
            event_source = "process"
            event_type = op_upper.replace(" ", "_") or "PROCESS_NETWORK_OPERATION"
            protocol = Normalizer.normalize_transport_protocol(raw_op)

            net_match = re.search(
                r"([\w\.\-]+):(\d+)\s*(?:->|\-)\s*([\w\.\-]+):(\d+)",
                f"{raw_path} {raw_detail}"
            )

            if net_match:
                src_ip = Normalizer.normalize_ip(net_match.group(1))
                src_port = int(net_match.group(2))
                dst_ip = Normalizer.normalize_ip(net_match.group(3))
                dst_port = int(net_match.group(4))

        else:
            event_source = "process"
            event_type = f"FILE_{op_upper}" if "FILE" in op_upper else op_upper
            file_path = raw_path

        evidence_ref = f"Row {row_idx}"

        event_id = Normalizer.generate_event_id(
            source=event_source,
            evidence_file=evidence_file,
            record_reference=evidence_ref,
            raw_payload=f"{raw_time}|{raw_proc}|{raw_pid}|{raw_op}|{raw_path}"
        )

        metadata = {
            "raw_operation": raw_op,
            "raw_path": raw_path,
            "raw_result": raw_result,
            "raw_detail": raw_detail,
            "raw_time": orig_ts,
            "created_pid": created_pid,
            "transport_protocol": protocol if src_ip else "",
            "app_protocol": Normalizer.normalize_app_protocol(f"{raw_path} {raw_detail}"),
            "network_telemetry": "",
        }

        return NormalizedEvent(
            event_id=event_id,
            case_id=self.case_id,
            timestamp=iso_ts or "",
            original_timestamp=orig_ts,
            source=event_source,
            event_type=event_type,
            pid=pid_int,
            ppid=ppid,
            process_name=proc_norm,
            registry_key=reg_key,
            registry_operation=reg_op,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            file_path=file_path,
            evidence_file=evidence_file,
            evidence_reference=evidence_ref,
            metadata=metadata
        )