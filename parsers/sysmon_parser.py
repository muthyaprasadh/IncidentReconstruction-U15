
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any

from database.models import NormalizedEvent
from normalization.normalizer import Normalizer
from config.settings import logger

SYSMON_EVENT_PROCESS_CREATE = 1
SYSMON_EVENT_NETWORK = 3
SYSMON_TIMESTAMP_DISCREPANCY_WARNING_MS = 1000


def _local_tag(tag: str) -> str:
    if not tag:
        return ""
    return tag.split("}", 1)[-1]


def _child_text(node: ET.Element, local_name: str) -> str:
    for child in list(node):
        if _local_tag(child.tag) == local_name:
            return (child.text or "").strip()
    return ""


def _eventdata_map(event_node: ET.Element) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for node in event_node.iter():
        if _local_tag(node.tag) != "Data":
            continue
        name = node.attrib.get("Name") or node.attrib.get("name") or ""
        if name:
            fields[name] = (node.text or "").strip()
    return fields


def _system_event_id(event_node: ET.Element) -> Optional[int]:
    for node in event_node.iter():
        if _local_tag(node.tag) == "EventID":
            text = (node.text or "").strip()
            return int(text) if text.isdigit() else None
    return None


def _system_time(event_node: ET.Element) -> str:
    for node in event_node.iter():
        if _local_tag(node.tag) == "TimeCreated":
            return str(node.attrib.get("SystemTime", "")).strip()
    return ""


def _parse_aware_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None

    text = str(value).strip()

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed
    except (ValueError, TypeError):
        return None


def _timestamp_comparison(utc_iso: str, system_time: str) -> Dict[str, Any]:
    result = {
        "SystemTime": system_time,
        "SystemTimeNormalized": "",
        "timestamp_delta_ms": None,
        "timestamp_comparison_status": "UNAVAILABLE",
    }

    utc_dt = _parse_aware_datetime(utc_iso)
    system_dt = _parse_aware_datetime(system_time)

    if utc_dt is None or system_dt is None:
        result["timestamp_comparison_status"] = "UNPARSEABLE"
        return result

    delta_ms = abs((system_dt - utc_dt).total_seconds() * 1000)

    result["SystemTimeNormalized"] = system_dt.isoformat()
    result["timestamp_delta_ms"] = round(delta_ms, 3)
    result["timestamp_comparison_status"] = (
        "MATCH" if delta_ms <= 1 else "DIFFERENT"
    )

    return result


def _optional_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None

    text = str(value).strip()

    if not text or text == "-":
        return None

    if text.isdigit():
        return int(text)

    return None


def _optional_bool_string(value: Optional[str]) -> str:
    if value is None:
        return ""

    text = str(value).strip()

    if not text or text == "-":
        return ""

    return text


def _process_guid(value: str) -> str:
    guid = (value or "").strip()
    compact_guid = guid.strip("{}").replace("-", "")
    if compact_guid == "0" * 32:
        return ""
    return guid


class SysmonParser:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse_file(
        self,
        file_path: str,
        base_date: Optional[str] = None,
        timezone_name: Optional[str] = None
    ) -> List[NormalizedEvent]:

        path = Path(file_path)

        if not path.exists():
            self.errors.append(f"File not found: {file_path}")
            return []

        suffix = path.suffix.lower()

        if suffix == ".evtx":
            self.errors.append(
                "Binary EVTX is not parsed here. Export the log as XML first."
            )
            return []

        return self.parse_xml(
            path,
            base_date=base_date,
            timezone_name=timezone_name
        )

    def parse_xml(
        self,
        path: Path,
        base_date: Optional[str] = None,
        timezone_name: Optional[str] = None
    ) -> List[NormalizedEvent]:

        events: List[NormalizedEvent] = []

        self.errors.clear()
        self.warnings.clear()

        try:
            tree = ET.parse(str(path))
            root = tree.getroot()
        except Exception as e:
            self.errors.append(
                f"Fatal XML parse error {path.name}: {str(e)}"
            )
            return []

        event_nodes = [
            node for node in root.iter()
            if _local_tag(node.tag) == "Event" and node is not root
        ]

        if _local_tag(root.tag) == "Event":
            event_nodes = [root] + event_nodes

        row_idx = 0

        for node in event_nodes:
            sysmon_eid = _system_event_id(node)

            if sysmon_eid not in (
                SYSMON_EVENT_PROCESS_CREATE,
                SYSMON_EVENT_NETWORK
            ):
                continue

            row_idx += 1

            try:
                event = self._convert_event(
                    node=node,
                    row_idx=row_idx,
                    evidence_file=path.name,
                    sysmon_eid=sysmon_eid,
                    base_date=base_date,
                    timezone_name=timezone_name
                )

                if event:
                    events.append(event)

            except Exception as ex:
                self.warnings.append(
                    f"XML Event {row_idx}: {str(ex)}"
                )

        logger.info(
            "Sysmon XML parsed: %d events (EID 1/3), %d warnings, %d errors",
            len(events),
            len(self.warnings),
            len(self.errors)
        )

        return events

    def _convert_event(
        self,
        node: ET.Element,
        row_idx: int,
        evidence_file: str,
        sysmon_eid: int,
        base_date: Optional[str],
        timezone_name: Optional[str]
    ) -> Optional[NormalizedEvent]:

        data = _eventdata_map(node)

        utc_time = data.get("UtcTime", "")
        system_time = _system_time(node)

        iso_ts, orig_ts = Normalizer.parse_timestamp(
            utc_time,
            base_date=base_date,
            timezone_name=timezone_name
        )

        utc_iso_ts = iso_ts
        timestamp_source = "UtcTime" if iso_ts else ""
        if not iso_ts and system_time:
            system_dt = _parse_aware_datetime(system_time)
            if system_dt is not None:
                iso_ts = system_dt.astimezone(timezone.utc).isoformat()
                timestamp_source = "SystemTime"
                self.warnings.append(
                    f"XML Event {row_idx}: UtcTime is unavailable or invalid; "
                    "using XML SystemTime for chronology."
                )
            else:
                self.warnings.append(
                    f"XML Event {row_idx}: UtcTime is unavailable or invalid and "
                    "XML SystemTime is not timezone-aware; chronology timestamp unavailable."
                )

        timestamp_metadata = _timestamp_comparison(
            utc_iso_ts or "",
            system_time
        )
        timestamp_delta_ms = timestamp_metadata["timestamp_delta_ms"]
        if (
            timestamp_delta_ms is not None
            and timestamp_delta_ms > SYSMON_TIMESTAMP_DISCREPANCY_WARNING_MS
        ):
            self.warnings.append(
                f"XML Event {row_idx}: UtcTime and SystemTime differ by "
                f"{timestamp_delta_ms} ms; timestamp omitted from chronology."
            )
            system_iso_ts = timestamp_metadata["SystemTimeNormalized"]
            if system_iso_ts:
                timestamp_bounds = sorted(
                    (utc_iso_ts, system_iso_ts),
                    key=_parse_aware_datetime
                )
                timestamp_metadata["timestamp_uncertainty_start"] = timestamp_bounds[0]
                timestamp_metadata["timestamp_uncertainty_end"] = timestamp_bounds[1]
            iso_ts = ""
            timestamp_source = ""

        raw_process_guid = data.get("ProcessGuid", "")
        process_guid = _process_guid(raw_process_guid)
        if raw_process_guid and not process_guid:
            self.warnings.append(
                f"XML Event {row_idx}: ProcessGuid is all zeroes; "
                "process attribution is unavailable."
            )
        pid = _optional_int(data.get("ProcessId"))
        image = data.get("Image", "")

        process_name = (
            Normalizer.normalize_process_name(image)
            if image else ""
        )

        src_ip = ""
        dst_ip = ""
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = ""
        initiated = ""
        ppid: Optional[int] = None

        event_source = "process"
        event_type = "PROCESS_ACTIVITY"

        if sysmon_eid == SYSMON_EVENT_PROCESS_CREATE:
            event_source = "process"
            event_type = "PROCESS_START"
            ppid = _optional_int(data.get("ParentProcessId"))

        elif sysmon_eid == SYSMON_EVENT_NETWORK:
            event_source = "network"
            event_type = "NET_CONNECT"

            src_ip = (
                Normalizer.normalize_ip(data.get("SourceIp", ""))
                if data.get("SourceIp") else ""
            )

            dst_ip = (
                Normalizer.normalize_ip(data.get("DestinationIp", ""))
                if data.get("DestinationIp") else ""
            )

            src_port = _optional_int(data.get("SourcePort"))
            dst_port = _optional_int(data.get("DestinationPort"))

            protocol = (
                Normalizer.normalize_transport_protocol(
                    data.get("Protocol", "")
                )
                if data.get("Protocol") else ""
            )

            initiated = _optional_bool_string(
                data.get("Initiated")
            )

        evidence_ref = f"Event {row_idx}"

        payload = (
            f"{sysmon_eid}|{utc_time}|{raw_process_guid}|{pid}|{image}|"
            f"{src_ip}|{src_port}|{dst_ip}|{dst_port}|{protocol}|{initiated}"
        )

        event_id = Normalizer.generate_event_id(
            source=event_source,
            evidence_file=evidence_file,
            record_reference=evidence_ref,
            raw_payload=payload
        )

        metadata: Dict[str, Any] = {
            "sysmon_event_id": sysmon_eid,
            "ProcessGuid": process_guid,
            "process_guid": process_guid,
            "Image": image,
            "UtcTime": utc_time,
            "TimestampSource": timestamp_source,
            "network_telemetry": (
                "sysmon_event_id_3"
                if sysmon_eid == SYSMON_EVENT_NETWORK else ""
            ),
            "original_xml_reference": (
                f"{evidence_file}#{evidence_ref}"
            ),
            **timestamp_metadata
        }

        if raw_process_guid:
            metadata["ProcessGuidRaw"] = raw_process_guid

        if initiated:
            metadata["Initiated"] = initiated

        raw_parent_guid = data.get("ParentProcessGuid", "")
        parent_guid = _process_guid(raw_parent_guid)

        if parent_guid:
            metadata["ParentProcessGuid"] = parent_guid
        elif raw_parent_guid:
            metadata["ParentProcessGuidRaw"] = raw_parent_guid

        command_line = data.get("CommandLine", "")

        if command_line:
            metadata["CommandLine"] = command_line

        return NormalizedEvent(
            event_id=event_id,
            case_id=self.case_id,
            timestamp=iso_ts or "",
            original_timestamp=orig_ts,
            source=event_source,
            event_type=event_type,
            pid=pid,
            ppid=ppid,
            process_name=process_name,
            process_guid=process_guid,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            file_path=image,
            evidence_file=evidence_file,
            evidence_reference=evidence_ref,
            metadata=metadata
        )


def sysmon_event_id_from_fields(
    evidence_file: str,
    row_idx: int,
    sysmon_eid: int,
    utc_time: str,
    process_guid: str,
    pid: Optional[int],
    image: str,
    src_ip: str = "",
    src_port: Optional[int] = None,
    dst_ip: str = "",
    dst_port: Optional[int] = None,
    protocol: str = "",
    initiated: str = ""
) -> str:

    source = (
        "process"
        if sysmon_eid == SYSMON_EVENT_PROCESS_CREATE
        else "network"
    )

    src_ip = (
        Normalizer.normalize_ip(src_ip)
        if src_ip else ""
    )

    dst_ip = (
        Normalizer.normalize_ip(dst_ip)
        if dst_ip else ""
    )

    protocol = (
        Normalizer.normalize_transport_protocol(protocol)
        if protocol else ""
    )

    payload = (
        f"{sysmon_eid}|{utc_time}|{process_guid}|{pid}|{image}|"
        f"{src_ip}|{src_port}|{dst_ip}|{dst_port}|{protocol}|{initiated}"
    )

    return Normalizer.generate_event_id(
        source,
        evidence_file,
        f"Event {row_idx}",
        payload
    )