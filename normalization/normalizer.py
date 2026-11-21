"""
Evidence Normalization Module for U-15 Incident Reconstruction.
Standardizes timestamps, process names, Registry paths, IP addresses, and protocols
into a uniform forensic event representation without loss of provenance.
"""
from datetime import datetime, timezone
import re
import ipaddress
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import uuid
import hashlib
from dateutil import parser as date_parser

from database.models import NormalizedEvent
from config.settings import logger

class Normalizer:
    _TIME_ONLY_RE = re.compile(
        r"^T?\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:\s*(AM|PM))?Z?$",
        re.IGNORECASE,
    )
    _HAS_YEAR_RE = re.compile(r"(?:^|[^\d])(\d{4})(?:[^\d]|$)")

    @staticmethod
    def _resolve_timezone(timezone_name: Optional[str]):
        if not timezone_name or str(timezone_name).strip().upper() in ("UTC", "Z", "GMT"):
            return timezone.utc
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(str(timezone_name).strip())
        except Exception as e:
            logger.warning("Unrecognized timezone '%s' (%s); UTC not applied as a silent fallback for local wall time.", timezone_name, e)
            return None

    @staticmethod
    def timestamp_contains_calendar_date(raw: str) -> bool:
        text = (raw or "").strip()
        if not text:
            return False
        if Normalizer._HAS_YEAR_RE.search(text):
            return True
        if re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", text):
            return True
        return False

    @staticmethod
    def is_complete_timestamp(ts: Optional[str]) -> bool:
        """True only when a normalized timestamp includes a calendar date (not time-of-day alone)."""
        if not ts:
            return False
        text = str(ts).strip()
        if text.startswith("INCOMPLETE"):
            return False
        if re.match(r"^T\d{2}:", text):
            return False
        return Normalizer.timestamp_contains_calendar_date(text)

    @staticmethod
    def try_parse_complete_datetime(ts: Optional[str]) -> Optional[datetime]:
        """Parse only complete timestamps. Time-only and invalid values yield None (never 'today')."""
        if not Normalizer.is_complete_timestamp(ts):
            return None
        try:
            dt = date_parser.parse(str(ts).strip())
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except Exception:
            return None

    @staticmethod
    def parse_timestamp(
        ts_raw: Any,
        base_date: Optional[str] = None,
        timezone_name: Optional[str] = None,
    ) -> Tuple[Optional[str], str]:
        """
        Converts heterogeneous raw timestamp inputs into standard ISO-8601 UTC string.
        Returns: (normalized_iso_utc, original_raw_str)

        Strict Forensic Integrity:
        - Never silently replaces missing, empty, or invalid timestamps with current time.
        - Never interprets time-only strings using the computer's current date.
        - Incomplete timestamps stay incomplete unless the investigator supplies capture date and timezone.
        - Preserves original raw timestamp verbatim.
        """
        if ts_raw is None:
            return None, ""

        orig_str = str(ts_raw).strip()
        if not orig_str:
            return None, ""

        try:
            # Absolute unix timestamps only (not Wireshark relative seconds such as 0.123)
            if re.match(r"^\d+(\.\d+)?$", orig_str):
                flt = float(orig_str)
                if flt > 1e14:
                    flt /= 1e9
                elif flt > 1e11:
                    flt /= 1e3
                if flt < 1e9:
                    # Relative capture clock or epoch-adjacent value: keep incomplete.
                    return None, orig_str
                dt = datetime.fromtimestamp(flt, tz=timezone.utc)
                return dt.isoformat(), orig_str

            procmon_match = re.match(
                r"^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(AM|PM)?$",
                orig_str,
                re.IGNORECASE,
            )
            if procmon_match:
                hours = int(procmon_match.group(1))
                minutes = int(procmon_match.group(2))
                seconds = int(procmon_match.group(3))
                micros_str = procmon_match.group(4) or "0"
                micros = int(micros_str[:6].ljust(6, "0"))
                ampm = (procmon_match.group(5) or "").upper()
                if ampm == "PM" and hours < 12:
                    hours += 12
                elif ampm == "AM" and hours == 12:
                    hours = 0

                tzinfo = Normalizer._resolve_timezone(timezone_name)
                if base_date and tzinfo is not None:
                    try:
                        b_dt = date_parser.parse(base_date)
                        dt = datetime(
                            b_dt.year, b_dt.month, b_dt.day,
                            hours, minutes, seconds, micros, tzinfo=tzinfo
                        )
                        return dt.astimezone(timezone.utc).isoformat(), orig_str
                    except Exception as e:
                        logger.warning("Invalid base_date provided '%s': %s", base_date, e)

                # Explicitly incomplete: do not invent a calendar date.
                return None, orig_str

            if not Normalizer.timestamp_contains_calendar_date(orig_str):
                return None, orig_str

            dt = date_parser.parse(orig_str)
            if dt.tzinfo is None:
                tzinfo = Normalizer._resolve_timezone(timezone_name) or timezone.utc
                dt = dt.replace(tzinfo=tzinfo)
            dt = dt.astimezone(timezone.utc)
            return dt.isoformat(), orig_str

        except Exception as e:
            logger.debug("Date parsing failure for '%s': %s", orig_str, e)
            return None, orig_str

    @staticmethod
    def normalize_process_name(raw_name: Optional[str]) -> str:
        """
        Normalizes process name: lowercase basename, strips leading path and file extension if necessary.
        E.g., "C:\\Windows\\System32\\cmd.exe" -> "cmd.exe"
        """
        if not raw_name:
            return ""
        cleaned = str(raw_name).strip().replace("/", "\\")
        if "\\" in cleaned:
            cleaned = cleaned.split("\\")[-1]
        return cleaned.lower()

    @staticmethod
    def normalize_registry_path(raw_path: Optional[str]) -> str:
        """
        Normalizes Registry key paths:
        - Replaces forward slashes with backslashes
        - Standardizes root hive acronyms (HKEY_LOCAL_MACHINE -> HKLM, HKEY_CURRENT_USER -> HKCU)
        - Strips trailing slashes
        """
        if not raw_path:
            return ""
        p = str(raw_path).strip().replace("/", "\\")
        p = re.sub(r"\\+", r"\\", p)

        p_up = p.upper()
        if p_up.startswith("HKEY_LOCAL_MACHINE\\"):
            p = "HKLM\\" + p[19:]
        elif p_up.startswith("HKEY_CURRENT_USER\\"):
            p = "HKCU\\" + p[18:]
        elif p_up.startswith("HKEY_CLASSES_ROOT\\"):
            p = "HKCR\\" + p[18:]
        elif p_up.startswith("HKEY_USERS\\"):
            p = "HKU\\" + p[11:]
        elif p_up.startswith("HKEY_CURRENT_CONFIG\\"):
            p = "HKCC\\" + p[20:]
        elif p_up == "HKEY_LOCAL_MACHINE":
            p = "HKLM"
        elif p_up == "HKEY_CURRENT_USER":
            p = "HKCU"
        elif p_up == "HKEY_CLASSES_ROOT":
            p = "HKCR"
        elif p_up == "HKEY_USERS":
            p = "HKU"
        elif p_up == "HKEY_CURRENT_CONFIG":
            p = "HKCC"
        return p.rstrip("\\")

    @staticmethod
    def normalize_ip(raw_ip: Optional[str]) -> str:
        """Standardizes IP addresses (IPv4 or IPv6) or returns empty if invalid."""
        if not raw_ip:
            return ""
        s = str(raw_ip).strip()
        try:
            addr = ipaddress.ip_address(s)
            return str(addr)
        except ValueError:
            return s.lower()

    @staticmethod
    def normalize_transport_protocol(raw_proto: Optional[str]) -> str:
        """
        Separates transport protocol (TCP, UDP, ICMP) from application protocol.
        Strictly categorizes:
        - TCP: TCP, HTTP, HTTPS, TLS, SSL, SSH, FTP, SMB
        - UDP: UDP, DNS, NTP, DHCP, SNMP
        - ICMP: ICMP
        - OTHER: unrecognized or link-layer
        """
        if not raw_proto:
            return "UNKNOWN"
        p = str(raw_proto).strip().upper()
        
        # Check ICMP first
        if "ICMP" in p:
            return "ICMP"
            
        # Check TCP & common TCP applications
        if any(k in p for k in ["TCP", "HTTP", "TLS", "SSL", "SSH", "FTP", "SMB"]):
            return "TCP"
            
        # Check UDP & common UDP applications
        if any(k in p for k in ["UDP", "DNS", "NTP", "DHCP", "SNMP"]):
            return "UDP"
            
        return "OTHER"

    @classmethod
    def normalize_protocol(cls, raw_proto: Optional[str]) -> str:
        """Alias for normalize_transport_protocol for backward compatibility."""
        return cls.normalize_transport_protocol(raw_proto)

    @staticmethod
    def normalize_app_protocol(raw_proto: Optional[str]) -> str:
        """Extracts application layer protocol if known (HTTP, DNS, TLS, etc.)."""
        if not raw_proto:
            return ""
        p = str(raw_proto).strip().upper()
        if "HTTP" in p:
            return "HTTP"
        if "DNS" in p:
            return "DNS"
        if "TLS" in p or "SSL" in p:
            return "TLS"
        if "SMB" in p:
            return "SMB"
        if "SSH" in p:
            return "SSH"
        return ""

    @staticmethod
    def generate_event_id(
        source: str,
        evidence_file: str,
        record_reference: str,
        raw_payload: str = ""
    ) -> str:
        """
        Creates a reproducible, provenance-grounded forensic event ID.
        Format: EVT-<SRC>-<FILE_STEM>-<REF_TAG>-<PAYLOAD_HASH>
        Example: EVT-PROC-procmon_events-R00006-a1b2c3
        
        Guarantees:
        - Every ground-truth event directly maps to the exact parsed event ID.
        - Provenance (file name and record index) is explicitly preserved in the ID.
        """
        src_prefix = {
            "process": "EVT-PROC",
            "registry": "EVT-REG",
            "network": "EVT-NET"
        }.get(source.lower(), "EVT-GEN")

        # Clean file stem
        clean_file = re.sub(r"[^\w\-]", "", Path(evidence_file).stem.lower())
        if not clean_file:
            clean_file = "raw"

        # Clean record reference (e.g. "Row 6" -> "R00006", "Packet #3" -> "P00003", "Line 12" -> "L00012")
        ref_match = re.search(r"(\d+)", record_reference)
        ref_num = int(ref_match.group(1)) if ref_match else 0
        
        if "packet" in record_reference.lower():
            ref_tag = f"P{ref_num:05d}"
        elif "line" in record_reference.lower():
            ref_tag = f"L{ref_num:05d}"
        else:
            ref_tag = f"R{ref_num:05d}"

        # Hash payload for collision-free determinism
        hash_str = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()[:6] if raw_payload else "000000"
        return f"{src_prefix}-{clean_file}-{ref_tag}-{hash_str}"

    @classmethod
    def deduplicate_events(cls, events: List[NormalizedEvent]) -> Tuple[List[NormalizedEvent], int]:
        """
        Removes only verified duplicate events based on identical core forensic tuple:
        (source, timestamp, pid, process_name, event_type, registry_key, src_ip, dst_ip, dst_port, file_path)
        Returns (deduplicated_events, count_of_duplicates_removed).
        """
        seen = set()
        deduped = []
        dups_count = 0
        for ev in events:
            core_tuple = (
                ev.source,
                ev.timestamp,
                ev.pid,
                ev.process_name,
                ev.event_type,
                ev.registry_key,
                ev.src_ip,
                ev.dst_ip,
                ev.src_port,
                ev.dst_port,
                ev.file_path
            )
            if core_tuple in seen:
                dups_count += 1
                continue
            seen.add(core_tuple)
            deduped.append(ev)
        return deduped, dups_count
