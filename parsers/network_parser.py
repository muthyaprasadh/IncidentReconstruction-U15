"""
Network Evidence Parser for U-15 Incident Reconstruction.
Parses Wireshark CSV exports and PCAP/PCAPNG capture files (via Scapy), extracting:
- Network five-tuple: src_ip, dst_ip, src_port, dst_port, protocol
- Frame timestamps and packet indices
- Application protocol metadata (DNS queries, HTTP request info)
"""
import csv
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from database.models import NormalizedEvent
from normalization.normalizer import Normalizer
from config.settings import logger

class NetworkParser:
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
        if suffix in [".pcap", ".pcapng", ".cap"]:
            return self.parse_pcap(path, base_date)
        elif suffix == ".csv":
            return self.parse_csv(path, base_date)
        else:
            # Check if text or binary
            try:
                with open(path, "rb") as bf:
                    magic = bf.read(4)
                    # Standard pcap magic: \xd4\xc3\xb2\xa1 or \xa1\xb2\xc3\xd4; pcapng magic: \x0a\x0d\x0d\x0a
                    if magic in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]:
                        return self.parse_pcap(path, base_date)
            except Exception:
                pass
            return self.parse_csv(path, base_date)

    def parse_csv(self, path: Path, base_date: Optional[str] = None) -> List[NormalizedEvent]:
        """Parses Wireshark exported CSV packet summary files."""
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
        f = None
        for enc in encodings:
            try:
                test_f = open(path, "r", encoding=enc)
                header = test_f.readline()
                if any(k in header.lower() for k in ["source", "destination", "protocol", "info", "time"]):
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
            
            col_no = field_map.get("no.") or field_map.get("number") or field_map.get("frame")
            # Prefer absolute epoch timestamps when the Wireshark export includes
            # frame.time_epoch. The default Wireshark "Time" column may be a
            # relative capture offset and must remain incomplete.
            col_time = (field_map.get("frame.time_epoch") or field_map.get("time_epoch")
                        or field_map.get("utc time") or field_map.get("timestamp")
                        or field_map.get("time"))
            col_src = field_map.get("source") or field_map.get("src") or field_map.get("ip.src")
            col_dst = field_map.get("destination") or field_map.get("dst") or field_map.get("ip.dst")
            col_proto = field_map.get("protocol") or field_map.get("proto")
            col_len = field_map.get("length") or field_map.get("len")
            col_info = field_map.get("info") or field_map.get("summary") or field_map.get("details")

            # Try to map direct port columns if exported
            col_sport = field_map.get("srcport") or field_map.get("source port") or field_map.get("tcp.srcport") or field_map.get("udp.srcport")
            col_dport = field_map.get("dstport") or field_map.get("destination port") or field_map.get("tcp.dstport") or field_map.get("udp.dstport")

            row_idx = 0
            for row in reader:
                row_idx += 1
                try:
                    raw_no = row.get(col_no, str(row_idx)) if col_no else str(row_idx)
                    raw_time = row.get(col_time, "") if col_time else ""
                    raw_src = row.get(col_src, "") if col_src else ""
                    raw_dst = row.get(col_dst, "") if col_dst else ""
                    raw_proto = row.get(col_proto, "TCP") if col_proto else "TCP"
                    raw_len = row.get(col_len, "0") if col_len else "0"
                    raw_info = row.get(col_info, "") if col_info else ""

                    src_port = None
                    dst_port = None

                    # If direct port columns exist
                    if col_sport and row.get(col_sport, "").isdigit():
                        src_port = int(row.get(col_sport))
                    if col_dport and row.get(col_dport, "").isdigit():
                        dst_port = int(row.get(col_dport))

                    # Otherwise extract ports from Info column: e.g. "49152 -> 80 [SYN]", "5353 -> 5353"
                    if src_port is None or dst_port is None:
                        port_match = re.search(r"(\d{1,5})\s*(?:->|\>)\s*(\d{1,5})", raw_info)
                        if port_match:
                            src_port = int(port_match.group(1))
                            dst_port = int(port_match.group(2))

                    norm_src = Normalizer.normalize_ip(raw_src)
                    norm_dst = Normalizer.normalize_ip(raw_dst)
                    transport_proto = Normalizer.normalize_transport_protocol(raw_proto)
                    app_proto = Normalizer.normalize_app_protocol(raw_proto) or Normalizer.normalize_app_protocol(raw_info)
                    iso_ts, orig_ts = Normalizer.parse_timestamp(raw_time, base_date=base_date, timezone_name=None)

                    evidence_ref = f"Packet #{raw_no}"
                    event_id = Normalizer.generate_event_id(
                        source="network",
                        evidence_file=path.name,
                        record_reference=evidence_ref,
                        raw_payload=f"{raw_no}|{norm_src}|{norm_dst}|{src_port}|{dst_port}|{transport_proto}"
                    )

                    ev = NormalizedEvent(
                        event_id=event_id,
                        case_id=self.case_id,
                        timestamp=iso_ts or "",
                        original_timestamp=orig_ts,
                        source="network",
                        event_type="NET_PACKET",
                        src_ip=norm_src,
                        dst_ip=norm_dst,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=transport_proto,
                        evidence_file=path.name,
                        evidence_reference=evidence_ref,
                        metadata={
                            "frame_number": raw_no,
                            "length": raw_len,
                            "info": raw_info,
                            "raw_time": orig_ts,
                            "transport_protocol": transport_proto,
                            "app_protocol": app_proto
                        }
                    )
                    events.append(ev)
                except Exception as ex:
                    self.warnings.append(f"Row {row_idx}: {str(ex)}")

        except Exception as e:
            self.errors.append(f"Error parsing Wireshark CSV {path.name}: {str(e)}")
        finally:
            if f:
                f.close()

        logger.info("Wireshark CSV parsed: %d packets, %d warnings, %d errors", len(events), len(self.warnings), len(self.errors))
        return events

    def parse_pcap(self, path: Path, base_date: Optional[str] = None) -> List[NormalizedEvent]:
        """Parses raw PCAP or PCAPNG packet capture using Scapy."""
        events: List[NormalizedEvent] = []
        self.errors.clear()
        self.warnings.clear()

        try:
            from scapy.utils import PcapReader
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.dns import DNS
        except ImportError:
            self.errors.append("Scapy is not installed. PCAP parsing requires Scapy.")
            return []

        packet_idx = 0
        try:
            with PcapReader(str(path)) as pcap_reader:
                for pkt in pcap_reader:
                    packet_idx += 1
                    try:
                        # Epoch float timestamp
                        pkt_time = float(pkt.time)
                        iso_ts, orig_ts = Normalizer.parse_timestamp(pkt_time)

                        src_ip = ""
                        dst_ip = ""
                        src_port = None
                        dst_port = None
                        protocol = "OTHER"
                        info = ""

                        if IP in pkt:
                            src_ip = pkt[IP].src
                            dst_ip = pkt[IP].dst
                        elif IPv6 in pkt:
                            src_ip = pkt[IPv6].src
                            dst_ip = pkt[IPv6].dst

                        if TCP in pkt:
                            protocol = "TCP"
                            src_port = int(pkt[TCP].sport)
                            dst_port = int(pkt[TCP].dport)
                            flags = pkt[TCP].flags
                            info = f"{src_port} -> {dst_port} [{flags}]"
                        elif UDP in pkt:
                            protocol = "UDP"
                            src_port = int(pkt[UDP].sport)
                            dst_port = int(pkt[UDP].dport)
                            info = f"{src_port} -> {dst_port}"
                            if DNS in pkt and pkt[DNS].qd:
                                try:
                                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                                    protocol = "DNS"
                                    info += f" Query: {qname}"
                                except Exception:
                                    pass
                        elif ICMP in pkt:
                            protocol = "ICMP"
                            info = f"ICMP Type {pkt[ICMP].type}"

                        transport_proto = Normalizer.normalize_transport_protocol(protocol)
                        app_proto = Normalizer.normalize_app_protocol(protocol) or Normalizer.normalize_app_protocol(info)

                        evidence_ref = f"Packet #{packet_idx}"
                        event_id = Normalizer.generate_event_id(
                            source="network",
                            evidence_file=path.name,
                            record_reference=evidence_ref,
                            raw_payload=f"{packet_idx}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{transport_proto}"
                        )

                        ev = NormalizedEvent(
                            event_id=event_id,
                            case_id=self.case_id,
                            timestamp=iso_ts or "",
                            original_timestamp=orig_ts,
                            source="network",
                            event_type="NET_PACKET",
                            src_ip=Normalizer.normalize_ip(src_ip),
                            dst_ip=Normalizer.normalize_ip(dst_ip),
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=transport_proto,
                            evidence_file=path.name,
                            evidence_reference=evidence_ref,
                            metadata={
                                "frame_number": packet_idx,
                                "length": len(pkt),
                                "info": info,
                                "transport_protocol": transport_proto,
                                "app_protocol": app_proto
                            }
                        )
                        events.append(ev)
                    except Exception as p_ex:
                        if packet_idx <= 10 or packet_idx % 1000 == 0:
                            self.warnings.append(f"Packet #{packet_idx} decode warning: {str(p_ex)}")

        except Exception as e:
            self.errors.append(f"Fatal PCAP parsing error {path.name}: {str(e)}")

        logger.info("PCAP file parsed: %d packets, %d warnings, %d errors", len(events), len(self.warnings), len(self.errors))
        return events
