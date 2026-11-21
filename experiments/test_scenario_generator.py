"""
Controlled Forensic Experiment Generator for U-15 Incident Reconstruction.
Produces independent cases (development vs held-out). Does not split events from one case.
Network process telemetry is recorded as Sysmon Event ID 3 XML, not Procmon TCP Connect.
Ground truth is written from the experimental script, never from correlation output.
"""
import csv
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

from config.settings import TEST_CASES_DIR, TEST_REGISTRY_SUBKEY, logger
from normalization.normalizer import Normalizer
from experiments.ground_truth_manager import GroundTruthManager
from experiments.experiment_manifest import ExperimentManifest
from experiments.dataset_catalog import AVAILABLE_SCENARIOS, dataset_type_for_scenario
from parsers.sysmon_parser import sysmon_event_id_from_fields
from database.models import Case
import database.db as db

__all__ = ["ControlledExperimentGenerator", "AVAILABLE_SCENARIOS"]

SYSMON_FILE = "sysmon_events.xml"


def _guid(n: int) -> str:
    return "{55555555-0000-4000-8000-%012d}" % n


def _utc_sysmon(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _procmon_tod(dt: datetime) -> str:
    return dt.strftime("%I:%M:%S.%f")[:-3] + " AM"


def _wire_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class ControlledExperimentGenerator:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.case_dir = TEST_CASES_DIR / case_id
        self.case_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _make_procmon_record(
        row_idx: int,
        time_str: str,
        proc: str,
        pid: int,
        op: str,
        path: str,
        result: str = "SUCCESS",
        detail: str = "",
        file_name: str = "procmon_events.csv"
    ) -> Tuple[Dict[str, str], str]:
        row_ref = f"Row {row_idx}"
        op_upper = op.upper()
        if op_upper.startswith("REG"):
            source = "registry"
        else:
            source = "process"
        payload = f"{time_str}|{proc}|{pid}|{op}|{path}"
        eid = Normalizer.generate_event_id(source, file_name, row_ref, payload)
        row_dict = {
            "Time of Day": time_str,
            "Process Name": proc,
            "PID": str(pid),
            "Operation": op,
            "Path": path,
            "Result": result,
            "Detail": detail
        }
        return row_dict, eid

    @staticmethod
    def _make_wireshark_record(
        pkt_no: int,
        time_str: str,
        src_ip: str,
        dst_ip: str,
        proto: str,
        length: int,
        info: str,
        file_name: str = "wireshark_packets.csv"
    ) -> Tuple[Dict[str, str], str]:
        pkt_ref = f"Packet #{pkt_no}"
        transport = Normalizer.normalize_transport_protocol(proto)
        import re
        port_m = re.search(r"(\d{1,5})\s*(?:->|\>)\s*(\d{1,5})", info)
        sport = port_m.group(1) if port_m else ""
        dport = port_m.group(2) if port_m else ""
        payload = f"{pkt_no}|{src_ip}|{dst_ip}|{sport}|{dport}|{transport}"
        eid = Normalizer.generate_event_id("network", file_name, pkt_ref, payload)
        row_dict = {
            "No.": str(pkt_no),
            "Time": time_str,
            "Source": src_ip,
            "Destination": dst_ip,
            "Protocol": proto,
            "Length": str(length),
            "Info": info
        }
        return row_dict, eid

    def _sysmon_eid1(self, idx: int, dt: datetime, guid: str, pid: int, image: str, ppid: Optional[int] = None) -> Tuple[str, str]:
        utc = _utc_sysmon(dt)
        extra = [("<Data Name=\"ParentProcessId\">%s</Data>" % ppid) if ppid is not None else ""]
        xml = self._sysmon_xml_event(1, dt, guid, pid, image, extra)
        eid = sysmon_event_id_from_fields(SYSMON_FILE, idx, 1, utc, guid, pid, image)
        return xml, eid

    def _sysmon_eid3(
        self, idx: int, dt: datetime, guid: str, pid: int, image: str,
        src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str = "tcp", initiated: str = "true"
    ) -> Tuple[str, str]:
        utc = _utc_sysmon(dt)
        extra = [
            f'<Data Name="SourceIp">{src_ip}</Data>',
            f'<Data Name="SourcePort">{src_port}</Data>',
            f'<Data Name="DestinationIp">{dst_ip}</Data>',
            f'<Data Name="DestinationPort">{dst_port}</Data>',
            f'<Data Name="Protocol">{protocol}</Data>',
            f'<Data Name="Initiated">{initiated}</Data>',
        ]
        xml = self._sysmon_xml_event(3, dt, guid, pid, image, extra)
        eid = sysmon_event_id_from_fields(
            SYSMON_FILE, idx, 3, utc, guid, pid, image, src_ip, src_port, dst_ip, dst_port, protocol, initiated
        )
        return xml, eid

    @staticmethod
    def _sysmon_xml_event(event_id: int, dt: datetime, guid: str, pid: int, image: str, extra: List[str]) -> str:
        system_time = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        utc = _utc_sysmon(dt)
        extra_xml = "\n        ".join([e for e in extra if e])
        return f"""  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon"/>
      <EventID>{event_id}</EventID>
      <TimeCreated SystemTime="{system_time}"/>
    </System>
    <EventData>
      <Data Name="UtcTime">{utc}</Data>
      <Data Name="ProcessGuid">{guid}</Data>
      <Data Name="ProcessId">{pid}</Data>
      <Data Name="Image">{image}</Data>
      {extra_xml}
    </EventData>
  </Event>
"""

    def _write_files(self, procmon_rows, reg_lines, wireshark_rows, sysmon_xml_parts) -> Dict[str, Path]:
        procmon_path = self.case_dir / "procmon_events.csv"
        with open(procmon_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"])
            writer.writeheader()
            writer.writerows(procmon_rows)

        reg_path = self.case_dir / "registry_export.reg"
        with open(reg_path, "w", encoding="utf-8") as f:
            f.writelines(reg_lines)

        wireshark_path = self.case_dir / "wireshark_packets.csv"
        with open(wireshark_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
            writer.writeheader()
            writer.writerows(wireshark_rows)

        sysmon_path = self.case_dir / SYSMON_FILE
        with open(sysmon_path, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n')
            f.write("".join(sysmon_xml_parts))
            f.write("</Events>\n")

        return {
            "procmon_file": procmon_path,
            "registry_file": reg_path,
            "wireshark_file": wireshark_path,
            "sysmon_file": sysmon_path,
        }

    def generate_scenario(self, scenario_id: str = "CASE-06-MULTI-ATTACK-01") -> Dict[str, Any]:
        if not db.get_case_by_id(self.case_id):
            db.create_case(Case(
                case_id=self.case_id,
                name=f"Controlled Experiment: {scenario_id}",
                description=f"Auto-generated benchmark case for {scenario_id}",
                collection_date="2026-11-10"
            ))

        base_time = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
        procmon_rows: List[Dict[str, str]] = []
        wireshark_rows: List[Dict[str, str]] = []
        sysmon_xml: List[str] = []
        sysmon_idx = 0
        reg_lines = ["Windows Registry Editor Version 5.00\n\n"]

        incident_event_ids: List[str] = []
        expected_relationships: List[Tuple[str, str, str]] = []
        chronology: List[str] = []
        process_actions: List[Dict[str, Any]] = []
        registry_actions: List[Dict[str, Any]] = []
        network_actions: List[Dict[str, Any]] = []
        dataset_type = dataset_type_for_scenario(scenario_id)

        def add_procmon(dt, proc, pid, op, path, detail="", incident=False):
            r, eid = self._make_procmon_record(len(procmon_rows) + 1, _procmon_tod(dt), proc, pid, op, path, detail=detail)
            procmon_rows.append(r)
            if incident:
                incident_event_ids.append(eid)
                chronology.append(eid)
            return eid

        def add_sysmon1(dt, guid, pid, image, ppid=None, incident=False):
            nonlocal sysmon_idx
            sysmon_idx += 1
            xml, eid = self._sysmon_eid1(sysmon_idx, dt, guid, pid, image, ppid)
            sysmon_xml.append(xml)
            process_actions.append({"action": "process_create", "pid": pid, "process_guid": guid, "image": image, "utc": _utc_sysmon(dt)})
            if incident:
                incident_event_ids.append(eid)
                chronology.append(eid)
            return eid

        def add_sysmon3(dt, guid, pid, image, sip, sport, dip, dport, proto="tcp", incident=False):
            nonlocal sysmon_idx
            sysmon_idx += 1
            xml, eid = self._sysmon_eid3(sysmon_idx, dt, guid, pid, image, sip, sport, dip, dport, proto)
            sysmon_xml.append(xml)
            network_actions.append({
                "action": "sysmon_network_connection", "pid": pid, "process_guid": guid,
                "src_ip": sip, "src_port": sport, "dst_ip": dip, "dst_port": dport, "protocol": proto,
                "utc": _utc_sysmon(dt)
            })
            if incident:
                incident_event_ids.append(eid)
                chronology.append(eid)
            return eid

        def add_wire(dt, src, dst, proto, info, length=66, incident=False):
            r, eid = self._make_wireshark_record(len(wireshark_rows) + 1, _wire_time(dt), src, dst, proto, length, info)
            wireshark_rows.append(r)
            network_actions.append({"action": "packet", "src_ip": src, "dst_ip": dst, "protocol": proto, "info": info, "utc": _wire_time(dt)})
            if incident:
                incident_event_ids.append(eid)
                chronology.append(eid)
            return eid

        # ----- scenarios -----
        if scenario_id == "CASE-01-BENIGN-PROC":
            for i, (name, pid) in enumerate([("svchost.exe", 1004), ("services.exe", 1008), ("explorer.exe", 1012)], 1):
                dt = base_time + timedelta(seconds=i)
                add_procmon(dt, name, pid, "Process Start", rf"C:\Windows\System32\{name}", detail=f"PID: {pid}")
                add_sysmon1(dt, _guid(i), pid, rf"C:\Windows\System32\{name}")

        elif scenario_id == "CASE-02-BENIGN-NET":
            for i in range(1, 4):
                add_wire(base_time + timedelta(seconds=i), "192.168.1.10", "8.8.8.8", "DNS", f"{50000+i} -> 53 Standard query A time.windows.com", length=68)

        elif scenario_id == "CASE-03-BENIGN-REG":
            reg_lines.extend([r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]", "\n", '"CleanCheck"=dword:00000001\n\n'])
            registry_actions.append({"action": "snapshot_value", "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer", "name": "CleanCheck"})

        elif scenario_id == "CASE-04-PROC-REG-BENIGN":
            # Benign baseline: normal user application (notepad) with registry activity
            pid, guid = 2200, _guid(4)
            e1 = add_procmon(base_time + timedelta(seconds=1), "notepad.exe", pid, "Process Create", r"C:\Windows\System32\notepad.exe", detail=f"PID: {pid}, Parent PID: 1012", incident=False)
            add_sysmon1(base_time + timedelta(seconds=1), guid, pid, r"C:\Windows\System32\notepad.exe", 1012, incident=False)
            e3 = add_procmon(base_time + timedelta(seconds=2), "notepad.exe", pid, "RegSetValue", rf"HKCU\{TEST_REGISTRY_SUBKEY}\LastFile", detail="Type: REG_SZ, Data: notes.txt", incident=False)
            reg_lines.extend([f"[HKEY_CURRENT_USER\\{TEST_REGISTRY_SUBKEY}]\n", '"LastFile"="notes.txt"\n\n'])
            registry_actions.append({"action": "reg_set_value", "key": rf"HKCU\{TEST_REGISTRY_SUBKEY}\LastFile", "pid": pid})

        elif scenario_id == "CASE-05-PROC-NET-BENIGN":
            # Benign baseline: normal utility (curl) web request
            pid, guid = 2300, _guid(5)
            sip, sport, dip, dport = "192.168.1.20", 51000, "93.184.216.34", 80
            e1 = add_procmon(base_time + timedelta(seconds=1), "curl.exe", pid, "Process Start", r"C:\Windows\System32\curl.exe", incident=False)
            es1 = add_sysmon1(base_time + timedelta(seconds=1), guid, pid, r"C:\Windows\System32\curl.exe", incident=False)
            es3 = add_sysmon3(base_time + timedelta(seconds=2), guid, pid, r"C:\Windows\System32\curl.exe", sip, sport, dip, dport, incident=False)
            ew = add_wire(base_time + timedelta(seconds=2, milliseconds=20), sip, dip, "TCP", f"{sport} -> {dport} [SYN]", incident=False)

        elif scenario_id in ("CASE-10-PID-REUSE", "CASE-21-HELD-OUT-PID-REUSE"):
            recycled = 4000
            g_a, g_b = _guid(10), _guid(11)
            add_procmon(base_time + timedelta(seconds=1), "ServiceA.exe", recycled, "Process Start", r"C:\Windows\System32\ServiceA.exe")
            add_sysmon1(base_time + timedelta(seconds=1), g_a, recycled, r"C:\Windows\System32\ServiceA.exe")
            add_procmon(base_time + timedelta(seconds=5), "ServiceA.exe", recycled, "Process Exit", r"C:\Windows\System32\ServiceA.exe")
            e_mal = add_procmon(base_time + timedelta(seconds=15), "mal_agent.exe", recycled, "Process Start", r"C:\IncidentLab\mal_agent.exe", incident=True)
            es1 = add_sysmon1(base_time + timedelta(seconds=15), g_b, recycled, r"C:\IncidentLab\mal_agent.exe", incident=True)
            sip, sport, dip, dport = "192.168.1.100", 49200, "198.51.100.99", 443
            es3 = add_sysmon3(base_time + timedelta(seconds=18), g_b, recycled, r"C:\IncidentLab\mal_agent.exe", sip, sport, dip, dport, incident=True)
            ew = add_wire(base_time + timedelta(seconds=18, milliseconds=50), sip, dip, "TCP", f"{sport} -> {dport} [SYN]", incident=True)
            expected_relationships.append((es1, es3, "CONNECTED_TO"))
            expected_relationships.append((es3, ew, "OBSERVED_IN"))

        elif scenario_id == "CASE-15-REVERSE-PACKETS":
            pid, guid = 2222, _guid(15)
            sip, sport, dip, dport = "192.168.1.50", 50123, "203.0.113.10", 80
            add_procmon(base_time + timedelta(seconds=1), "curl.exe", pid, "Process Start", r"C:\Windows\System32\curl.exe", incident=True)
            es1 = add_sysmon1(base_time + timedelta(seconds=1), guid, pid, r"C:\Windows\System32\curl.exe", incident=True)
            es3 = add_sysmon3(base_time + timedelta(seconds=2), guid, pid, r"C:\Windows\System32\curl.exe", sip, sport, dip, dport, incident=True)
            ew1 = add_wire(base_time + timedelta(seconds=2, milliseconds=10), sip, dip, "TCP", f"{sport} -> {dport} [SYN]", incident=True)
            ew2 = add_wire(base_time + timedelta(seconds=2, milliseconds=35), dip, sip, "TCP", f"{dport} -> {sport} [SYN, ACK]", incident=True)
            expected_relationships.append((es1, es3, "CONNECTED_TO"))
            expected_relationships.append((es3, ew1, "OBSERVED_IN"))
            expected_relationships.append((es3, ew2, "OBSERVED_IN"))

        elif scenario_id == "CASE-16-DEEP-PROCESS-TREE":
            pids = [1100, 1200, 1300, 1400]
            names = ["loader.exe", "cmd.exe", "powershell.exe", "whoami.exe"]
            prev_eid = None
            for idx, (p_name, pid) in enumerate(zip(names, pids), 1):
                ppid = pids[idx - 2] if idx > 1 else 900
                dt = base_time + timedelta(seconds=idx * 2)
                eid = add_procmon(dt, p_name, pid, "Process Create", rf"C:\Tools\{p_name}", detail=f"PID: {pid}, Parent PID: {ppid}", incident=True)
                add_sysmon1(dt, _guid(160 + idx), pid, rf"C:\Tools\{p_name}", ppid, incident=True)
                if prev_eid:
                    expected_relationships.append((prev_eid, eid, "SPAWNED"))
                prev_eid = eid

        elif scenario_id == "CASE-19-CONCURRENT-PROCESSES":
            # Two concurrent processes, distinct GUIDs, only proc A is incident C2
            a_pid, b_pid = 3100, 3200
            ga, gb = _guid(19), _guid(191)
            ea = add_procmon(base_time + timedelta(seconds=1), "agentA.exe", a_pid, "Process Create", r"C:\IncidentLab\agentA.exe", detail="PID: 3100, Parent PID: 1204", incident=True)
            add_procmon(base_time + timedelta(seconds=1, milliseconds=50), "updateB.exe", b_pid, "Process Create", r"C:\Program Files\Update\updateB.exe", detail="PID: 3200, Parent PID: 1204")
            esa = add_sysmon1(base_time + timedelta(seconds=1), ga, a_pid, r"C:\IncidentLab\agentA.exe", 1204, incident=True)
            add_sysmon1(base_time + timedelta(seconds=1, milliseconds=50), gb, b_pid, r"C:\Program Files\Update\updateB.exe", 1204)
            es3a = add_sysmon3(base_time + timedelta(seconds=3), ga, a_pid, r"C:\IncidentLab\agentA.exe", "192.168.1.40", 40001, "198.51.100.20", 443, incident=True)
            add_sysmon3(base_time + timedelta(seconds=3, milliseconds=80), gb, b_pid, r"C:\Program Files\Update\updateB.exe", "192.168.1.40", 40002, "13.107.4.50", 443)
            ewa = add_wire(base_time + timedelta(seconds=3, milliseconds=15), "192.168.1.40", "198.51.100.20", "TCP", "40001 -> 443 [SYN]", incident=True)
            add_wire(base_time + timedelta(seconds=3, milliseconds=90), "192.168.1.40", "13.107.4.50", "TCP", "40002 -> 443 [SYN]")
            expected_relationships.append((esa, es3a, "CONNECTED_TO"))
            expected_relationships.append((es3a, ewa, "OBSERVED_IN"))

        else:
            # Shared multi-source template with scenario-specific omissions/noise
            app_pid, child_pid = 4128, 5892
            guid = _guid(60)
            attacker_ip, attacker_port = "198.51.100.45", 8080
            local_ip, local_port = "192.168.1.105", 49822
            include_reg = scenario_id not in ("CASE-12-MISSING-REG", "CASE-22-HELD-OUT-MISSING-REG-NOISE")
            include_sysmon_net = scenario_id not in ("CASE-11-MISSING-NET", "CASE-13-MISSING-SOCK-TELEMETRY")
            include_wire = scenario_id not in ("CASE-11-MISSING-NET",)
            heavy_net = "HEAVY-NOISE" in scenario_id or scenario_id in ("CASE-14-UNATTRIBUTED-WIRE", "CASE-22-HELD-OUT-MISSING-REG-NOISE", "CASE-08-NET-HEAVY-NOISE")
            heavy_reg = scenario_id in ("CASE-09-REG-HEAVY-NOISE",)
            staged = scenario_id == "CASE-17-STAGED-PERSISTENCE"
            disconnected = scenario_id == "CASE-18-DISCONNECTED-TEMPORAL"
            mixed = scenario_id in ("CASE-20-HELD-OUT-MIXED", "CASE-07-MULTI-ATTACK-02")

            noise_n = 20 if heavy_reg else 5
            for i in range(1, noise_n + 1):
                add_procmon(base_time - timedelta(seconds=noise_n * 2 - i * 2), "svchost.exe", 844, "RegOpenKey", r"HKLM\System\CurrentControlSet\Services\Schedule")

            e1 = add_procmon(
                base_time + timedelta(seconds=1), "TestApp.exe", app_pid, "Process Create",
                r"C:\IncidentLab\TestApp.exe", detail=f"PID: {app_pid}, Parent PID: 1204", incident=True
            )
            es1 = add_sysmon1(base_time + timedelta(seconds=1), guid, app_pid, r"C:\IncidentLab\TestApp.exe", 1204, incident=True)
            e2 = add_procmon(
                base_time + timedelta(seconds=2), "TestApp.exe", app_pid, "CreateFile",
                r"C:\IncidentLab\payload.bin", detail="Disposition: Create", incident=True
            )

            if include_reg:
                e3 = add_procmon(
                    base_time + timedelta(seconds=3), "TestApp.exe", app_pid, "RegSetValue",
                    rf"HKCU\{TEST_REGISTRY_SUBKEY}\PayloadPath",
                    detail=r"Type: REG_SZ, Data: C:\IncidentLab\payload.bin", incident=True
                )
                expected_relationships.append((e1, e3, "MODIFIED"))
                registry_actions.append({"action": "reg_set_value", "key": rf"HKCU\{TEST_REGISTRY_SUBKEY}\PayloadPath", "pid": app_pid})
                reg_lines.extend([
                    f"[HKEY_CURRENT_USER\\{TEST_REGISTRY_SUBKEY}]\n",
                    '"Installed"=dword:00000001\n',
                    '"PayloadPath"="C:\\\\IncidentLab\\\\payload.bin"\n\n',
                ])
                if staged:
                    e_run = add_procmon(
                        base_time + timedelta(seconds=3, milliseconds=200), "TestApp.exe", app_pid, "RegSetValue",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\IncidentLab",
                        detail=r"Type: REG_SZ, Data: C:\IncidentLab\TestApp.exe", incident=True
                    )
                    expected_relationships.append((e1, e_run, "MODIFIED"))
                    registry_actions.append({"action": "reg_set_value", "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\IncidentLab", "pid": app_pid})

            es3 = None
            if include_sysmon_net:
                es3 = add_sysmon3(
                    base_time + timedelta(seconds=5), guid, app_pid, r"C:\IncidentLab\TestApp.exe",
                    local_ip, local_port, attacker_ip, attacker_port, incident=True
                )
                expected_relationships.append((es1, es3, "CONNECTED_TO"))

            if include_wire and include_sysmon_net and es3:
                ew1 = add_wire(base_time + timedelta(seconds=5, milliseconds=120), local_ip, attacker_ip, "TCP", f"{local_port} -> {attacker_port} [SYN] Seq=0", incident=True)
                ew2 = add_wire(base_time + timedelta(seconds=5, milliseconds=145), attacker_ip, local_ip, "TCP", f"{attacker_port} -> {local_port} [SYN, ACK] Seq=0 Ack=1", incident=True)
                ew3 = add_wire(base_time + timedelta(seconds=5, milliseconds=160), local_ip, attacker_ip, "TCP", f"{local_port} -> {attacker_port} [PSH, ACK] Seq=1 Ack=1 Len=446", length=512, incident=True)
                expected_relationships.append((es3, ew1, "OBSERVED_IN"))
                expected_relationships.append((es3, ew2, "OBSERVED_IN"))
                expected_relationships.append((es3, ew3, "OBSERVED_IN"))
            elif include_wire and not include_sysmon_net:
                add_wire(base_time + timedelta(seconds=5, milliseconds=120), local_ip, attacker_ip, "TCP", f"{local_port} -> {attacker_port} [SYN] Seq=0")

            if heavy_net or scenario_id == "CASE-14-UNATTRIBUTED-WIRE":
                for n_idx in range(1, 11):
                    add_wire(
                        base_time + timedelta(seconds=4, milliseconds=n_idx * 150),
                        f"10.0.0.{n_idx + 10}", "8.8.8.8", "UDP",
                        f"{40000 + n_idx} -> 53 Standard query DNS", length=78
                    )

            e6 = add_procmon(
                base_time + timedelta(seconds=7), "cmd.exe", child_pid, "Process Create",
                r"C:\Windows\System32\cmd.exe", detail=f"PID: {child_pid}, Parent PID: {app_pid}", incident=True
            )
            add_sysmon1(base_time + timedelta(seconds=7), _guid(61), child_pid, r"C:\Windows\System32\cmd.exe", app_pid, incident=True)
            expected_relationships.append((e1, e6, "SPAWNED"))

            if disconnected:
                add_wire(base_time + timedelta(seconds=90), "10.9.9.9", "1.1.1.1", "UDP", "53000 -> 53 Standard query A unrelated.example")
            if mixed:
                add_wire(base_time + timedelta(seconds=6), "192.168.1.200", "9.9.9.9", "UDP", "5353 -> 53 mDNS")

        paths = self._write_files(procmon_rows, reg_lines, wireshark_rows, sysmon_xml)
        end_time = base_time + timedelta(seconds=120)

        evidence_refs = [
            {"role": "procmon", "path": str(paths["procmon_file"])},
            {"role": "registry", "path": str(paths["registry_file"])},
            {"role": "wireshark", "path": str(paths["wireshark_file"])},
            {"role": "sysmon_xml", "path": str(paths["sysmon_file"])},
        ]

        ExperimentManifest.save(
            case_id=self.case_id,
            scenario=scenario_id,
            experiment_start=base_time.isoformat(),
            experiment_end=end_time.isoformat(),
            actual_process_actions=process_actions,
            actual_registry_actions=registry_actions,
            actual_network_actions=network_actions,
            expected_event_relationships=expected_relationships,
            expected_chronology=chronology,
            evidence_file_references=evidence_refs,
            dataset_type=dataset_type,
            notes="Recorded by the experiment generator before any correlation run.",
        )

        GroundTruthManager.save_ground_truth(
            case_id=self.case_id,
            scenario_name=scenario_id,
            incident_event_ids=incident_event_ids,
            expected_relationships=expected_relationships,
            ground_truth_chronology=chronology,
            dataset_type=dataset_type,
            notes=f"Independent experiment labels for {scenario_id}",
            origin="experiment_manifest",
        )

        return {
            "scenario_id": scenario_id,
            "dataset_type": dataset_type,
            "procmon_file": str(paths["procmon_file"]),
            "registry_file": str(paths["registry_file"]),
            "wireshark_file": str(paths["wireshark_file"]),
            "sysmon_file": str(paths["sysmon_file"]),
            "ground_truth_events": len(incident_event_ids),
            "expected_relationships": len(expected_relationships),
        }

    def generate_synthetic_incident_dataset(
        self,
        scenario_name: str = "Triage-Attack-Chain-01",
        noise_events_count: int = 15
    ) -> Dict[str, Any]:
        return self.generate_scenario("CASE-06-MULTI-ATTACK-01")

    def generate_all_catalog_cases(self, prefix: str = "") -> List[Dict[str, Any]]:
        results = []
        for scenario in AVAILABLE_SCENARIOS:
            case_id = f"{prefix}{scenario}" if prefix else scenario
            gen = ControlledExperimentGenerator(case_id)
            results.append(gen.generate_scenario(scenario))
        return results

    def execute_live_safe_activity(self) -> Dict[str, Any]:
        executed_steps = []
        test_file = self.case_dir / "incidentlab_harmless.tmp"
        with open(test_file, "w") as f:
            f.write("IncidentLab Benign Test Marker - " + datetime.now().isoformat())
        executed_steps.append(f"Created harmless file: {test_file.name}")

        if sys.platform == "win32":
            try:
                import winreg
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, TEST_REGISTRY_SUBKEY)
                winreg.SetValueEx(key, "AuditTestMarker", 0, winreg.REG_SZ, datetime.now().isoformat())
                winreg.CloseKey(key)
                executed_steps.append(rf"Wrote safe Registry key: HKCU\{TEST_REGISTRY_SUBKEY}")
            except Exception as e:
                executed_steps.append(f"Registry operation error: {e}")

        try:
            import subprocess
            proc = subprocess.run(["cmd.exe", "/c", "echo", "IncidentLab Safe Process"], capture_output=True, text=True)
            executed_steps.append(f"Launched benign child process: cmd.exe (Exit: {proc.returncode})")
        except Exception as e:
            executed_steps.append(f"Child process error: {e}")

        return {"status": "Success", "executed_steps": executed_steps, "timestamp": datetime.now(timezone.utc).isoformat()}
