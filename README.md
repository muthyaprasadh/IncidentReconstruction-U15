# U-15 | Cross-Artifact Incident Reconstruction

A local Windows digital-forensics research prototype that parses process, Registry, Sysmon socket, and Wireshark evidence; correlates supported relationships; builds a provenance-aware NetworkX graph; and produces an incident timeline.

> **Research question:** Can correlated endpoint and network traces reconstruct an incident more accurately than isolated analysis?

## Important scope and evidence labels

This repository contains both a software prototype and synthetic scenario generators. Synthetic evidence is useful for parser, correlation, graph, and test validation. It is **not** a real Procmon, Sysmon, or Wireshark capture and its metrics must not be presented as real-world research results.

Real research evaluation requires independently executed Windows experiments, actual exported evidence, independently recorded ground truth, and held-out cases. The project does not claim to be an antivirus, production EDR, court-admissible forensic suite, or superior to commercial XDR products.

## Architecture

| Evidence/tool | Role |
|---|---|
| Process Monitor (Procmon) | Process, file-system, and Registry operations |
| Sysmon Event ID 1 | Process creation and ProcessGuid |
| Sysmon Event ID 3 | Endpoint network connection telemetry, including process and socket tuple |
| Wireshark / PCAP | Packet-level network evidence |
| Registry `.reg` export | Static Registry state snapshot only; no historical modification timestamps |
| Python + Pandas | Parsing and normalization |
| NetworkX | Directed multi-edge evidence graph |
| Streamlit | Local investigation dashboard |
| SQLite | Local case/event/relationship storage |

### Network attribution rule

Wireshark records packets, not Windows PIDs. The system never attributes a packet to a process using timestamps alone. Process-to-network linkage requires Sysmon Event ID 3 endpoint telemetry. Sysmon-to-Wireshark corroboration requires a complete exact five-tuple (source IP, destination IP, source port, destination port, transport protocol), forward or reverse direction, and either a reliable timestamp within the configured window or a packet timestamp inside the bounded `UtcTime`/`SystemTime` uncertainty interval. Uncertain intervals wider than the configured window are not used. If a Sysmon event has no ProcessGuid and no reliable scalar timestamp, PID attribution additionally requires a matching packet observed while that PID's validated process epoch is active. Missing tuple fields do not act as wildcards.

### Timestamp rule

Procmon `Time of Day` is local wall-clock time. The investigator must supply the case collection date and capture timezone (the UI defaults to `Asia/Kolkata`, which should be changed if the capture machine used another timezone). Wireshark relative capture offsets are not absolute timestamps; export `frame.time_epoch` or use PCAP/PCAPNG for absolute packet times. Sysmon preserves both `UtcTime` and XML `SystemTime`; it warns and omits the chronology timestamp when the two differ by more than one second, retaining their range as explicit uncertainty metadata. A valid timezone-aware XML `SystemTime` is used as a warned fallback when `UtcTime` cannot be parsed.

## Project layout

- `app/` — Streamlit pages and visual components
- `parsers/` — Procmon, Sysmon, Registry, and Wireshark parsers
- `normalization/` — event normalization, timestamps, IDs, deduplication
- `correlation/` — process, Registry, and network correlation
- `graph/` — NetworkX graph construction and analysis
- `reconstruction/` — timeline, narrative, PDF report
- `evaluation/` — baselines, metrics, ablation, sensitivity
- `experiments/` — synthetic scenario templates and ground-truth manifests
- `tests/` — automated backend/audit tests
- `config/sysmonconfig.xml` — minimal Sysmon configuration for Event IDs 1 and 3
- `scripts/` — synthetic end-to-end demo and scenario-catalog validation

## Windows installation

Use Python 3.11 or newer. From PowerShell, in the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run this once in the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run tests

```powershell
python -m unittest tests.test_backend tests.test_audit
```

## Run the application

```powershell
python run.py
```

Open `http://localhost:8501` in a browser.

## Run a synthetic end-to-end demonstration

```powershell
python scripts/run_synthetic_demo.py
```

The script generates synthetic Procmon-like CSV, Registry snapshot, Wireshark-like CSV, and Sysmon XML evidence, then runs parsing, correlation, graph construction, timeline generation, and baseline evaluation. Outputs are written under `output/demo/`, `output/graphs/`, and `output/charts/`. These results are software smoke-test outputs only.

To generate and validate all 22 scenario templates:

```powershell
python scripts/validate_synthetic_catalog.py
```

This validates that each synthetic scenario's ground-truth event IDs map to parsed event IDs and that development/held-out template labels do not overlap. It does not create 22 real-world captures.

## Collect real evidence on Windows

### 1. Sysmon

Download Sysmon from Microsoft Sysinternals. Open an elevated PowerShell terminal in the folder containing `Sysmon64.exe` and install the supplied configuration:

```powershell
.\Sysmon64.exe -accepteula -i .\config\sysmonconfig.xml
```

The included configuration enables Process Create (Event ID 1) and Network Connect (Event ID 3) collection. Review your organization's privacy and collection requirements before enabling broad telemetry. Export the Sysmon Operational channel after the experiment:

```powershell
wevtutil epl Microsoft-Windows-Sysmon/Operational .\sysmon_capture.evtx
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:true > .\sysmon_events.xml
```

Upload the XML export. Binary `.evtx` parsing is not implemented in this version.

### 2. Procmon

1. Run Procmon as Administrator.
2. Start capture immediately before the controlled experiment.
3. Stop capture immediately after it.
4. Save **All events** as CSV.
5. Record the capture date and timezone; enter the timezone in the evidence upload page.

Procmon is used for process and Registry/file operations. Do not treat it as the network socket attribution source in this project.

### 3. Wireshark

1. Capture on the correct network interface during the same controlled experiment.
2. Save the original `.pcapng` or `.pcap` file when possible.
3. The application can parse PCAP/PCAPNG when Scapy is installed.
4. For CSV, export fields including `frame.time_epoch`, `ip.src`, `ip.dst`, transport source/destination ports, and transport protocol where possible. Wireshark's default relative `Time` column is not an absolute timestamp.

### 4. Registry evidence

For the controlled lab key only, a `.reg` export can document the final state:

```powershell
reg.exe export "HKCU\Software\IncidentLab" ".\registry_export.reg" /y
```

A `.reg` file is a static snapshot, not a timestamped Registry operation history. Use Procmon's Registry events for timestamped process-attributed operations.

### 5. Controlled experiment hygiene

Use harmless test programs and a dedicated test Registry path such as `HKCU\Software\IncidentLab`. Do not use malware or modify critical Windows Registry locations. Capture all sources over the same experiment interval and preserve original files.

## Evaluation methodology

The intended comparisons are:

1. Process-only evidence.
2. Process + Registry evidence.
3. All sources with conventional one-hop rule-based correlation (no graph traversal).
4. Proposed provenance-aware graph traversal.

Report event detection and relationship prediction separately. Metrics include precision, recall, F1, false-positive rate, relationship precision/recall/F1, and timeline ordering. Ablation removes evidence sources; sensitivity analysis varies the temporal window.

A fair held-out evaluation must use independent experiment sessions/cases, not randomly split events from one incident. The authoritative synthetic scenario catalog defines **19 development scenarios (CASE-01 through CASE-19)** and **3 held-out scenarios (CASE-20 through CASE-22)**. These synthetic templates become real held-out captures only after independent Windows collection and ground-truth validation.

## Known limitations

- Binary EVTX parsing is not implemented; export Sysmon XML.
- `.reg` snapshots do not contain historical Registry operation times.
- Network process attribution depends on Sysmon Event ID 3 being enabled and present.
- A Sysmon-to-PCAP match is corroboration, not proof of application-level intent.
- ProcessGuid availability and event loss depend on Sysmon configuration and collection.
- Procmon time-of-day records need the correct case date and timezone.
- Synthetic evaluation is not a substitute for held-out real experiments.
- The current rule-based seed policy and baseline heuristics require further methodological justification before publication.
- Reports are research summaries, not certified or court-admissible forensic exhibits.

## Research integrity

Never invent ground truth, silently repair missing timestamps, attribute packets to PIDs from time proximity alone, or present synthetic metrics as measured real-world performance. Preserve original evidence files, SHA-256 hashes, parser warnings, event references, and relationship explanations.
