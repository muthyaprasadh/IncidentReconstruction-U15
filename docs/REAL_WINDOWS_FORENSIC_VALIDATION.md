# Real Windows Forensic Validation

This guide defines the evidence capture required to validate the platform beyond synthetic scenarios. It does not claim a real Windows capture has occurred until exported artifacts and a signed ground-truth manifest are present.

## 1. Controlled Environment

- Use an isolated Windows 10/11 host.
- Record OS build, CPU, RAM, installed tools, collection date, and time zone.
- Synchronize Windows time and display UTC timestamps during capture.
- Install Sysmon and apply `config/sysmonconfig.xml`.
- Start Process Monitor and use a dedicated PML export.
- Start Wireshark on the relevant interface and save a PCAP/PCAPNG capture.
- Keep all test commands and timestamps in a separate experiment log.

## 2. Required Three Experiments

| Experiment | Benign activity | Required ground truth |
|---|---|---|
| RW-01 | Start and terminate a benign executable | Process start/end times, PID, PPID, executable path |
| RW-02 | Start a process and communicate with a local or controlled remote endpoint | RW-01 fields plus destination IP, port, protocol and process name |
| RW-03 | Execute a process, modify a controlled Registry key, and communicate | RW-02 fields plus Registry key, value, operation and modification time |

The Registry key must be written only to a test namespace such as `HKCU\Software\U15Forensics\Experiment`.

## 3. Exports

Export:

- Sysmon XML Event Log
- Procmon CSV with process, file, Registry and network columns
- Wireshark CSV or the original PCAP/PCAPNG
- Registry evidence for the controlled test key
- Experiment log and ground-truth JSON

Do not edit timestamp or identity fields after capture. Preserve SHA-256 hashes of every original artifact.

## 4. Ground Truth Format

Place independent ground truth at `data/ground_truth/<CASE-ID>_ground_truth.json`.

Required fields:

```json
{
  "case_id": "RW-01",
  "dataset_type": "real_world",
  "independent_of_correlation_engine": true,
  "incident_event_ids": [],
  "expected_relationships": [],
  "ground_truth_chronology": [],
  "evidence_mappings": [],
  "notes": ""
}
```

`incident_event_ids` must correspond only to events observed in the exported evidence. Relationships must be recorded by their source event ID, target event ID and type.

## 5. Ingestion

Use the Evidence Upload dashboard to create an active case and upload Sysmon XML, Procmon CSV, Registry `.reg`, and Wireshark/PCAP evidence. Review parsed counts, parser warnings and evidence hashes before correlation.

## 6. Validation Rules

Reject the experiment when:

- Required evidence sources are missing.
- Artifact timestamps or host time zone cannot be reconciled.
- Ground truth was derived from predicted relationships.
- Process, PID, ProcessGuid or socket fields are reconstructed rather than observed.
- The ground-truth event IDs cannot be matched to normalized evidence IDs.

Run the standard synthetic suite only for software regression. Do not mix synthetic and real-world metrics in headline claims.
