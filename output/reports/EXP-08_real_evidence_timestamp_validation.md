# EXP-08: Real Evidence Timestamp Consistency and Cross-Artifact Validation

**Project:** U-15 – Cross-Artifact Incident Reconstruction from Process, Registry and Network Evidence  
**Experiment:** EXP-08  
**Date:** 22 November 2026  
**Evidence Case:** EXP-03-REPEAT-REAL

## 1. Objective

To investigate timestamp consistency between original Sysmon network events and Wireshark packet captures, validate network-flow correspondence using five-tuple matching, and assess the reliability of timestamps used during cross-artifact correlation.

## 2. Evidence Sources

The experiment examined:

| Evidence source | Original artifact |
|---|---|
| Process Monitor | Logfile.CSV |
| Sysmon | EXP-03-REPEAT-sysmon-window.xml |
| Wireshark | EXP-03-REPEAT-wireshark.pcapng |
| Original Process Monitor capture | Logfile.PML |
| Original Sysmon event log | EXP-03-REPEAT-sysmon.evtx |

The original binary evidence was preserved.

## 3. PCAPNG Metadata

The original PCAPNG was inspected directly.

| Property | Result |
|---|---|
| File size | 17,900,644 bytes |
| Capture software | Dumpcap 4.6.10 |
| Operating system | Windows 11, Build 26300 |
| Interface | Wi-Fi 2 |
| Link type | Ethernet |
| Timestamp resolution | Nanoseconds |
| Packet records | 19,963 |
| Interface count | 1 |
| Explicit timestamp offset | Not present |

Nanosecond resolution indicates timestamp precision, not clock accuracy or synchronization.

## 4. Sysmon Timestamp Investigation

The original XML contained 365 events:

- Event ID 1: 4
- Event ID 3: 7
- Event ID 12: 282
- Event ID 13: 72

All seven Event ID 3 records contained network identifiers, including:

- Source and destination IP addresses
- Source and destination ports
- Protocol
- Process ID
- ProcessGuid
- UtcTime
- Windows SystemTime

The difference between UtcTime and SystemTime exceeded one second for all seven network events.

## 5. Five-Tuple Validation

Each Sysmon network event was compared with the original PCAPNG using:

1. Source IP
2. Destination IP
3. Source port
4. Destination port
5. Protocol

All seven Sysmon network events had at least one matching packet flow.

| Event | Exact five-tuple packet count | Nearest packet to UtcTime | Nearest packet to SystemTime |
|---|---:|---:|---:|
| 1 | 6 | +396.083 ms | -121.781 ms |
| 2 | 6 | +1,897.083 ms | +467.868 ms |
| 3 | 6 | +1,898.083 ms | +467.883 ms |
| 4 | 10 | +1,879.186 ms | -2,365.704 ms |
| 5 | 2 | +1,896.672 ms | -1,714.709 ms |
| 6 | 3 | +391.371 ms | +372.096 ms |
| 7 | 3 | +1,898.371 ms | +435.605 ms |

Positive values indicate that the packet occurred after the reference timestamp; negative values indicate that it occurred before it.

SystemTime was closer to the nearest matching packet in six of seven comparisons. UtcTime was closer in one.

These results do not establish exact packet-to-event correspondence because several events involve repeated traffic on identical five-tuples.

## 6. Findings

### Finding 1: Cross-artifact flow consistency

All seven Sysmon network records had corresponding network flows in the PCAPNG based on exact five-tuple matching.

### Finding 2: Timestamp discrepancy

The Sysmon UtcTime and Windows SystemTime values showed differences of approximately 2.93–4.37 seconds.

### Finding 3: Repeated network traffic

Some Sysmon records shared identical or nearly identical timestamps and network identifiers. Consequently, selecting the nearest packet does not reliably identify the exact packet associated with an individual Sysmon event.

### Finding 4: Capture timestamp metadata

The PCAPNG used nanosecond timestamp resolution. However, no explicit interface timestamp offset was recorded. Clock synchronization accuracy could not be established from the inspected metadata.

## 7. Timestamp Handling Decision

The experiment recommends retaining both timestamp representations independently.

| Timestamp field | Treatment |
|---|---|
| Sysmon UtcTime | Retain as primary event timestamp |
| Windows SystemTime | Preserve separately |
| Timestamp discrepancy | Preserve in metadata |
| Timestamp uncertainty interval | Preserve where available |
| PCAPNG packet timestamp | Retain as independent network observation |

No automatic timestamp shifting or replacement is recommended based on this experiment alone.

## 8. Limitations

1. The experiment contains seven Sysmon network events.
2. Repeated network flows prevent definitive individual packet-to-event attribution in some cases.
3. Nanosecond resolution does not establish clock synchronization accuracy.
4. The experiment does not establish which timestamp source is universally more accurate.
5. Flow correspondence does not independently prove incident attribution accuracy.
6. No exhaustive ground-truth packet-to-event mapping was available.

## 9. Impact on U-15

The results support preserving timestamp provenance and treating temporal uncertainty explicitly during cross-artifact correlation.

The experiment provides additional evidence that network-flow identifiers can support cross-source consistency checks even when timestamp values disagree.

It does not establish an independent improvement in incident reconstruction accuracy.

## 10. Database and Evidence Integrity

This experiment was conducted through read-only inspection of the original Sysmon XML and PCAPNG.

No existing database relationships were regenerated.

No original evidence files were modified.

No ground-truth records were changed.

The existing real-case correlations remain preserved.

## 11. Conclusion

EXP-08 demonstrated five-tuple consistency between seven original Sysmon network events and corresponding network traffic in the Wireshark capture.

The investigation also identified substantial differences between Sysmon UtcTime and Windows SystemTime. Packet-level analysis showed that SystemTime was closer to the nearest matching packet in six of seven comparisons, but repeated network traffic prevented definitive individual packet attribution.

Accordingly, U-15 should preserve both timestamp representations and their provenance rather than automatically replacing one with the other.

The findings strengthen the project's timestamp-handling methodology while identifying independent attribution accuracy as an area requiring further validation.

**Experiment status: Completed – Timestamp consistency investigation.**