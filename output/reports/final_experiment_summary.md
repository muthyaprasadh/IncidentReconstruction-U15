# Cross-Artifact Incident Reconstruction — Experimental Results

**Report generated:** 2026-11-21 11:11 UTC

## 1. Experimental Overview

This evaluation compares four investigation methods across 22 benchmark scenarios:

1. Process-only investigation.
2. Network-only investigation.
3. Rule-based correlation.
4. Proposed cross-artifact graph correlation.

The benchmark contains 19 development scenarios and 3 designated held-out test scenarios.

The measurements below are read from the existing `evaluation_metrics.csv`. This report-generation script does not rerun experiments or modify the underlying benchmark measurements.

## 2. Evaluation Metrics

The evaluation includes event-level precision, recall, F1-score, false-positive rate and event coverage, together with relationship-level F1-score and timeline accuracy.

**Aggregation note:** The reported values are means across scenario-level measurements. They are not pooled, micro-averaged measurements across all events.

## 3. Overall Results

| Investigation Method | Scenarios | Precision | Recall | F1 | False Positive Rate | Event Coverage | Relationship F1 | Timeline Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Method 1: Process-Only | 22 | 0.6955 | 0.4378 | 0.5227 | 0.2000 | 0.6651 | 0.0000 | 0.7727 |
| Method 2: Network-Only | 22 | 0.4565 | 0.2797 | 0.3296 | 0.2057 | 0.5069 | 0.4273 | 0.6364 |
| Method 3: Rule-Based Correlation | 22 | 0.7045 | 0.5823 | 0.6253 | 0.2318 | 0.8096 | 0.4758 | 0.7727 |
| Method 4: Proposed Cross-Artifact Graph | 22 | 0.7110 | 0.7727 | 0.7328 | 0.2545 | 1.0000 | 0.6885 | 0.7727 |

## 4. Development Results

| Investigation Method | Scenarios | Precision | Recall | F1 | False Positive Rate | Event Coverage | Relationship F1 | Timeline Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Method 1: Process-Only | 19 | 0.6789 | 0.4251 | 0.5091 | 0.1789 | 0.6882 | 0.0000 | 0.7368 |
| Method 2: Network-Only | 19 | 0.4188 | 0.2531 | 0.3002 | 0.1972 | 0.5162 | 0.3851 | 0.5789 |
| Method 3: Rule-Based Correlation | 19 | 0.6842 | 0.5628 | 0.6070 | 0.2158 | 0.8260 | 0.4579 | 0.7368 |
| Method 4: Proposed Cross-Artifact Graph | 19 | 0.6880 | 0.7368 | 0.7049 | 0.2421 | 1.0000 | 0.6481 | 0.7368 |

## 5. Held-Out Test Results

| Investigation Method | Scenarios | Precision | Recall | F1 | False Positive Rate | Event Coverage | Relationship F1 | Timeline Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Method 1: Process-Only | 3 | 0.8000 | 0.5185 | 0.6085 | 0.3333 | 0.5185 | 0.0000 | 1.0000 |
| Method 2: Network-Only | 3 | 0.6952 | 0.4481 | 0.5159 | 0.2593 | 0.4481 | 0.6945 | 1.0000 |
| Method 3: Rule-Based Correlation | 3 | 0.8333 | 0.7056 | 0.7412 | 0.3333 | 0.7056 | 0.5889 | 1.0000 |
| Method 4: Proposed Cross-Artifact Graph | 3 | 0.8571 | 1.0000 | 0.9091 | 0.3333 | 1.0000 | 0.9441 | 1.0000 |

## 6. Findings

### 6.1 Event Detection

Across all 22 scenarios, the proposed cross-artifact graph method achieved an F1-score of **0.7328**, compared with **0.6253** for rule-based correlation.

On the development split, the proposed method achieved an F1-score of **0.7049**, compared with **0.6070** for rule-based correlation.

On the designated held-out test split, the proposed method achieved an F1-score of **0.9091**, compared with **0.7412** for rule-based correlation.

### 6.2 Evidence Coverage

The proposed method achieved mean event coverage of **1.0000** across all scenarios.

This supports the finding that cross-artifact correlation recovered a broader set of labeled incident events in this benchmark.

### 6.3 Relationship Reconstruction

The proposed method achieved an overall mean relationship F1-score of **0.6885**.

Relationship reconstruction should be interpreted alongside the event-level results and the ground-truth labeling scope.

### 6.4 False-Positive Trade-off

The proposed method's overall mean false-positive rate was **0.2545**, compared with **0.2318** for rule-based correlation.

On the development split, the proposed method's false-positive rate was **0.2421**, compared with **0.2158**.

Therefore, these results do not demonstrate false-positive suppression by the proposed method. Its improved recall and coverage are accompanied by a false-positive-rate trade-off.

## 7. Interpretation

The benchmark results indicate that the proposed cross-artifact graph approach improves mean event recall, F1-score and event coverage compared with the rule-based baseline across the evaluated splits.

The strongest observed difference is in event coverage, where the proposed method reaches complete mean coverage in the reported benchmark measurements.

However, the false-positive-rate results show that improved evidence recovery does not automatically imply fewer false positives. The proposed method should therefore be understood as a coverage-oriented reconstruction approach with a precision trade-off, rather than a universally superior detector.

The held-out results are based on three scenarios. They provide an initial test-split evaluation, but the small number of scenarios limits the strength of generalization claims.

## 8. Ablation and Sensitivity Interpretation

The separately stored ablation and sensitivity results must be interpreted according to the measured outcomes:

- Removing registry evidence caused measurable degradation in the inspected ablation scenarios.
- Removing exact five-tuple network matching caused the largest measured degradation in those scenarios.
- Removing ProcessGuid, timestamp-window constraints or process-lifetime handling did not produce measurable degradation in the inspected ablation results. These safeguards remain design choices, but their empirical contribution was not demonstrated by those tests.
- The tested temporal windows did not show a measurable performance difference in the inspected sensitivity results. The experiments therefore do not establish that a five-second window is optimal.
- PID-reuse and concurrent-process stress cases showed elevated false-positive rates. The method should not be described as maintaining low false-positive rates under every stress condition.

These findings are limited to the scenarios and configurations represented in the existing experiment files.

## 9. Real-World Validation Scope

Synthetic benchmark results must be distinguished from the separately conducted controlled Windows experiment.

The controlled Windows experiment used benign activity, including process execution, registry changes and a network connection. It is not a real data-theft incident and must not be presented as one.

In that experiment, the proposed graph and conventional all-source method each matched all 30 annotated expected relationships within the evaluated scope. This is annotated relationship coverage, not a complete relationship precision or F1 measurement.

The experiment does not establish that the proposed graph outperforms conventional all-source correlation in real-world investigations.

## 10. Limitations

1. The benchmark contains a limited number of scenarios, including only three held-out test scenarios.
2. Synthetic evidence cannot fully represent the complexity of enterprise incidents.
3. The controlled Windows validation represents one benign experiment, not a malicious incident.
4. Encrypted network payloads limit application-level interpretation.
5. Timestamp discrepancies and incomplete endpoint telemetry can restrict event chronology and attribution.
6. Relationship metrics depend on the completeness and scope of the annotated ground truth.
7. Elevated false-positive rates in certain stress scenarios require further investigation.
8. The results do not establish forensic admissibility or production readiness.

## 11. Conclusion

The evaluated results support the use of cross-artifact graph correlation to improve incident-event recovery and relationship reconstruction coverage across the tested benchmark scenarios.

The proposed method achieved higher mean F1-score and event coverage than the rule-based baseline. However, the false-positive-rate trade-off, limited held-out sample size and restricted real-world validation scope must remain explicit.

Further evaluation using independently collected enterprise evidence, larger held-out datasets and more exhaustive ground-truth annotations is required before making broader generalization claims.

---

## 12. EXP-08: Real Evidence Timestamp Consistency and Cross-Artifact Validation

**Evidence case:** EXP-03-REPEAT-REAL

**Status:** Completed — timestamp consistency investigation.

### Objective
Investigate timestamp differences between original Sysmon network events and Wireshark packet captures using five-tuple matching.

### Results
- Inspected 7 original Sysmon Event ID 3 records.
- All 7 records had corresponding five-tuple matches in the PCAPNG.
- SystemTime was closer to the nearest matching packet in 6 of 7 comparisons.
- UtcTime was closer in 1 comparison.
- Identified repeated network flows that prevent definitive individual packet-to-event attribution.
- Confirmed PCAPNG nanosecond timestamp resolution.
- No explicit PCAPNG timestamp-offset option was recorded.

### Decision
Retain Sysmon UtcTime as the primary event timestamp. Preserve Windows SystemTime, timestamp discrepancies and uncertainty metadata independently. Do not automatically shift timestamps or regenerate existing relationships.

### Limitations
The experiment establishes network-flow consistency, not independently verified incident attribution accuracy. Nanosecond timestamp resolution does not establish clock synchronization accuracy.

**Full report:** `EXP-08_real_evidence_timestamp_validation.md`