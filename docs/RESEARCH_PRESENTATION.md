# U-15 Research Presentation

## Slide 1 — Title

Cross-Artifact Incident Reconstruction Using Process, Registry and Network Evidence

## Slide 2 — Research Question

Can cross-artifact correlation reconstruct incidents more completely than single-source or conventional rule-based investigation?

## Slide 3 — Problem

- PID reuse
- Concurrent processes
- Missing Registry/telemetry
- Network attribution ambiguity
- Synthetic and real evidence separation

## Slide 4 — Evidence and System

Procmon + Sysmon + Registry export + Wireshark → normalization → correlation → graph/timeline → evaluation

## Slide 5 — Method 3

Rule-based correlation, direct relationship generation, no graph reachability.

## Slide 6 — Method 4

Directed provenance graph, trusted edge filtering, process-seed path reconstruction, causal explanation.

## Slide 7 — Dataset

- 19 development scenarios
- 3 held-out scenarios
- CASE-20 mixed incident
- CASE-21 PID reuse
- CASE-22 missing Registry and noise

## Slide 8 — Metrics

Precision, recall, F1, false-positive rate, event coverage, relationship attribution and timeline accuracy.

## Slide 9 — Ablation

ProcessGuid, timestamp matching, Registry evidence, five-tuple matching and lifetime validation.

## Slide 10 — Sensitivity

±1, ±5, ±10 and ±30 seconds; noise, PID reuse, concurrency and missing evidence.

## Slide 11 — Demonstration

Show evidence graph, process exploration, Registry attribution, network corroboration, chronological timeline and provenance.

## Slide 12 — Validation Status

Synthetic pipeline complete. Real Windows validation pending independently exported captures and ground truth.

## Slide 13 — Limitations and Future Work

No real-capture claim yet; add repeated controlled captures and EVTX support.
