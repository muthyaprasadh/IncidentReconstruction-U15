# EXP-09: Process-Instance-Equivalent Held-Out Evaluation

Generated (UTC): 2026-11-22T13:13:57.586129+00:00

## Objective

Evaluate held-out relationships using both strict event-ID matching and validated process-instance-equivalent matching.

## Overall results

| Metric | Result |
|---|---:|
| Held-out cases | 3 |
| Expected relationships | 13 |
| Strict event-ID matches | 10 / 13 |
| Strict event-level recall | 76.92% |
| Equivalent matches | 13 / 13 |
| Process-instance-equivalent recall | 100.00% |

## Per-case results

| Case | Expected | Strict matches | Equivalent matches |
|---|---:|---:|---:|
| CASE-20-20_HELD_OUT_MIXED | 6 | 5 | 6 |
| CASE-21-21_HELD_OUT_PID_REUSE | 2 | 1 | 2 |
| CASE-22-22_HELD_OUT_MISSING_REG_NOISE | 5 | 4 | 5 |

## Evaluation methodology

**Strict matching:** Requires exact source event ID, target event ID and relationship type.

**Equivalent matching:** Maps process-source event IDs to the validated process epoch's start event ID. Relationship direction and type remain unchanged. Non-process events retain their original IDs.

## Limitations

- Held-out cases are synthetic.
- The evaluation covers annotated expected relationships only.
- Unreviewed predictions are not classified as false positives.
- This experiment does not establish precision, F1 or false-positive rate.
- Equivalent matching depends on process-lifetime attribution.
- Equivalent recall does not replace strict event-level recall.

## Integrity

- Database writes: None.
- Ground-truth modifications: None.
- Evidence modifications: None.
- Existing reports overwritten: None.

## Interpretation

The equivalent score measures recovery of annotated relationships after accounting for different process-start event representations across telemetry sources. It must be reported alongside, not instead of, strict event-level recall.
