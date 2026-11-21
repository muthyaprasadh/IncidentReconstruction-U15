import csv
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
OUTPUT_REPORTS = ROOT / "output" / "reports"
METRICS_FILE = REPORTS / "evaluation_metrics.csv"
OUTPUT_FILE = REPORTS / "final_experiment_summary.md"

METHODS = [
    "Method 1: Process-Only",
    "Method 2: Network-Only",
    "Method 3: Rule-Based Correlation",
    "Method 4: Proposed Cross-Artifact Graph",
]

METRIC_COLUMNS = [
    ("mean_precision", "Precision"),
    ("mean_recall", "Recall"),
    ("mean_f1_score", "F1"),
    ("mean_false_positive_rate", "False Positive Rate"),
    ("mean_event_coverage", "Event Coverage"),
    ("mean_relationship_f1", "Relationship F1"),
    ("mean_timeline_accuracy", "Timeline Accuracy"),
]

def load_metrics():
    if not METRICS_FILE.exists():
        raise FileNotFoundError(f"Missing benchmark file: {METRICS_FILE}")

    with METRICS_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))

    required = {
        "dataset_split",
        "investigation_method",
        "scenarios_evaluated",
        *[column for column, _ in METRIC_COLUMNS],
    }

    if not rows:
        raise ValueError("The evaluation metrics file contains no records.")

    missing = required - set(rows[0].keys())
    if missing:
        raise ValueError(f"Missing required CSV columns: {sorted(missing)}")

    return rows

def get_row(rows, split, method):
    matches = [
        row for row in rows
        if row["dataset_split"] == split
        and row["investigation_method"] == method
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one row for {split} / {method}; found {len(matches)}."
        )

    return matches[0]

def format_value(value):
    return f"{float(value):.4f}"

def build_table(rows, split):
    lines = [
        "| Investigation Method | Scenarios | Precision | Recall | F1 | False Positive Rate | Event Coverage | Relationship F1 | Timeline Accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for method in METHODS:
        row = get_row(rows, split, method)
        values = [
            method,
            row["scenarios_evaluated"],
            format_value(row["mean_precision"]),
            format_value(row["mean_recall"]),
            format_value(row["mean_f1_score"]),
            format_value(row["mean_false_positive_rate"]),
            format_value(row["mean_event_coverage"]),
            format_value(row["mean_relationship_f1"]),
            format_value(row["mean_timeline_accuracy"]),
        ]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)

def build_summary(rows):
    all_graph = get_row(
        rows, "All Scenarios", "Method 4: Proposed Cross-Artifact Graph"
    )
    all_rules = get_row(
        rows, "All Scenarios", "Method 3: Rule-Based Correlation"
    )
    dev_graph = get_row(
        rows, "Development", "Method 4: Proposed Cross-Artifact Graph"
    )
    dev_rules = get_row(
        rows, "Development", "Method 3: Rule-Based Correlation"
    )
    test_graph = get_row(
        rows, "Held-Out Test", "Method 4: Proposed Cross-Artifact Graph"
    )
    test_rules = get_row(
        rows, "Held-Out Test", "Method 3: Rule-Based Correlation"
    )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""# Cross-Artifact Incident Reconstruction — Experimental Results

**Report generated:** {generated}

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

{build_table(rows, "All Scenarios")}

## 4. Development Results

{build_table(rows, "Development")}

## 5. Held-Out Test Results

{build_table(rows, "Held-Out Test")}

## 6. Findings

### 6.1 Event Detection

Across all 22 scenarios, the proposed cross-artifact graph method achieved an F1-score of **{format_value(all_graph["mean_f1_score"])}**, compared with **{format_value(all_rules["mean_f1_score"])}** for rule-based correlation.

On the development split, the proposed method achieved an F1-score of **{format_value(dev_graph["mean_f1_score"])}**, compared with **{format_value(dev_rules["mean_f1_score"])}** for rule-based correlation.

On the designated held-out test split, the proposed method achieved an F1-score of **{format_value(test_graph["mean_f1_score"])}**, compared with **{format_value(test_rules["mean_f1_score"])}** for rule-based correlation.

### 6.2 Evidence Coverage

The proposed method achieved mean event coverage of **{format_value(all_graph["mean_event_coverage"])}** across all scenarios.

This supports the finding that cross-artifact correlation recovered a broader set of labeled incident events in this benchmark.

### 6.3 Relationship Reconstruction

The proposed method achieved an overall mean relationship F1-score of **{format_value(all_graph["mean_relationship_f1"])}**.

Relationship reconstruction should be interpreted alongside the event-level results and the ground-truth labeling scope.

### 6.4 False-Positive Trade-off

The proposed method's overall mean false-positive rate was **{format_value(all_graph["mean_false_positive_rate"])}**, compared with **{format_value(all_rules["mean_false_positive_rate"])}** for rule-based correlation.

On the development split, the proposed method's false-positive rate was **{format_value(dev_graph["mean_false_positive_rate"])}**, compared with **{format_value(dev_rules["mean_false_positive_rate"])}**.

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
"""

def main():
    rows = load_metrics()
    summary = build_summary(rows)

    REPORTS.mkdir(parents=True, exist_ok=True)
    OUTPUT_REPORTS.mkdir(parents=True, exist_ok=True)

    OUTPUT_FILE.write_text(summary, encoding="utf-8")
    (OUTPUT_REPORTS / OUTPUT_FILE.name).write_text(summary, encoding="utf-8")

    print("Research summary refreshed successfully.")
    print(f"Primary report: {OUTPUT_FILE}")
    print(f"Secondary report: {OUTPUT_REPORTS / OUTPUT_FILE.name}")
    print("Existing benchmark CSV files were not modified.")
    print(f"Scenarios in overall evaluation: {get_row(rows, 'All Scenarios', METHODS[0])['scenarios_evaluated']}")

if __name__ == "__main__":
    main()
