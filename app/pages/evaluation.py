"""
Experimental Evaluation Page for U-15 Incident Reconstruction Platform.
Directly addresses the primary research question:
"Can correlated endpoint and network traces reconstruct an incident more accurately than isolated analysis?"
Executes Baselines 1, 2, 3 vs Proposed Method, Ablation studies, and Sensitivity analyses.
"""
import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Set, Tuple
import database.db as db
from database.models import NormalizedEvent
from evaluation.baselines import BaselineRunner
from evaluation.metrics import ForensicEvaluator
from evaluation.ablation import AblationStudy
from evaluation.sensitivity import SensitivityAnalysis
from experiments.ground_truth_manager import GroundTruthManager
from app.components.charts import (
    create_baseline_comparison_chart,
    create_ablation_chart,
    create_sensitivity_chart
)

def render_evaluation_page():
    st.markdown("## 📊 Research Evaluation & Baseline Benchmarks")
    st.caption("Empirical validation: Single-source vs multi-source reconstruction, false positive rates, ablation, and temporal sensitivity.")

    case_id = st.session_state.get("current_case_id")
    if not case_id:
        st.warning("⚠️ Please select an active investigation case first.")
        return

    # Check for ground truth
    gt = GroundTruthManager.load_ground_truth(case_id)
    if not gt:
        st.warning(f"No independent ground truth record found for case '{case_id}'.")
        st.info("💡 To generate a complete controlled experimental case with independently recorded ground truth, navigate to 'Evidence Upload' and click 'Generate & Ingest Lab Data'.")
        return

    gt_incident_ids = set(gt.get("incident_event_ids", []))
    gt_rels = [tuple(r) for r in gt.get("expected_relationships", [])]
    is_real_case = gt.get("dataset_type") in ("real_world", "held_out_real_world")

    st.markdown(
        f"""
        <div style="background-color: #1F2937; border-left: 4px solid #10B981; border-radius: 6px; padding: 12px; margin-bottom: 16px; border: 1px solid #374151;">
            <b>Active Ground Truth Benchmark:</b> <code>{gt.get('scenario_name')}</code><br>
            <b>Documented Incident Events:</b> {len(gt_incident_ids)} | <b>Expected Ground-Truth Relationships:</b> {len(gt_rels)}
        </div>
        """,
        unsafe_allow_html=True
    )

    events_dicts = db.get_events(case_id)
    if not events_dicts:
        st.info("No normalized events in this case.")
        return

    events = [NormalizedEvent(**{k: v for k, v in d.items() if k in NormalizedEvent.__annotations__}) for d in events_dicts]
    all_eids = {e.event_id for e in events}

    # Evaluation Controls
    e_col1, e_col2 = st.columns([3, 1])
    with e_col1:
        eval_window = st.slider("Evaluation Correlation Window (± seconds)", 1.0, 30.0, 5.0, 1.0)
    with e_col2:
        st.write("")
        st.write("")
        run_bench_btn = st.button("⚡ Run Benchmark Suite", type="primary")

    tab_baselines, tab_ablation, tab_sensitivity, tab_gt = st.tabs([
        "1. Baseline Comparison (Research Question)",
        "2. Ablation Study (Missing Evidence)",
        "3. Sensitivity Analysis (Temporal Windows)",
        "4. Ground Truth Inspector"
    ])

    # 1. BASELINE COMPARISON TAB
    with tab_baselines:
        st.markdown("### 🏆 4-Approach Empirical Benchmark")
        st.markdown(
            """
            - **Baseline 1:** Process evidence only (isolated process lifecycle & PPID).
            - **Baseline 2:** Process + Registry evidence (endpoint persistence without network visibility).
            - **Baseline 3:** All sources with conventional rule-based correlation (Sysmon Event ID 3, five-tuple, ProcessGuid/PID lifetime) **without graph connected-component reasoning**.
            - **Proposed Method:** Provenance-aware evidence graph over the same rule-based relationships.
            """
        )

        # Execute Baselines
        with st.spinner("Evaluating investigation approaches against documented ground truth..."):
            method_runs = [
                ("Baseline 1: Process Only", BaselineRunner.run_baseline_1_process_only),
                ("Baseline 2: Process + Registry", BaselineRunner.run_baseline_2_proc_and_reg),
                ("Baseline 3: All Sources Rule-Based (No Graph)", BaselineRunner.run_baseline_3_all_no_graph),
                ("Proposed: Provenance Graph", BaselineRunner.run_proposed_method),
            ]
            comparison_summary = []
            gt_chrono = gt.get("ground_truth_chronology") or list(gt_incident_ids)
            for name, run_method in method_runs:
                predicted_ids, predicted_relationships, chronology = run_method(
                    events, case_id, temporal_window=eval_window
                )
                if is_real_case:
                    metrics = ForensicEvaluator.calculate_labeled_relationship_coverage(
                        predicted_relationships,
                        gt_rels,
                        gt_incident_ids,
                    )
                else:
                    event_metrics = ForensicEvaluator.calculate_classification_metrics(
                        predicted_ids, gt_incident_ids, all_eids
                    )
                    relationship_metrics = ForensicEvaluator.calculate_relationship_metrics(
                        predicted_relationships, gt_rels
                    )
                    timeline_accuracy = ForensicEvaluator.calculate_timeline_ordering_accuracy(
                        chronology, gt_chrono
                    )
                    metrics = {
                        **event_metrics,
                        **relationship_metrics,
                        "timeline_accuracy": timeline_accuracy,
                    }

                entry = {"method": name, **metrics}
                comparison_summary.append(entry)

            # Save evaluation runs to DB
            for entry in comparison_summary:
                db.save_evaluation_run(
                    run_id=f"{case_id}_{entry['method'][:10]}_{eval_window}",
                    case_id=case_id,
                    method=entry["method"],
                    temporal_window=eval_window,
                    metrics=entry
                )

        if is_real_case:
            st.info(
                "Real-world ground truth is positive-only and may omit alternative valid evidence links. "
                "This view reports exact expected-link coverage; unreviewed links are not labeled false positives. "
                "Event-level precision/FPR and timeline accuracy are unavailable for this case."
            )
            df_comp = pd.DataFrame([
                {
                    "Investigation Approach": item["method"],
                    "Expected links recovered": (
                        f"{item['exact_expected_relationship_matches']}/"
                        f"{item['expected_relationship_count']}"
                    ),
                    "Expected-link coverage": f"{item['expected_link_coverage']:.4f}",
                    "Unreviewed scoped links": len(item["unreviewed_scoped_relationships"]),
                }
                for item in comparison_summary
            ])
        else:
            chart_fig = create_baseline_comparison_chart(comparison_summary)
            st.plotly_chart(chart_fig, use_container_width=True)
            df_comp = pd.DataFrame([
                {
                    "Investigation Approach": item["method"],
                    "Precision": f"{item['precision']:.4f}",
                    "Recall": f"{item['recall']:.4f}",
                    "F1-Score": f"{item['f1_score']:.4f}",
                    "False Positive Rate": f"{item['false_positive_rate']:.4f}",
                    "Rel Precision": f"{item['rel_precision']:.4f}",
                    "Rel Recall": f"{item['rel_recall']:.4f}",
                    "Rel F1": f"{item['rel_f1']:.4f}",
                    "Timeline Order Acc": f"{item['timeline_accuracy']:.4f}",
                    "True Positives": item["tp"],
                    "False Positives": item["fp"],
                    "False Negatives": item["fn"],
                }
                for item in comparison_summary
            ])
        st.dataframe(df_comp, use_container_width=True)

        # Scientific Conclusion callout
        if not is_real_case:
            st.info(
                "Event detection (precision, recall, F1, FPR) is reported separately from relationship prediction "
                "(rel precision/recall/F1) and timeline ordering accuracy. Figures on this page are computed from "
                "the active case ground truth. They are not claims of superiority over commercial EDR/XDR products, "
                "court admissibility, or production-grade forensic reliability."
            )

    # 2. ABLATION STUDY TAB
    with tab_ablation:
        st.markdown("### 🧩 Missing-Evidence Ablation Study")
        st.caption("Quantifies incident reconstruction degradation when individual forensic evidence sources are omitted.")
        if is_real_case:
            st.info(
                "Ablation is not scored for this real case because its event labels are incomplete. "
                "Run this study after collecting independently labeled cases for every evidence condition."
            )
        else:
            ablation_res = AblationStudy.run_ablation(
                events, case_id, gt_incident_ids, gt_rels, temporal_window=eval_window
            )
            abl_chart = create_ablation_chart(ablation_res)
            st.plotly_chart(abl_chart, use_container_width=True)
            df_abl = pd.DataFrame([
                {
                    "Configuration": result["configuration"],
                    "Feature Ablated": result["feature_ablated"],
                    "Events Analyzed": result["event_count"],
                    "Precision": f"{result['precision']:.4f}",
                    "Recall": f"{result['recall']:.4f}",
                    "F1-Score": f"{result['f1_score']:.4f}",
                    "False Positive Rate": f"{result['false_positive_rate']:.4f}",
                    "Rel Attribution Acc": f"{result['relationship_attribution_accuracy']:.4f}",
                }
                for result in ablation_res
            ])
            st.dataframe(df_abl, use_container_width=True)

    # 3. SENSITIVITY ANALYSIS TAB
    with tab_sensitivity:
        st.markdown("### 📈 Temporal Window Sensitivity Analysis")
        st.caption("Evaluates performance across time correlation windows: ±1s, ±5s, ±10s, ±30s.")
        if is_real_case:
            st.info(
                "Sensitivity metrics are not reported for this case because the edge labels and chronology "
                "are incomplete. Repeat across independently labeled cases before drawing conclusions."
            )
        else:
            sensitivity_res = SensitivityAnalysis.run_sensitivity(
                events, case_id, gt_incident_ids, gt_rels
            )
            sens_fig = create_sensitivity_chart(sensitivity_res)
            st.plotly_chart(sens_fig, use_container_width=True)
            df_sens = pd.DataFrame([
                {
                    "Method": result["method"],
                    "Window": result["window_label"],
                    "Precision": f"{result['precision']:.4f}",
                    "Recall": f"{result['recall']:.4f}",
                    "F1-Score": f"{result['f1_score']:.4f}",
                    "False Positive Rate": f"{result['false_positive_rate']:.4f}",
                    "Rel Attribution Acc": f"{result['relationship_attribution_accuracy']:.4f}",
                }
                for result in sensitivity_res
            ])
            st.dataframe(df_sens, use_container_width=True)

    # 4. GROUND TRUTH INSPECTOR TAB
    with tab_gt:
        st.markdown("### 🔍 Independently Documented Ground Truth")
        st.caption("Verified ground truth records generated prior to investigation output.")
        
        gt_col1, gt_col2 = st.columns(2)
        with gt_col1:
            st.markdown("**Incident-Related Event IDs:**")
            st.json(list(gt_incident_ids))
        with gt_col2:
            st.markdown("**Expected Ground-Truth Relationships:**")
            st.json(gt_rels)

        if gt.get("incident_phases"):
            st.markdown("**Intentional Incident Phases:**")
            st.table(gt["incident_phases"])

    st.markdown("---")
    # Export CSV of evaluation metrics
    st.markdown("### 💾 Export Evaluation Benchmarks")
    csv_eval = df_comp.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Baseline Comparison Metrics (CSV)",
        data=csv_eval,
        file_name=f"evaluation_metrics_{case_id}.csv",
        mime="text/csv"
    )
