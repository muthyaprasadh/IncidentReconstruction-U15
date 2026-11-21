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
            gt_chrono = gt.get("ground_truth_chronology") or list(gt_incident_ids)

            # 1. Baseline 1
            b1_eids, b1_rels, b1_chrono = BaselineRunner.run_baseline_1_process_only(events, case_id, temporal_window=eval_window)
            b1_c = ForensicEvaluator.calculate_classification_metrics(b1_eids, gt_incident_ids, all_eids)
            b1_r = ForensicEvaluator.calculate_relationship_metrics(b1_rels, gt_rels)
            b1_order = ForensicEvaluator.calculate_timeline_ordering_accuracy(b1_chrono, gt_chrono)

            # 2. Baseline 2
            b2_eids, b2_rels, b2_chrono = BaselineRunner.run_baseline_2_proc_and_reg(events, case_id, temporal_window=eval_window)
            b2_c = ForensicEvaluator.calculate_classification_metrics(b2_eids, gt_incident_ids, all_eids)
            b2_r = ForensicEvaluator.calculate_relationship_metrics(b2_rels, gt_rels)
            b2_order = ForensicEvaluator.calculate_timeline_ordering_accuracy(b2_chrono, gt_chrono)

            # 3. Baseline 3
            b3_eids, b3_rels, b3_chrono = BaselineRunner.run_baseline_3_all_no_graph(events, case_id, temporal_window=eval_window)
            b3_c = ForensicEvaluator.calculate_classification_metrics(b3_eids, gt_incident_ids, all_eids)
            b3_r = ForensicEvaluator.calculate_relationship_metrics(b3_rels, gt_rels)
            b3_order = ForensicEvaluator.calculate_timeline_ordering_accuracy(b3_chrono, gt_chrono)

            # 4. Proposed Method
            prop_eids, prop_rels, prop_chrono = BaselineRunner.run_proposed_method(events, case_id, temporal_window=eval_window)
            prop_c = ForensicEvaluator.calculate_classification_metrics(prop_eids, gt_incident_ids, all_eids)
            prop_r = ForensicEvaluator.calculate_relationship_metrics(prop_rels, gt_rels)
            prop_order = ForensicEvaluator.calculate_timeline_ordering_accuracy(prop_chrono, gt_chrono)

            comparison_summary = [
                {"method": "Baseline 1: Process Only", **b1_c, **b1_r, "timeline_accuracy": b1_order},
                {"method": "Baseline 2: Process + Registry", **b2_c, **b2_r, "timeline_accuracy": b2_order},
                {"method": "Baseline 3: All Sources Rule-Based (No Graph)", **b3_c, **b3_r, "timeline_accuracy": b3_order},
                {"method": "Proposed: Provenance Graph", **prop_c, **prop_r, "timeline_accuracy": prop_order},
            ]

            # Save evaluation runs to DB
            for entry in comparison_summary:
                db.save_evaluation_run(
                    run_id=f"{case_id}_{entry['method'][:10]}_{eval_window}",
                    case_id=case_id,
                    method=entry["method"],
                    temporal_window=eval_window,
                    metrics=entry
                )

        # Render Comparison Chart
        chart_fig = create_baseline_comparison_chart(comparison_summary)
        st.plotly_chart(chart_fig, use_container_width=True)

        # Metric Table
        df_comp = pd.DataFrame([
            {
                "Investigation Approach": d["method"],
                "Precision": f"{d['precision']:.4f}",
                "Recall": f"{d['recall']:.4f}",
                "F1-Score": f"{d['f1_score']:.4f}",
                "False Positive Rate": f"{d['false_positive_rate']:.4f}",
                "Rel Precision": f"{d['rel_precision']:.4f}",
                "Rel Recall": f"{d['rel_recall']:.4f}",
                "Rel F1": f"{d['rel_f1']:.4f}",
                "Timeline Order Acc": f"{d['timeline_accuracy']:.4f}",
                "True Positives": d["tp"],
                "False Positives": d["fp"],
                "False Negatives": d["fn"]
            }
            for d in comparison_summary
        ])
        st.dataframe(df_comp, use_container_width=True)

        # Scientific Conclusion callout
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
        ablation_res = AblationStudy.run_ablation(events, case_id, gt_incident_ids, gt_rels, temporal_window=eval_window)
        
        abl_chart = create_ablation_chart(ablation_res)
        st.plotly_chart(abl_chart, use_container_width=True)

        df_abl = pd.DataFrame([
            {
                "Configuration": r["configuration"],
                "Feature Ablated": r["feature_ablated"],
                "Events Analyzed": r["event_count"],
                "Precision": f"{r['precision']:.4f}",
                "Recall": f"{r['recall']:.4f}",
                "F1-Score": f"{r['f1_score']:.4f}",
                "False Positive Rate": f"{r['false_positive_rate']:.4f}",
                "Rel Attribution Acc": f"{r['relationship_attribution_accuracy']:.4f}"
            }
            for r in ablation_res
        ])
        st.dataframe(df_abl, use_container_width=True)

    # 3. SENSITIVITY ANALYSIS TAB
    with tab_sensitivity:
        st.markdown("### 📈 Temporal Window Sensitivity Analysis")
        st.caption("Evaluates performance across time correlation windows: ±1s, ±5s, ±10s, ±30s.")
        sensitivity_res = SensitivityAnalysis.run_sensitivity(events, case_id, gt_incident_ids, gt_rels)
        
        sens_fig = create_sensitivity_chart(sensitivity_res)
        st.plotly_chart(sens_fig, use_container_width=True)

        df_sens = pd.DataFrame([
            {
                "Method": r["method"],
                "Window": r["window_label"],
                "Precision": f"{r['precision']:.4f}",
                "Recall": f"{r['recall']:.4f}",
                "F1-Score": f"{r['f1_score']:.4f}",
                "False Positive Rate": f"{r['false_positive_rate']:.4f}",
                "Rel Attribution Acc": f"{r['relationship_attribution_accuracy']:.4f}"
            }
            for r in sensitivity_res
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
