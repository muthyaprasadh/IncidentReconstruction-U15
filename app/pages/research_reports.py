"""
Research Reports Page for U-15 Incident Reconstruction Platform.
Displays automated evaluation deliverables and allows downloading research artifacts:
1. Scenario summary CSV
2. Ground-truth relationships CSV
3. Predicted relationships CSV
4. Baseline comparison CSV
5. Evaluation metrics CSV
6. Ablation study CSV
7. Sensitivity analysis CSV
8. Incident timeline CSV
9. Evidence provenance report (MD)
10. Final experiment summary (MD)
"""
import streamlit as st
import pandas as pd
from pathlib import Path
import subprocess
import sys

from config.settings import BASE_DIR, REPORTS_DIR

ROOT_REPORTS_DIR = BASE_DIR / "reports"


def render_research_reports_page():
    st.markdown("## ðŸ“„ Automated Research Reports & Experimental Deliverables")
    st.caption("Forensic reconstruction benchmarks, baseline comparisons, ablation studies, and provenance reports.")

    col_hdr, col_btn = st.columns([3, 1])
    with col_hdr:
        st.write("Browse and export generated empirical research outputs (saved in `reports/`).")
    with col_btn:
        if st.button("🔄 Refresh Summary Report", type="primary"):
            with st.spinner("Refreshing research summary from existing benchmark results..."):
                gen_script = BASE_DIR / "scripts" / "refresh_research_summary.py"
                proc = subprocess.run([sys.executable, str(gen_script)], capture_output=True, text=True)
                if proc.returncode == 0:
                    st.success("Research summary refreshed. Existing benchmark measurements were preserved.")
                    st.rerun()
                else:
                    st.error(f"Failed to refresh summary: {proc.stderr}")

    st.markdown("---")

    report_tabs = st.tabs([
        "1. Summary Report (MD)",
        "2. Provenance Report (MD)",
        "3. Baseline Comparison (CSV)",
        "4. Evaluation Metrics (CSV)",
        "5. Ablation Study (CSV)",
        "6. Sensitivity Analysis (CSV)",
        "7. Scenario Summary (CSV)",
        "8. Relationships (CSV)"
    ])

    # Tab 1: Final Summary
    with report_tabs[0]:
        st.markdown("### ðŸ“˜ Final Experiment Summary Report")
        summary_path = ROOT_REPORTS_DIR / "final_experiment_summary.md"
        if summary_path.exists():
            content = summary_path.read_text(encoding="utf-8")
            st.markdown(content)
            st.download_button(
                "ðŸ“¥ Download Final Experiment Summary (MD)",
                data=content.encode("utf-8"),
                file_name="final_experiment_summary.md",
                mime="text/markdown"
            )
        else:
            st.warning("Report not generated yet. Use 'Refresh Summary Report' above.")

    # Tab 2: Provenance Report
    with report_tabs[1]:
        st.markdown("### ðŸ›¡ï¸ Evidence Provenance & Verification Report")
        prov_path = ROOT_REPORTS_DIR / "evidence_provenance_report.md"
        if prov_path.exists():
            content = prov_path.read_text(encoding="utf-8")
            st.markdown(content)
            st.download_button(
                "ðŸ“¥ Download Evidence Provenance Report (MD)",
                data=content.encode("utf-8"),
                file_name="evidence_provenance_report.md",
                mime="text/markdown"
            )
        else:
            st.warning("Report not generated yet.")

    # Tab 3: Baseline Comparison CSV
    with report_tabs[2]:
        st.markdown("### ðŸ“Š Baseline Comparison (Method 1 to 4)")
        csv_path = ROOT_REPORTS_DIR / "baseline_comparison.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            st.dataframe(df, use_container_width=True, height=450)
            st.download_button(
                "ðŸ“¥ Download baseline_comparison.csv",
                data=csv_path.read_bytes(),
                file_name="baseline_comparison.csv",
                mime="text/csv"
            )
        else:
            st.warning("File not found.")

    # Tab 4: Evaluation Metrics CSV
    with report_tabs[3]:
        st.markdown("### ðŸ“ˆ Aggregated Evaluation Metrics by Method & Split")
        csv_path = ROOT_REPORTS_DIR / "evaluation_metrics.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            st.dataframe(df, use_container_width=True)
            st.download_button(
                "ðŸ“¥ Download evaluation_metrics.csv",
                data=csv_path.read_bytes(),
                file_name="evaluation_metrics.csv",
                mime="text/csv"
            )
        else:
            st.warning("File not found.")

    # Tab 5: Ablation Study CSV
    with report_tabs[4]:
        st.markdown("### ðŸ§© Ablation Study Results")
        csv_path = ROOT_REPORTS_DIR / "ablation_study.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            st.dataframe(df, use_container_width=True)
            st.download_button(
                "ðŸ“¥ Download ablation_study.csv",
                data=csv_path.read_bytes(),
                file_name="ablation_study.csv",
                mime="text/csv"
            )
        else:
            st.warning("File not found.")

    # Tab 6: Sensitivity Analysis CSV
    with report_tabs[5]:
        st.markdown("### â±ï¸ Sensitivity Analysis Results (Temporal & Stress)")
        csv_path = ROOT_REPORTS_DIR / "sensitivity_analysis.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            st.dataframe(df, use_container_width=True, height=450)
            st.download_button(
                "ðŸ“¥ Download sensitivity_analysis.csv",
                data=csv_path.read_bytes(),
                file_name="sensitivity_analysis.csv",
                mime="text/csv"
            )
        else:
            st.warning("File not found.")

    # Tab 7: Scenario Summary CSV
    with report_tabs[6]:
        st.markdown("### ðŸ“‹ 22 Forensic Scenarios Catalog Summary")
        csv_path = ROOT_REPORTS_DIR / "scenario_summary.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            st.dataframe(df, use_container_width=True, height=450)
            st.download_button(
                "ðŸ“¥ Download scenario_summary.csv",
                data=csv_path.read_bytes(),
                file_name="scenario_summary.csv",
                mime="text/csv"
            )
        else:
            st.warning("File not found.")

    # Tab 8: Relationships CSV
    with report_tabs[7]:
        st.markdown("### ðŸ”— Predicted vs Ground Truth Relationships")
        pred_path = ROOT_REPORTS_DIR / "predicted_relationships.csv"
        gt_path = ROOT_REPORTS_DIR / "ground_truth_relationships.csv"

        if pred_path.exists():
            st.markdown("**Predicted Relationships:**")
            df_pred = pd.read_csv(pred_path)
            st.dataframe(df_pred, use_container_width=True, height=300)
            st.download_button(
                "ðŸ“¥ Download predicted_relationships.csv",
                data=pred_path.read_bytes(),
                file_name="predicted_relationships.csv",
                mime="text/csv"
            )

        if gt_path.exists():
            st.markdown("**Ground-Truth Relationships:**")
            df_gt = pd.read_csv(gt_path)
            st.dataframe(df_gt, use_container_width=True, height=250)
            st.download_button(
                "ðŸ“¥ Download ground_truth_relationships.csv",
                data=gt_path.read_bytes(),
                file_name="ground_truth_relationships.csv",
                mime="text/csv"
            )

