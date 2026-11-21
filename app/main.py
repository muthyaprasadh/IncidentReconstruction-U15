"""
Main Streamlit Application for U-15 Incident Reconstruction Platform.
Title: U-15 | Cross-Artifact Incident Reconstruction from Process, Registry and Network Evidence.
"""
import streamlit as st
import sys
from pathlib import Path

# Add project root to sys.path to ensure absolute imports work seamlessly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import database.db as db
from app.dashboard import render_dashboard
from app.pages.cases import render_cases_page
from app.pages.evidence_upload import render_evidence_upload_page
from app.pages.evidence_analysis import render_evidence_analysis_page
from app.pages.graph_view import render_graph_view_page
from app.pages.incident_timeline import render_incident_timeline_page
from app.pages.evaluation import render_evaluation_page
from app.pages.research_reports import render_research_reports_page

# Page Configuration
st.set_page_config(
    page_title="IncidentReconstruction | Cross-Artifact Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Enterprise Cybersecurity Dark Theme CSS
CUSTOM_CSS = """
<style>
    /* Dark Theme Core Styles */
    .stApp {
        background-color: #0F172A;
        color: #F8FAFC;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0B1120;
        border-right: 1px solid #1E293B;
    }
    
    /* Metrics and Card Blocks */
    div[data-testid="stMetricValue"] {
        color: #38BDF8 !important;
        font-weight: 700 !important;
        font-family: 'JetBrains Mono', monospace;
    }
    div[data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Expander and Containers */
    .streamlit-expanderHeader {
        background-color: #1E293B !important;
        border-radius: 6px !important;
        border: 1px solid #334155 !important;
        color: #F1F5F9 !important;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 6px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease-in-out;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #2563EB, #1D4ED8) !important;
        border: 1px solid #3B82F6 !important;
        box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.2);
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #1D4ED8, #1E40AF) !important;
        box-shadow: 0 6px 8px -1px rgba(37, 99, 235, 0.3);
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 4px 4px 0 0;
        padding: 8px 16px;
        background-color: #1E293B;
        color: #94A3B8;
        border: 1px solid #334155;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2563EB !important;
        color: #FFFFFF !important;
        font-weight: bold;
    }

    /* Code blocks */
    code {
        color: #38BDF8 !important;
        background-color: #1E293B !important;
        padding: 2px 5px !important;
        border-radius: 4px !important;
        border: 1px solid #334155 !important;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Session State
if "current_case_id" not in st.session_state:
    # Auto-load latest case if exists
    all_cases = db.get_all_cases()
    if all_cases:
        st.session_state["current_case_id"] = all_cases[0]["case_id"]
        st.session_state["current_case_name"] = all_cases[0]["name"]
    else:
        st.session_state["current_case_id"] = None
        st.session_state["current_case_name"] = None

# Sidebar Navigation
with st.sidebar:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
            <span style="font-size: 2rem;">🛡️</span>
            <div>
                <h3 style="margin: 0; color: #38BDF8; font-size: 1.15rem; font-weight: bold;">IncidentLab</h3>
                <span style="font-size: 0.75rem; color: #94A3B8;">U-15 Reconstruction Engine</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Active Case Badge & Quick Selector
    curr_cid = st.session_state.get("current_case_id")
    curr_cname = st.session_state.get("current_case_name", "")
    
    if curr_cid:
        st.markdown(
            f"""
            <div style="background-color: #1E293B; border-radius: 6px; padding: 10px; margin-bottom: 15px; border-left: 3px solid #38BDF8; border: 1px solid #334155;">
                <span style="font-size: 0.7rem; color: #94A3B8; text-transform: uppercase; font-weight: bold;">Active Investigation</span>
                <div style="color: #F8FAFC; font-weight: bold; font-size: 0.9rem; margin: 2px 0;">{curr_cname}</div>
                <div style="font-family: monospace; font-size: 0.75rem; color: #38BDF8;">[{curr_cid}]</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div style="background-color: #1E293B; border-radius: 6px; padding: 10px; margin-bottom: 15px; border-left: 3px solid #F59E0B; border: 1px solid #334155;">
                <span style="font-size: 0.75rem; color: #F59E0B; font-weight: bold;">⚠️ NO CASE SELECTED</span>
                <div style="font-size: 0.75rem; color: #94A3B8;">Please create or select a case to begin.</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Navigation Menu
    menu_options = [
        "📊 Forensic Dashboard",
        "📁 Case Management",
        "📥 Evidence Ingestion",
        "🔬 Normalization & Correlation",
        "🕸️ Evidence Graph",
        "⏱️ Reconstructed Timeline",
        "📈 Research Evaluation",
        "📄 Research Reports"
    ]
    
    selected_page = st.radio(
        "NAVIGATION",
        menu_options,
        index=0,
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.75rem; color: #64748B; line-height: 1.4;">
            <b>Project:</b> U-15 Forensic Reconstruction<br>
            <b>Stack:</b> Python 3.13 | NetworkX | Plotly | PyVis | ReportLab<br>
            <b>Status:</b> Local Windows Execution
        </div>
        """,
        unsafe_allow_html=True
    )

# Page Routing
if selected_page == "📊 Forensic Dashboard":
    render_dashboard()
elif selected_page == "📁 Case Management":
    render_cases_page()
elif selected_page == "📥 Evidence Ingestion":
    render_evidence_upload_page()
elif selected_page == "🔬 Normalization & Correlation":
    render_evidence_analysis_page()
elif selected_page == "🕸️ Evidence Graph":
    render_graph_view_page()
elif selected_page == "⏱️ Reconstructed Timeline":
    render_incident_timeline_page()
elif selected_page == "📈 Research Evaluation":
    render_evaluation_page()
elif selected_page == "📄 Research Reports":
    render_research_reports_page()
