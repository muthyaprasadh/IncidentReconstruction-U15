"""
Case Management Page for U-15 Incident Reconstruction Platform.
Enables creating new investigations, switching active case contexts, and safely deleting cases.
"""
import streamlit as st
from datetime import date
import database.db as db
from database.models import Case

def render_cases_page():
    st.markdown("## 📁 Forensic Case Management")
    st.caption("Manage isolated digital forensics cases, evidence containers, and ground truth records.")

    # Form to create new investigation
    with st.expander("➕ Create New Investigation Case", expanded=False):
        with st.form("create_case_form"):
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                case_id = st.text_input("Case ID *", placeholder="e.g. CASE-2026-001", help="Unique alphanumeric case identifier").strip()
                case_name = st.text_input("Investigation Name *", placeholder="e.g. Incident Lab Triage 01").strip()
            with c_col2:
                coll_date = st.date_input("Evidence Collection Date", value=date.today())
                case_desc = st.text_area("Investigation Description", placeholder="Brief description of the alleged incident or test scenario...").strip()

            submitted = st.form_submit_button("Create Case")
            if submitted:
                if not case_id or not case_name:
                    st.error("Please provide both a Case ID and an Investigation Name.")
                else:
                    new_case = Case(
                        case_id=case_id,
                        name=case_name,
                        description=case_desc,
                        collection_date=coll_date.isoformat()
                    )
                    success = db.create_case(new_case)
                    if success:
                        st.success(f"Investigation case '{case_id}' created successfully!")
                        st.session_state["current_case_id"] = case_id
                        st.session_state["current_case_name"] = case_name
                        st.rerun()
                    else:
                        st.error(f"Failed to create case. Case ID '{case_id}' may already exist.")

    st.markdown("---")
    st.markdown("### 🗃️ Existing Investigations")

    cases = db.get_all_cases()
    if not cases:
        st.info("No investigation cases recorded. Use the form above to initialize your first case.")
        return

    current_id = st.session_state.get("current_case_id")

    for c in cases:
        cid = c["case_id"]
        is_active = (cid == current_id)
        
        card_border = "#3B82F6" if is_active else "#374151"
        bg_color = "#1F2937" if not is_active else "#1E293B"

        with st.container():
            st.markdown(
                f"""
                <div style="border: 1px solid {card_border}; background-color: {bg_color}; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h4 style="margin: 0; color: #60A5FA;">{c['name']} <span style="font-family: monospace; color: #9CA3AF; font-size: 0.9rem;">[{cid}]</span></h4>
                        <span style="background-color: {'#10B98122' if is_active else '#6B728022'}; color: {'#10B981' if is_active else '#9CA3AF'}; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;">
                            {'CURRENTLY ACTIVE' if is_active else c['status']}
                        </span>
                    </div>
                    <p style="margin: 6px 0; color: #D1D5DB; font-size: 0.9rem;">{c['description'] or 'No description provided.'}</p>
                    <div style="display: flex; gap: 20px; font-size: 0.8rem; color: #9CA3AF;">
                        <span>📅 Collection: {c['collection_date'] or 'N/A'}</span>
                        <span>⏱️ Created: {c['created_at'][:19]}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            act_col1, act_col2, act_col3 = st.columns([2, 4, 2])
            with act_col1:
                if not is_active:
                    if st.button("Set as Active Case", key=f"set_{cid}"):
                        st.session_state["current_case_id"] = cid
                        st.session_state["current_case_name"] = c["name"]
                        st.rerun()
                else:
                    st.success("Active Context")

            with act_col3:
                # Safe deletion requiring confirmation
                with st.popover("🗑️ Delete Case"):
                    st.warning(f"Permanently delete case '{cid}' and all associated evidence, events, and graphs?")
                    confirm_check = st.checkbox("I confirm deletion", key=f"confirm_del_{cid}")
                    if st.button("Delete Permanently", type="primary", key=f"del_btn_{cid}"):
                        if confirm_check:
                            db.delete_case(cid)
                            if st.session_state.get("current_case_id") == cid:
                                st.session_state["current_case_id"] = None
                                st.session_state["current_case_name"] = None
                            st.success(f"Case '{cid}' deleted.")
                            st.rerun()
                        else:
                            st.error("Please check the confirmation box first.")
