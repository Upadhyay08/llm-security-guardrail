import streamlit as st
from lane1_engine import run_lane1_deterministic_engine
from lane2_engine import run_lane2_semantic_engine

st.set_page_config(
    page_title="Enterprise LLM Security Guardrail",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #38BDF8;
        margin-bottom: 0.3rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown('<div class="main-title">🛡️ Enterprise LLM Security Guardrail Application</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Multi-layered security pipeline detecting PII/Financial data violations (Lane 1) '
    'and evaluating semantic intent safety (Lane 2).</div>',
    unsafe_allow_html=True
)

# Sidebar System Status
st.sidebar.header("System Status")
st.sidebar.success("Lane 1: Deterministic Engine (Active)")
st.sidebar.success("Lane 2: NVIDIA Nemotron Engine (Active)")

# User Input Section
user_prompt = st.text_area(
    "Enter Prompt to Evaluate:",
    placeholder="Type a query or prompt here...",
    height=140
)

if st.button("Run Security Evaluation", type="primary"):
    if not user_prompt.strip():
        st.warning("Please enter a prompt before running the evaluation.")
    else:
        st.subheader("Pipeline Execution Results")
        
        # ---------------------------------------------------------
        # LANE 1: Deterministic Engine (Regex Redaction)
        # ---------------------------------------------------------
        st.markdown("### 🔍 Lane 1: Deterministic Engine")
        
        # Unpack 3 values: (sanitized_text, pii_detected, metadata)
        sanitized_text, pii_detected, lane1_meta = run_lane1_deterministic_engine(user_prompt)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Original Prompt:**")
            st.code(user_prompt, language="text")
        
        with col2:
            st.markdown("**Sanitized Text (Post-Redaction):**")
            st.code(sanitized_text, language="text")
            
        if pii_detected:
            st.info(f"ℹ️ Sensitive pattern match found. Redactions applied using `[POLICY_REDACTED]` tokens.")
        else:
            st.caption("No deterministic PII or financial patterns flagged in Lane 1.")

        st.divider()

        # ---------------------------------------------------------
        # LANE 2: Semantic Safety & Policy Engine
        # ---------------------------------------------------------
        st.markdown("### 🧠 Lane 2: Semantic Safety & Policy Engine (NVIDIA Nemotron)")
        
        with st.spinner("Analyzing intent safety with NVIDIA Nemotron..."):
            # Unpack 4 values: (is_safe, category, verdict_reason, action_status)
            is_safe, category, verdict_reason, action_status = run_lane2_semantic_engine(sanitized_text)

        # Action Verdict Banner
        if action_status == "ALLOWED" or is_safe:
            st.success(f"✅ **VERDICT: {action_status}**")
        elif action_status == "FLAGGED":
            st.warning(f"⚠️ **VERDICT: {action_status}**")
        else:
            st.error(f"🛑 **VERDICT: {action_status}**")

        # Diagnostics Display
        m_col1, m_col2 = st.columns(2)
        with m_col1:
            st.metric(label="Policy Category", value=category)
        with m_col2:
            st.metric(label="Action Status", value=action_status)

        st.markdown("**Security Diagnostic & Risk Analysis:**")
        st.info(verdict_reason)
