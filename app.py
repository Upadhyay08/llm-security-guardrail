import streamlit as st
from lane1_engine import run_lane1_deterministic_engine
from lane2_engine import run_lane2_semantic_engine

# --- Page Configuration ---
st.set_page_config(
    page_title="Enterprise LLM Security Guardrail",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Elite UI ---
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stTextArea textarea {
        background-color: #161b22;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 8px;
    }
    .block-container {
        padding-top: 2rem;
    }
    </style>
""", unsafe_allow_html=True)

# --- Sidebar Info ---
with st.sidebar:
    st.markdown("### 🛡️ Guardrail Status")
    st.success("🟢 Lane 1: Deterministic Engine (Active)")
    st.success("🟢 Lane 2: OpenAI GPT-4o-mini (Active)")
    st.markdown("---")
    st.markdown("**Architecture:** Dual-Lane Pipeline")
    st.markdown("**Compliance:** Zero-Hardcoding Intent Reasoning")

# --- Main Dashboard Header ---
st.title("🛡️ Enterprise LLM Security Guardrail Dashboard")
st.markdown("Real-time multi-layered defense pipeline detecting PII/Financial leakage (Lane 1) and evaluating semantic intent safety (Lane 2).")
st.markdown("---")

# --- User Input Section ---
st.markdown("### 📥 Input Console")
user_prompt = st.text_area(
    "Enter Prompt to Evaluate:",
    placeholder="Type or paste your prompt here (e.g., PII data, ransomware scripts, wire transfers, or safe queries)...",
    height=130
)

col1, col2 = st.columns([1, 1])
with col1:
    run_btn = st.button("🚀 Run Pipeline", type="primary", use_container_width=True)
with col2:
    clear_btn = st.button("🔄 Clear Input", use_container_width=True)

if clear_btn:
    st.rerun()

if run_btn:
    if not user_prompt.strip():
        st.warning("⚠️ Please enter a prompt to evaluate.")
    else:
        with st.spinner("🔍 Executing dual-lane security inspection..."):
            
            # --- Bulletproof Lane 1 Execution ---
            lane1_output = run_lane1_deterministic_engine(user_prompt)
            
            if isinstance(lane1_output, tuple):
                if len(lane1_output) >= 4:
                    sanitized_text, pii_detected, lane1_meta = lane1_output[0], lane1_output[1], lane1_output[2]
                elif len(lane1_output) == 3:
                    sanitized_text, pii_detected, lane1_meta = lane1_output
                else:
                    sanitized_text, pii_detected, lane1_meta = user_prompt, False, {}
            else:
                sanitized_text, pii_detected, lane1_meta = user_prompt, False, {}
            
            st.markdown("---")
            st.markdown("### 🔍 Execution Pipeline Results")
            
            tab1, tab2 = st.tabs(["Lane 1: Deterministic & PII", "Lane 2: Semantic Intent (OpenAI)"])
            
            with tab1:
                st.markdown("#### Deterministic Redaction Engine")
                st.markdown(f"**Original Text:**\n`{user_prompt}`")
                st.markdown(f"**Sanitized Output (Post-Scrub):**\n`{sanitized_text}`")
                
                if pii_detected:
                    st.warning(f"⚠ Scrubbed **{lane1_meta.get('redaction_count', 0)}** sensitive entities.")
                    st.json(lane1_meta.get('detected_entities', []))
                else:
                    st.success("✅ Lane 1 Passed: No hardcoded PII/financial regex patterns matched.")
            
            with tab2:
                st.markdown("#### Semantic Safety & Policy Engine (GPT-4o-mini)")
                
                # --- Lane 2 Execution ---
                l2_passed, l2_code, l2_msg, l2_status = run_lane2_semantic_engine(sanitized_text)
                
                if l2_status == "BLOCKED":
                    st.error(f"🛑 **VERDICT: BLOCKED**")
                    st.markdown(f"**Policy Category:** `{l2_code}`")
                    st.markdown(f"**Diagnostic & Risk Analysis:**\n> {l2_msg}")
                else:
                    st.success(f"✅ **VERDICT: ALLOWED**")
                    st.markdown(f"**Policy Category:** `{l2_code}`")
                    st.markdown(f"**Diagnostic & Risk Analysis:**\n> {l2_msg}")
