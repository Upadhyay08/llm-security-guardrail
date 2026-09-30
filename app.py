import streamlit as st
from lane1_engine import run_lane1_deterministic_engine
from lane2_engine import run_lane2_semantic_engine

# -------------------------------------------------------------
# PAGE CONFIGURATION & CUSTOM CSS
# -------------------------------------------------------------
st.set_page_config(
    page_title="SentinelShield | Dual-Lane LLM Guardrail",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for Professional Financial Tech Aesthetics
st.markdown("""
    <style>
    /* Main Theme Overrides */
    .stApp {
        background-color: #0F172A;
        color: #F8FAFC;
    }
    
    /* Header Container */
    .header-box {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        padding: 1.8rem;
        border-radius: 12px;
        border: 1px solid #334155;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .main-title {
        font-size: 2.3rem;
        font-weight: 800;
        color: #38BDF8;
        margin-bottom: 0.3rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #94A3B8;
        line-height: 1.5;
    }

    /* Info Cards & Architecture Box */
    .arch-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 1.2rem;
        margin-bottom: 1.5rem;
    }
    .badge-lane1 {
        background-color: #0EA5E9;
        color: #000000;
        font-weight: bold;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.85rem;
    }
    .badge-lane2 {
        background-color: #A855F7;
        color: #FFFFFF;
        font-weight: bold;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.85rem;
    }

    /* Metric Highlights */
    .metric-container {
        display: flex;
        gap: 10px;
        margin-bottom: 1rem;
    }
    
    </style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# APP HEADER SECTION
# -------------------------------------------------------------
st.markdown("""
    <div class="header-box">
        <div class="main-title">🛡️ SentinelShield: Enterprise LLM Guardrail</div>
        <div class="sub-title">
            Real-time, dual-layer AI security framework engineered for Banking & Financial Services. 
            Protects enterprise LLM endpoints against <b>PII leakage, account credential exploitation, fraud intent, and prompt injections</b>.
        </div>
    </div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# SIDEBAR CONFIGURATION & GUIDE
# -------------------------------------------------------------
st.sidebar.header("⚙️ Security Settings")

default_key = st.secrets.get("NVIDIA_API_KEY", "") if "NVIDIA_API_KEY" in st.secrets else ""

nvidia_api_key = st.sidebar.text_input(
    "NVIDIA Build API Key",
    value=default_key,
    type="password",
    help="Required for Lane 2 Semantic Safety evaluation. Get a free key at build.nvidia.com"
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔍 System Metrics")
st.sidebar.metric(label="Lane 1 Latency", value="~2 ms", delta="Sub-millisecond")
st.sidebar.metric(label="Lane 2 Latency", value="~250 ms", delta="Real-Time API")
st.sidebar.metric(label="PII Coverage", value="10+ Types", delta="Deterministic Regex")

st.sidebar.markdown("---")
st.sidebar.info("💡 **Tip:** Enter custom text or test financial fraud prompts to observe zero-trust sanitized forwarding.")

# -------------------------------------------------------------
# ARCHITECTURE OVERVIEW (Interactive Expander)
# -------------------------------------------------------------
with st.expander("ℹ️ How SentinelShield Works (Architecture & Data Flow)", expanded=False):
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("""
        #### ⚡ Lane 1: Deterministic Engine
        * **Type:** Fast Pattern Matcher (Regex-driven)
        * **Target:** High-risk Structured PII, Credit Cards, SSN, IBAN, Application IDs, API Keys & JWT Tokens.
        * **Action:** Redacts sensitive credentials **before** sending payload to any external AI API. Zero data exposure.
        """)
    with col_b:
        st.markdown("""
        #### 🧠 Lane 2: Semantic Safety Engine
        * **Type:** Deep Learning Guard Model (`NVIDIA Nemotron Safety 8B`)
        * **Target:** Jailbreak prompts, Fraudulent Transaction requests, Authorization Bypass, Policy Violations.
        * **Action:** Evaluates intent on sanitized output and returns a **Block/Allow** decision.
        """)
    
    st.markdown("---")
    st.markdown("""
    ```
    [ User Input Prompt ]
             │
             ▼
    ┌─────────────────────────────────────────┐
    │ 🛡️ Lane 1: Deterministic PII Masking    │  ──► Mask Credentials ([APPLICATION_ID_REDACTED], etc.)
    └─────────────────────────────────────────┘
             │
             ▼  (Sanitized Text Payload)
    ┌─────────────────────────────────────────┐
    │ 🧠 Lane 2: NVIDIA Nemotron Safety Guard │  ──► Semantic Fraud & Jailbreak Analysis
    └─────────────────────────────────────────┘
             │
             ▼
    [ Final Decision: ALLOWED / BLOCKED ]
    ```
    """)

# -------------------------------------------------------------
# INPUT SECTION
# -------------------------------------------------------------
st.markdown("### 1. Enterprise Prompt Playground")

user_prompt = st.text_area(
    "Enter any prompt, request, or test snippet to run through guardrails:",
    placeholder="Example: Send $50,000 from account #SAV-982143 to external account #EXT-00213 or 'How to bypass OTP verification?'...",
    height=130
)

# Execution trigger
col_btn1, col_btn2 = st.columns([1, 4])
with col_btn1:
    eval_button = st.button("🛡️ Evaluate Security Guardrails", type="primary", use_container_width=True)

st.markdown("---")

# -------------------------------------------------------------
# EVALUATION & RESULTS DISPLAY
# -------------------------------------------------------------
if eval_button:
    if not user_prompt.strip():
        st.warning("⚠️ Please type or paste a prompt in the text box above to execute evaluation.")
    else:
        st.markdown("### 2. Live Security Pipeline Execution")
        
        c1, c2 = st.columns(2)

        # ---------------------------------------------------------
        # LANE 1 EXECUTION
        # ---------------------------------------------------------
        with c1:
            st.markdown('#### <span class="badge-lane1">LANE 1</span> Deterministic Masking', unsafe_allow_html=True)
            st.caption("Regex Engine scanning for sensitive credentials & data leaks...")

            clean_text, violations, is_flagged = run_lane1_deterministic_engine(user_prompt)

            if is_flagged:
                st.error(f"🚨 **PII / Credentials Redacted** ({len(violations)} match(es))")
                st.markdown("**Sanitized Text (Safe for LLM Forwarding):**")
                st.code(clean_text, language="text")

                with st.expander("🔍 Detailed Violations Log", expanded=True):
                    for v in violations:
                        st.markdown(f"• **Type:** `{v['type']}` | **Value:** `{v['value']}`")
            else:
                st.success("✅ **No Sensitive PII / Credentials Detected**")
                st.markdown("**Clean Output:**")
                st.code(clean_text, language="text")

        # ---------------------------------------------------------
        # LANE 2 EXECUTION
        # ---------------------------------------------------------
        with c2:
            st.markdown('#### <span class="badge-lane2">LANE 2</span> Semantic Safety & Policy', unsafe_allow_html=True)
            st.caption("NVIDIA Nemotron Safety 8B evaluating intent & policy compliance...")

            if not nvidia_api_key:
                st.warning("🔑 **NVIDIA API Key Missing:** Please enter your key in the sidebar to run Lane 2 Safety Analysis.")
            else:
                with st.spinner("Analyzing intent safety with NVIDIA Nemotron..."):
                    # Forward sanitized text from Lane 1 to preserve privacy
                    is_safe, category, verdict_reason = run_lane2_semantic_engine(clean_text, nvidia_api_key)

                if is_safe:
                    st.success("✅ **VERDICT: ALLOWED**")
                    st.markdown(f"**Policy Category:** `{category}`")
                    st.info(f"**Security Analysis:** {verdict_reason}")
                else:
                    st.error("🛑 **VERDICT: BLOCKED**")
                    st.markdown(f"**Policy Violation:** `{category}`")
                    st.warning(f"**Security Analysis:** {verdict_reason}")
