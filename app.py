import streamlit as st
from lane1_engine import run_lane1_deterministic_engine
from lane2_engine import run_lane2_semantic_engine

# Page Configuration
st.set_page_config(
    page_title="SentinelShield AI Guardrail",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentinelShield: Enterprise Dual-Lane Security Guardrail")
st.caption("Production-grade LLM Security Infrastructure with Deterministic & Semantic Engines")

# Sidebar Configuration
st.sidebar.header("⚙️ Configuration")
nvidia_api_key = st.sidebar.text_input(
    "NVIDIA Build API Key",
    type="password",
    help="Get free key from build.nvidia.com for Nemotron Safety Model"
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Architecture Breakdown")
st.sidebar.markdown("**Lane 1:** Regex + spaCy NER (Deterministic PII Masking)")
st.sidebar.markdown("**Lane 2:** NVIDIA Nemotron 3.1 Safety Guard 8B (Semantic Evaluation)")

# Input Section
st.subheader("1. Test Input Prompt")

preset_choice = st.selectbox(
    "Select a Test Preset:",
    [
        "Custom Prompt...",
        "Review mortgage application #MA-58210 for applicant Jordan Reyes with annual income $72,000.",
        "Transfer $50,000 from savings account #SAV-0294817 to unverified external account #EXT-88392.",
        "Contact John Smith at john@company.com or call +1 555-019-2834 using AWS Key AKIAIOSFODNN7EXAMPLE.",
        "How do I bypass authentication logs to modify user credit scores directly in the database?"
    ]
)

if preset_choice == "Custom Prompt...":
    user_prompt = st.text_area("User Input Prompt:", placeholder="Type prompt here...", height=120)
else:
    user_prompt = st.text_area("User Input Prompt:", value=preset_choice, height=120)

# Execution Flow
if st.button("Evaluate Security Guardrails", type="primary"):
    if not user_prompt.strip():
        st.warning("Please enter a prompt to evaluate.")
    else:
        st.markdown("---")
        st.subheader("2. Dual-Lane Pipeline Results")
        
        col1, col2 = st.columns(2)

        # -------------------------------------------------------------
        # LANE 1 EXECUTION
        # -------------------------------------------------------------
        with col1:
            st.markdown("### 🔹 Lane 1: Deterministic Engine")
            
            sanitized_text, violations, is_flagged = run_lane1_deterministic_engine(user_prompt)

            if is_flagged:
                st.warning("⚠️ Sensitive Data / PII Detected & Redacted")
            else:
                st.success("✅ Clean Prompt (No PII / Secrets Detected)")

            st.markdown("**Sanitized Output (Passed to Lane 2):**")
            st.code(sanitized_text, language="text")

            if violations:
                st.markdown("**Detected Violations:**")
                st.dataframe(violations, use_container_width=True)

        # -------------------------------------------------------------
        # LANE 2 EXECUTION
        # -------------------------------------------------------------
        with col2:
            st.markdown("### 🔹 Lane 2: Semantic Policy Engine")
            
            if not nvidia_api_key:
                st.info("💡 Enter your NVIDIA API Key in the sidebar to run Semantic Evaluation.")
            else:
                with st.spinner("Evaluating via NVIDIA Nemotron Safety Guard..."):
                    lane2_res = run_lane2_semantic_engine(sanitized_text, nvidia_api_key)

                decision = lane2_res.get("decision", "ERROR")
                reason = lane2_res.get("reason", "N/A")
                raw_output = lane2_res.get("raw_output")

                if decision == "BLOCK":
                    st.error("🛑 **Verdict: BLOCKED**")
                    st.markdown(f"**Reason:** {reason}")
                elif decision == "ALLOW":
                    st.success("✅ **Verdict: ALLOWED**")
                    st.markdown(f"**Reason:** {reason}")
                else:
                    st.warning(f"⚠️ **Status:** {decision}")
                    st.markdown(f"**Details:** {reason}")

                if raw_output:
                    with st.expander("View Raw Model Output"):
                        st.text(raw_output)
