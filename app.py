import streamlit as st
from lane1_engine import run_lane1_deterministic_engine
from lane2_engine import run_lane2_semantic_engine

# Page Configuration
st.set_page_config(
    page_title="Enterprise LLM Security Guardrail",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Enterprise LLM Security Guardrail Application")
st.markdown("Multi-layered security pipeline detecting deterministic violations (Lane 1) and evaluating semantic intent safety via OpenAI (Lane 2).")
st.markdown("---")

# User Input Section
user_prompt = st.text_area(
    "Enter Prompt to Evaluate:",
    placeholder="Type your prompt here (e.g., ransomware script, wire transfer request, or a safe educational question)...",
    height=120
)

if st.button("Run Security Pipeline", type="primary"):
    if not user_prompt.strip():
        st.warning("⚠️ Please enter a prompt to evaluate.")
    else:
        with st.spinner("Executing multi-layered guardrail pipeline..."):
            
            # --- Lane 1 Execution ---
            l1_passed, l1_code, l1_msg, l1_status = run_lane1_deterministic_engine(user_prompt)
            
            st.markdown("---")
            st.subheader("🔍 Lane 1: Deterministic Engine")
            st.markdown(f"**Original Prompt:**\n\n`{user_prompt}`")
            
            if not l1_passed:
                st.error(f"🛑 VERDICT: BLOCKED\n\n**Policy Category:** {l1_code}\n\n**Diagnostic:** {l1_msg}")
            else:
                st.success("✅ Lane 1 Passed (No deterministic PII or financial patterns matched).")
                
                # --- Lane 2 Execution ---
                l2_passed, l2_code, l2_msg, l2_status = run_lane2_semantic_engine(user_prompt)
                
                st.markdown("---")
                st.subheader("🧠 Lane 2: Semantic Safety & Policy Engine (OpenAI GPT-4o-mini)")
                
                if l2_status == "BLOCKED":
                    st.error(f"🛑 VERDICT: BLOCKED\n\n**Policy Category:** {l2_code}\n\n**Security Diagnostic & Risk Analysis:**\n{l2_msg}")
                else:
                    st.success(f"✅ VERDICT: ALLOWED\n\n**Policy Category:** {l2_code}\n\n**Security Diagnostic & Risk Analysis:**\n{l2_msg}")
