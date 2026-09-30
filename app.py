with st.spinner("🔍 Executing dual-lane security inspection..."):
            
            # --- Bulletproof Lane 1 Execution (Handles 3 or 4 values automatically) ---
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
