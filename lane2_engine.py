import os
import logging
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _get_nvidia_api_key() -> str:
    key = os.getenv("NVIDIA_API_KEY")
    if not key:
        try:
            import streamlit as st
            key = st.secrets.get("NVIDIA_API_KEY", None)
        except Exception:
            pass
    return key or ""

def run_lane2_semantic_engine(sanitized_text: str = "") -> tuple[bool, str, str, str]:
    if not sanitized_text or not sanitized_text.strip():
        return True, "COMPLIANT_QUERY", "No input query provided.", "ALLOWED"

    nvidia_api_key = _get_nvidia_api_key()

    if not nvidia_api_key:
        return False, "CONFIG_ERROR", "API Key missing in Streamlit Secrets (NVIDIA_API_KEY).", "BLOCKED"

    # FIX: Increased timeout to 45 seconds for Cold Starts, enabled 2 retries
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=nvidia_api_key,
        max_retries=2,       
        timeout=45.0         
    )

    try:
        model_name = "meta/llama-guard-4-12b"
        logger.info(f"Firing Lane 2 Safety Engine exactly with: {model_name} (Timeout set to 45s)")

        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "user", "content": sanitized_text}
            ],
            temperature=0.0,
            max_tokens=100
        )

        raw_output = completion.choices[0].message.content.strip()

        if raw_output.lower().startswith("safe"):
            return True, "SAFE_INTENT", "Query satisfies Llama Guard 4 safety checks.", "ALLOWED"
        else:
            lines = raw_output.split("\n")
            violation_category = lines[1].strip() if len(lines) > 1 else "POLICY_VIOLATION"
            
            return (
                False, 
                f"SAFETY_VIOLATION_{violation_category}", 
                f"Prompt flagged as unsafe by Llama Guard under category {violation_category}.", 
                "BLOCKED"
            )

    except Exception as e:
        logger.error(f"Lane 2 Execution Error: {type(e).__name__} - {str(e)}")
        return False, "EVALUATION_FAILURE", f"API Error: {str(e)}", "BLOCKED"
