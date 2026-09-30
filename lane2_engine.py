import os
import re
import json
import logging
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _get_nvidia_api_key() -> str:
    """Fetch key from Environment or Streamlit Secrets."""
    key = os.getenv("NVIDIA_API_KEY")
    if not key:
        try:
            import streamlit as st
            key = st.secrets.get("NVIDIA_API_KEY", None)
        except Exception:
            pass
    return key or ""


def run_lane2_semantic_engine(sanitized_text: str = "") -> tuple[bool, str, str, str]:
    """
    Lane 2 Safety Guardrail Engine using NVIDIA Llama Guard 4 (12B).
    """
    if not sanitized_text or not sanitized_text.strip():
        return True, "COMPLIANT_QUERY", "No input query provided.", "ALLOWED"

    nvidia_api_key = _get_nvidia_api_key()

    if not nvidia_api_key:
        return False, "CONFIG_ERROR", "API Key missing in Streamlit Secrets (NVIDIA_API_KEY).", "BLOCKED"

    try:
        # Initialize OpenAI Client pointing to NVIDIA NIM Base URL
        client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=nvidia_api_key
        )

        # Llama Guard natively expects user prompts and returns 'safe' or 'unsafe\nS<category_code>'
        response = client.chat.completions.create(
            model="meta/llama-guard-3-8b",  # or meta/llama-guard-4-12b based on exact endpoint model string
            messages=[
                {"role": "user", "content": sanitized_text}
            ],
            temperature=0.0,
            max_tokens=100
        )

        raw_output = response.choices[0].message.content.strip()

        # Parse Llama Guard Output
        if raw_output.lower().startswith("safe"):
            return True, "SAFE_QUERY", "Input complies with AI safety guardrails.", "ALLOWED"
        else:
            # Output format for unsafe is usually:
            # unsafe
            # S1
            lines = raw_output.split("\n")
            category_code = lines[1].strip() if len(lines) > 1 else "POLICY_VIOLATION"
            
            return False, f"SAFETY_VIOLATION_{category_code}", f"Flagged by Llama Guard under category {category_code}.", "BLOCKED"

    except Exception as e:
        logger.error(f"Lane 2 Execution Error: {type(e).__name__} - {str(e)}")
        return False, "EVALUATION_FAILURE", f"API Connection Error [{type(e).__name__}]: {str(e)}", "BLOCKED"
