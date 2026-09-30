import os
import logging
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Primary Llama Guard 4 12B model with fast fallback
LLAMA_GUARD_MODELS = [
    "meta/llama-guard-4-12b",
    "meta/llama-guard-3-8b"
]

def _get_nvidia_api_key() -> str:
    """Fetch key seamlessly from Environment or Streamlit Secrets."""
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
    Lane 2 Engine powered by NVIDIA NIM Llama Guard 4 (12B).
    Optimized for zero-retries and low latency.
    """
    if not sanitized_text or not sanitized_text.strip():
        return True, "COMPLIANT_QUERY", "No input query provided.", "ALLOWED"

    nvidia_api_key = _get_nvidia_api_key()

    if not nvidia_api_key:
        return False, "CONFIG_ERROR", "API Key missing in Streamlit Secrets (NVIDIA_API_KEY).", "BLOCKED"

    # Ultra-fast client setup: Zero retries, strict 5.0 second timeout
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=nvidia_api_key,
        max_retries=0, 
        timeout=5.0    
    )

    last_exception = None

    for model_name in LLAMA_GUARD_MODELS:
        try:
            logger.info(f"Running Lane 2 Safety Evaluation with model: {model_name}")

            # Llama Guard natively evaluates the prompt and replies safe/unsafe
            completion = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "user", "content": sanitized_text}
                ],
                temperature=0.0,
                max_tokens=100
            )

            raw_output = completion.choices[0].message.content.strip()

            # Parse Llama Guard Output format ('safe' or 'unsafe\nS<category_code>')
            if raw_output.lower().startswith("safe"):
                return True, "SAFE_INTENT", "Query satisfies safety and compliance checks.", "ALLOWED"
            else:
                lines = raw_output.split("\n")
                violation_category = lines[1].strip() if len(lines) > 1 else "GENERAL_POLICY_VIOLATION"
                
                return (
                    False, 
                    f"SAFETY_VIOLATION_{violation_category}", 
                    f"Prompt flagged as unsafe under category {violation_category}.", 
                    "BLOCKED"
                )

        except Exception as e:
            logger.warning(f"Failed execution with {model_name}: {type(e).__name__} - {str(e)}")
            last_exception = e
            continue

    # Triggers only if all models fail (fail-secure fallback)
    return False, "EVALUATION_FAILURE", f"API Connection Error [{type(last_exception).__name__}]: {str(last_exception)}", "BLOCKED"
