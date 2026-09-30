import os
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _get_nvidia_api_key() -> str:
    """Fetch API Key safely from Environment variables."""
    return os.getenv("NVIDIA_API_KEY", "")

def run_lane2_semantic_engine(sanitized_text: str = "") -> tuple[bool, str, str, str]:
    """
    Lane 2 Engine powered by NVIDIA NIM Llama Guard 4 (12B).
    Uses RAW Python Requests to completely bypass OpenAI SDK/HTTPX firewall blocks.
    """
    if not sanitized_text or not sanitized_text.strip():
        return True, "COMPLIANT_QUERY", "No input query provided.", "ALLOWED"

    api_key = _get_nvidia_api_key()

    if not api_key:
        return False, "CONFIG_ERROR", "NVIDIA_API_KEY missing in Environment Secrets.", "BLOCKED"

    # Direct NVIDIA API Endpoint
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "model": "meta/llama-guard-4-12b",
        "messages": [{"role": "user", "content": sanitized_text}],
        "temperature": 0.0,
        "max_tokens": 100
    }

    try:
        logger.info("Firing Lane 2 Safety Engine via RAW Requests (Bypassing SDK Blocks)...")
        
        # 60-second timeout to handle NVIDIA cold starts safely
        response = requests.post(url, headers=headers, json=payload, timeout=60.0)
        
        # If NVIDIA blocks it, we will see the EXACT reason (e.g. 403 Forbidden)
        if response.status_code != 200:
            logger.error(f"NVIDIA API Error {response.status_code}: {response.text}")
            return False, "EVALUATION_FAILURE", f"NVIDIA Server Error: {response.status_code}", "BLOCKED"

        data = response.json()
        raw_output = data["choices"][0]["message"]["content"].strip()

        # Parse Llama Guard Output
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

    except requests.exceptions.Timeout:
        logger.error("Lane 2 Execution Error: Request timed out after 60 seconds.")
        return False, "EVALUATION_FAILURE", "NVIDIA Server Timeout (Cold Start)", "BLOCKED"
    except Exception as e:
        logger.error(f"Lane 2 Execution Error: {type(e).__name__} - {str(e)}")
        return False, "EVALUATION_FAILURE", f"Connection Error: {str(e)}", "BLOCKED"
