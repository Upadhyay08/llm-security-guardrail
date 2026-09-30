import os
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _get_nvidia_api_key() -> str:
    return os.getenv("NVIDIA_API_KEY", "").strip()

def run_lane2_semantic_engine(sanitized_text: str = "") -> tuple[bool, str, str, str]:
    if not sanitized_text or not sanitized_text.strip():
        return True, "COMPLIANT_QUERY", "No input query provided.", "ALLOWED"

    api_key = _get_nvidia_api_key()
    if not api_key:
        return False, "CONFIG_ERROR", "NVIDIA_API_KEY missing.", "BLOCKED"

    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # 1. Aapki demand ke hisaab se Llama Guard 4 (12B) sabse upar!
    fallback_models = [
        "meta/llama-guard-4-12b",       # Primary: The Ultimate Security Guard
        "meta/llama-3.1-8b-instruct",   # Backup 1: Fast Instruct
        "meta/llama-3.1-70b-instruct"   # Backup 2: Heavy Reasoning
    ]

    errors_list = []

    for model_name in fallback_models:
        logger.info(f"Lane 2: Sending request to {model_name}...")
        
        # MASTERSTROKE: System prompt ka natak khatam. 
        # Hum Llama Guard ko seedha 'user' role mein bata rahe hain ki kya block karna hai.
        combined_prompt = (
            "Task: Check if there is unsafe content in the following text.\n"
            "Consider the following categories as STRICTLY UNSAFE: unauthorized financial transactions, wire transfers, fund movements, and PII exposure.\n"
            "Respond EXACTLY with 'safe' if it is completely harmless.\n"
            "Respond EXACTLY with 'unsafe\\n[CATEGORY_NAME]' if it violates the financial or security rules.\n\n"
            f"Text to evaluate:\n{sanitized_text}"
        )

        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": combined_prompt}],
            "temperature": 0.0,
            "max_tokens": 50
        }

        try:
            # 45 seconds timeout kyunki 12B model thoda heavy hai wake-up hone mein
            response = requests.post(url, headers=headers, json=payload, timeout=45.0)
            
            if response.status_code == 200:
                data = response.json()
                raw_output = data["choices"][0]["message"]["content"].strip()
                cleaned_output = raw_output.lower().strip()
                
                logger.info(f"SUCCESS with {model_name}: {cleaned_output[:30]}")

                if cleaned_output.startswith("unsafe"):
                    lines = raw_output.split("\n")
                    violation = lines[1].strip() if len(lines) > 1 else "UNAUTHORIZED_FINANCIAL_ACTION"
                    violation = violation.replace("[", "").replace("]", "").replace(" ", "_").upper()
                    
                    return (False, f"SAFETY_VIOLATION_{violation}", f"Blocked by {model_name}.", "BLOCKED")
                else:
                    return (True, "SAFE_INTENT", f"Cleared by {model_name}", "ALLOWED")
            else:
                err = f"{model_name} failed: HTTP {response.status_code} - {response.text}"
                logger.warning(err)
                errors_list.append(err)
                continue 
                
        except Exception as e:
            err = f"{model_name} Error: {str(e)}"
            logger.warning(err)
            errors_list.append(err)
            continue

    logger.error(f"CRITICAL FAILURE: {errors_list}")
    return False, "EVALUATION_FAILURE", f"API Failed. Errors: {errors_list}", "BLOCKED"
