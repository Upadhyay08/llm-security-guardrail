import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_lane1_deterministic_engine(text: str = "") -> tuple[str, bool, dict]:
    """
    Lane 1: Deterministic & Dynamic Regex Redaction Engine.
    Strictly returns 3 values: (sanitized_text, has_pii, metadata)
    """
    if not text or not text.strip():
        logger.info("Lane 1 Engine: Empty query string received.")
        return text, False, {"detected_entities": [], "redaction_count": 0}

    try:
        redacted_text = text
        entities_detected = []

        # Comprehensive Dynamic Patterns for Financial & Applicant PII
        dynamic_patterns = {
            "MORTGAGE_ID_REDACTED": r"\b(?:hashtag#|#)?MA-\d{4,6}\b",
            "CURRENCY_INCOME_REDACTED": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b",
            "CREDIT_SCORE_REDACTED": r"\bcredit\s+score\s+(?:of\s+)?\d{3}\b",
            "ZIP_CODE_REDACTED": r"\b(?:ZIP\s+code\s+|postal\s+code\s+)?\b\d{5}(?:-\d{4})?\b",
            "APPLICANT_NAME_REDACTED": r"\bfor\s+applicant\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b",
            "EMPLOYMENT_DURATION_REDACTED": r"\b\d+\s+years?\s+at\s+current\s+employer(?:\s+in\s+[a-zA-Z]+)?\b",
            "SSN_REDACTED": r"\b\d{3}-\d{2}-\d{4}\b",
            "PAN_REDACTED": r"\b[A-Z]{5}\d{4}[A-Z]{1}\b",
            "AADHAAR_REDACTED": r"\b\d{4}\s?\d{4}\s?\d{4}\b"
        }

        for label, pattern in dynamic_patterns.items():
            matches = re.findall(pattern, redacted_text, re.IGNORECASE)
            if matches:
                for match in matches:
                    entities_detected.append((str(match), label))
                redacted_text = re.sub(
                    pattern, f"[{label}]", redacted_text, flags=re.IGNORECASE
                )

        has_pii = len(entities_detected) > 0
        metadata = {
            "detected_entities": entities_detected,
            "redaction_count": len(entities_detected)
        }

        logger.info(f"Lane 1 completed. Entities scrubbed: {len(entities_detected)}")
        return redacted_text, has_pii, metadata

    except Exception as e:
        logger.error(f"Lane 1 Engine Failure: {str(e)}")
        return text, False, {"error": str(e), "detected_entities": [], "redaction_count": 0}
