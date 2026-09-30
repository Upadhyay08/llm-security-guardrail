import re
from typing import Tuple, List, Dict

# Complete Production Regex & Pattern Matcher Suite
REGEX_PATTERNS: Dict[str, str] = {
    # Financial & Application Identifiers
    "APPLICATION_ID": r'#(?:MA|SAV|EXT|LOAN|ACC|CHK)-\d{4,8}\b',
    "CREDIT_CARD": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "IBAN": r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
    "ROUTING_NUMBER": r'\b(0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b',

    # Personal Identifiers & Unstructured PII
    "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "PAN_CARD": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "AADHAAR": r'\b[2-9]{1}\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',
    "PERSON_NAME": r'\b(?:applicant|customer|user|for|contact)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b',

    # Secrets, API Keys & Tech Leaks
    "AWS_KEY": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    "API_KEY": r'(?i)(api[_-]?key|secret|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
    "JWT_TOKEN": r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
}


def run_regex_redaction(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Handles structured PII, Financial IDs, Person Entities, and Secrets via Regex matching."""
    sanitized_text = text
    detected_violations = []

    for pii_type, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, sanitized_text, flags=re.IGNORECASE if pii_type == "API_KEY" else 0)
        if matches:
            for match in set(matches):
                val_str = match[0] if isinstance(match, tuple) else match
                if val_str and len(val_str.strip()) > 1:
                    detected_violations.append({
                        "type": pii_type,
                        "value": val_str,
                        "engine": "Deterministic Engine"
                    })
                    sanitized_text = sanitized_text.replace(val_str, f"[{pii_type}_REDACTED]")

    return sanitized_text, detected_violations


def run_lane1_deterministic_engine(text: str) -> Tuple[str, List[Dict[str, str]], bool]:
    """
    Main Lane 1 Entrypoint: Runs sequential Regex & Pattern filtering.
    Returns: (sanitized_text, list_of_violations, is_flagged)
    """
    final_sanitized_text, violations = run_regex_redaction(text)
    is_flagged = len(violations) > 0

    return final_sanitized_text, violations, is_flagged


# Quick Standalone Test
if __name__ == "__main__":
    test_text = "Review mortgage application #MA-58210 for applicant Jordan Reyes with AWS key AKIAIOSFODNN7EXAMPLE."
    clean, vios, flagged = run_lane1_deterministic_engine(test_text)
    print("Sanitized Output:", clean)
    print("Violations:", vios)
