import re
import spacy
from typing import Tuple, List, Dict

# Global level load for performance (avoid reloading model per request)
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    nlp = None

# Comprehensive Production Regex Suite for Structured PII, Banking Identifiers & Secrets
REGEX_PATTERNS: Dict[str, str] = {
    # Financial & Application Identifiers
    "APPLICATION_ID": r'#(?:MA|SAV|EXT|LOAN|ACC|CHK)-\d{4,8}\b',
    "CREDIT_CARD": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "IBAN": r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
    "ROUTING_NUMBER": r'\b(0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b',

    # Personal Identifiers
    "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "PAN_CARD": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "AADHAAR": r'\b[2-9]{1}\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',

    # Secrets, API Keys & Tech Leaks
    "AWS_KEY": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    "API_KEY": r'(?i)(api[_-]?key|secret|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
    "JWT_TOKEN": r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
}


def run_regex_redaction(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Handles structured PII, Financial IDs, and Cloud Secrets via Regex matching."""
    sanitized_text = text
    detected_violations = []

    for pii_type, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, sanitized_text)
        if matches:
            for match in set(matches):
                val_str = match[0] if isinstance(match, tuple) else match
                detected_violations.append({
                    "type": pii_type,
                    "value": val_str,
                    "engine": "Regex Engine"
                })
                sanitized_text = sanitized_text.replace(val_str, f"[{pii_type}_REDACTED]")

    return sanitized_text, detected_violations


def run_ner_redaction(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Handles unstructured PII (Names, Companies, Locations) via spaCy Named Entity Recognition."""
    sanitized_text = text
    detected_violations = []

    if nlp is None:
        return sanitized_text, detected_violations

    doc = nlp(sanitized_text)
    
    # Reverse order replacement to avoid character position displacement during string slicing
    for ent in sorted(doc.ents, key=lambda x: x.start_char, reverse=True):
        if ent.label_ in ["PERSON", "ORG", "GPE", "LOC"]:
            detected_violations.append({
                "type": ent.label_,
                "value": ent.text,
                "engine": "spaCy NER"
            })
            start, end = ent.start_char, ent.end_char
            sanitized_text = (
                sanitized_text[:start] +
                f"[{ent.label_}_REDACTED]" +
                sanitized_text[end:]
            )

    return sanitized_text, detected_violations


def run_lane1_deterministic_engine(text: str) -> Tuple[str, List[Dict[str, str]], bool]:
    """
    Main Lane 1 Entrypoint: Runs sequential Regex + spaCy NER filtering.
    Returns: (sanitized_text, list_of_violations, is_flagged)
    """
    # Step 1: Execute Regex Subscriptions
    text_after_regex, regex_violations = run_regex_redaction(text)
    
    # Step 2: Execute spaCy NER Entity Masking
    final_sanitized_text, ner_violations = run_ner_redaction(text_after_regex)

    all_violations = regex_violations + ner_violations
    is_flagged = len(all_violations) > 0

    return final_sanitized_text, all_violations, is_flagged


# Multi-Prompt Test Execution Suite
if __name__ == "__main__":
    test_prompts = [
        # Test 1: Mortgage Application + Person Name
        "I'm reviewing mortgage application #MA-58210 for applicant Jordan Reyes: annual income $72,000, credit score 640.",
        
        # Test 2: Wire Transfer + Multiple Account Hashtags + Person Name
        "Send $25,000 from savings account #SAV-0294817 (customer: Marjorie Tenley) to external account #EXT-7734021.",
        
        # Test 3: Direct PII Request + AWS Cloud Secret
        "Contact John Smith at john.smith@company.com or call +1 555-019-2834. Access key: AKIAIOSFODNN7EXAMPLE.",
        
        # Test 4: Indian Context (PAN Card & Aadhaar)
        "Please update KYC details for Ramesh Kumar. PAN Card: ABCDE1234F and Aadhaar: 9876 5432 1098.",
        
        # Test 5: Clean Request (No PII / Should Pass Unmodified)
        "Review these recent transactions and identify which ones are most likely fraudulent. Explain the signals."
    ]

    print("========================================================================")
    print("🛡️ SENTINELSHIELD: LANE 1 DETERMINISTIC ENGINE TEST SUITE")
    print("========================================================================\n")

    for idx, prompt in enumerate(test_prompts, 1):
        clean_text, violations, is_blocked = run_lane1_deterministic_engine(prompt)
        
        print(f"--- TEST CASE {idx} ---")
        print(f"Original:  {prompt}")
        print(f"Sanitized: {clean_text}")
        print(f"Flagged:   {is_blocked}")
        
        if violations:
            print("Detections:")
            for v in violations:
                print(f"  • [{v['engine']}] {v['type']}: {v['value']}")
        else:
            print("Detections: None (Clean Prompt)")
            
        print("-" * 72 + "\n")
