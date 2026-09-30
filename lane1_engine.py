import re
import spacy
from typing import Tuple, List, Dict

# Safe loading strategy for Streamlit Cloud
nlp = None
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    try:
        from spacy.cli import download
        download("en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")
    except Exception as e:
        print(f"Warning: spaCy NER model failed to load ({e}). Falling back to pure Regex mode.")
        nlp = None

# Comprehensive Production Regex Suite
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

    # Secrets & API Keys
    "AWS_KEY": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    "API_KEY": r'(?i)(api[_-]?key|secret|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
    "JWT_TOKEN": r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
}

def run_regex_redaction(text: str) -> Tuple[str, List[Dict[str, str]]]:
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
    sanitized_text = text
    detected_violations = []

    if nlp is None:
        return sanitized_text, detected_violations

    doc = nlp(sanitized_text)
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
    text_after_regex, regex_violations = run_regex_redaction(text)
    final_sanitized_text, ner_violations = run_ner_redaction(text_after_regex)
    all_violations = regex_violations + ner_violations
    return final_sanitized_text, all_violations, len(all_violations) > 0
