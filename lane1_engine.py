import re
from typing import Tuple, List, Dict

# Complete Global Enterprise Regex Suite
# Covers Indian, US, UK, EU & Global Identifiers, Financial Data, and Secrets
REGEX_PATTERNS: Dict[str, str] = {
    # 1. Financial Identifiers & Application Tracking
    "APPLICATION_ID": r'#(?:MA|SAV|EXT|LOAN|ACC|CHK|MORT|CARD|APP)-\d{4,8}\b',
    "CREDIT_CARD": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
    "IBAN": r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
    "ROUTING_NUMBER": r'\b(0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b',
    "ACCOUNT_NUMBER": r'(?i)\b(?:account|acc|acct|savings|checking)\s*(?:number|no|#)?\s*[:#-]?\s*(\d{6,16})\b',

    # 2. Foreign / Global Tax Identifiers (US, UK, AU, CA, etc.)
    "US_SSN": r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',  # US Social Security Number
    "US_ITIN": r'\b9\d{2}-[7-9]\d-\d{4}\b',                             # US Individual Taxpayer ID
    "UK_UTR": r'\b\d{10}\b',                                            # UK Unique Taxpayer Reference
    "UK_NINO": r'\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\d{6}[A-D]{1}\b', # UK National Insurance No
    "AU_TFN": r'\b\d{8,9}\b',                                            # Australia Tax File Number
    "CA_SIN": r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b',                       # Canada Social Insurance Number

    # 3. Foreign / Global Address & ID Proofs
    "DRIVERS_LICENSE": r'(?i)\b(?:driver\'?s?\s*licen[sc]e|dl|licence\s*no)\s*[:#-]?\s*([A-Z0-9]{6,15})\b',
    "STATE_ID": r'(?i)\b(?:state\s*id|national\s*id|eID)\s*[:#-]?\s*([A-Z0-9]{6,15})\b',
    "UTILITY_BILL_ACC": r'(?i)\b(?:utility\s*bill|water\s*bill|electricity\s*bill|gas\s*bill)\s*(?:no|num|account)?\s*[:#-]?\s*([A-Z0-9]{6,16})\b',

    # 4. Indian Identifiers
    "PAN_CARD": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "AADHAAR": r'\b[2-9]{1}\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',

    # 5. Financial Context & Credit Attributes
    "CREDIT_SCORE": r'(?i)\b(?:credit\s*score|cibil(?:\s*score)?|fico(?:\s*score)?)\s*[:#-]?\s*(\d{3})\b',
    "ANNUAL_INCOME": r'(?i)\b(?:annual\s*income|income|salary|net\s*pay)\s*[:#-]?\s*(\$?\d{1,3}(?:,\d{3})*|\d+)\b',
    "TRANSACTION_AMOUNT": r'(?i)\b(?:amount|balance|sum|transfer|deposit|withdrawal|loan\s*amount)\s*[:#-]?\s*(\$\d{1,3}(?:,\d{3})*|\$\d+|\b\d{1,3}(?:,\d{3})+\b)\b',

    # 6. Geographical & Postal Identifiers
    "ZIP_POSTCODE": r'(?i)\b(?:ZIP\s*(?:code)?|postal\s*code|pin\s*code|pincode)\s*[:#-]?\s*([A-Z0-9]{3,10}(?:[-\s][A-Z0-9]{3,4})?)\b',

    # 7. Personal Identifiers (PII)
    "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "PASSPORT": r'\b[A-PR-WYA-Z][0-9]{7,8}\b',
    "PERSON_NAME": r'(?i)\b(?:applicant|customer|user|client|borrower|for|contact)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b',

    # 8. Credentials, API Keys & System Leaks
    "AWS_KEY": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    "API_KEY": r'(?i)(api[_-]?key|secret|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
    "JWT_TOKEN": r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
    "IP_ADDRESS": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
}


def run_regex_redaction(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Handles structured PII, Foreign/Domestic IDs, Financial Attributes, and Secrets via Regex matching."""
    sanitized_text = text
    detected_violations = []

    for pii_type, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, sanitized_text)
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
