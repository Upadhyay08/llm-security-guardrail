import re
from typing import Tuple, List, Dict, Any

# Structure: Rule Key -> (Regex Pattern, Policy Category, Policy Name/Rule ID)
POLICY_RULES: Dict[str, Dict[str, Any]] = {
    # 1. Financial Identifiers & Application Tracking
    "APPLICATION_ID": {
        "pattern": r'#(?:MA|SAV|EXT|LOAN|ACC|CHK|MORT|CARD|APP)-\d{4,8}\b',
        "policy_id": "FIN-001",
        "category": "Financial Privacy / Tracking Data"
    },
    "CREDIT_CARD": {
        "pattern": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        "policy_id": "PCI-DSS-3.1",
        "category": "Payment Card Industry Data"
    },
    "IBAN": {
        "pattern": r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
        "policy_id": "FIN-002",
        "category": "Banking & Financial Identifiers"
    },
    "ROUTING_NUMBER": {
        "pattern": r'\b(0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b',
        "policy_id": "FIN-003",
        "category": "Banking & Financial Identifiers"
    },
    "ACCOUNT_NUMBER": {
        "pattern": r'(?i)\b(?:account|acc|acct|savings|checking)\s*(?:number|no|#)?\s*[:#-]?\s*(\d{6,16})\b',
        "policy_id": "FIN-004",
        "category": "Banking & Financial Identifiers"
    },

    # 2. Foreign / Global Tax Identifiers (US, UK, AU, CA, etc.)
    "US_SSN": {
        "pattern": r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        "policy_id": "PII-US-001",
        "category": "US Personally Identifiable Information"
    },
    "US_ITIN": {
        "pattern": r'\b9\d{2}-[7-9]\d-\d{4}\b',
        "policy_id": "PII-US-002",
        "category": "US Tax Identification Data"
    },
    "UK_UTR": {
        "pattern": r'\b\d{10}\b',
        "policy_id": "PII-UK-001",
        "category": "UK Tax Identification Data"
    },
    "UK_NINO": {
        "pattern": r'\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\d{6}[A-D]{1}\b',
        "policy_id": "PII-UK-002",
        "category": "UK National Insurance Data"
    },
    "AU_TFN": {
        "pattern": r'\b\d{8,9}\b',
        "policy_id": "PII-AU-001",
        "category": "Australia Tax File Data"
    },
    "CA_SIN": {
        "pattern": r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b',
        "policy_id": "PII-CA-001",
        "category": "Canada Social Insurance Data"
    },

    # 3. Foreign / Global Address & ID Proofs
    "DRIVERS_LICENSE": {
        "pattern": r'(?i)\b(?:driver\'?s?\s*licen[sc]e|dl|licence\s*no)\s*[:#-]?\s*([A-Z0-9]{6,15})\b',
        "policy_id": "PII-GLOBAL-001",
        "category": "Government Issued Identity / Residence Proof"
    },
    "STATE_ID": {
        "pattern": r'(?i)\b(?:state\s*id|national\s*id|eID)\s*[:#-]?\s*([A-Z0-9]{6,15})\b',
        "policy_id": "PII-GLOBAL-002",
        "category": "Government Issued Identity Card"
    },
    "UTILITY_BILL_ACC": {
        "pattern": r'(?i)\b(?:utility\s*bill|water\s*bill|electricity\s*bill|gas\s*bill)\s*(?:no|num|account)?\s*[:#-]?\s*([A-Z0-9]{6,16})\b',
        "policy_id": "PII-ADDR-001",
        "category": "Utility Billing & Address Proof Data"
    },

    # 4. Indian Identifiers
    "PAN_CARD": {
        "pattern": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
        "policy_id": "PII-IN-001",
        "category": "India Financial Identification"
    },
    "AADHAAR": {
        "pattern": r'\b[2-9]{1}\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',
        "policy_id": "PII-IN-002",
        "category": "India Identity Data Protection"
    },

    # 5. Financial Context & Credit Attributes
    "CREDIT_SCORE": {
        "pattern": r'(?i)\b(?:credit\s*score|cibil(?:\s*score)?|fico(?:\s*score)?)\s*[:#-]?\s*(\d{3})\b',
        "policy_id": "FIN-005",
        "category": "Credit Assessment Data"
    },
    "ANNUAL_INCOME": {
        "pattern": r'(?i)\b(?:annual\s*income|income|salary|net\s*pay)\s*[:#-]?\s*(\$?\d{1,3}(?:,\d{3})*|\d+)\b',
        "policy_id": "FIN-006",
        "category": "Compensation & Financial Position"
    },
    "TRANSACTION_AMOUNT": {
        "pattern": r'(?i)\b(?:amount|balance|sum|transfer|deposit|withdrawal|loan\s*amount)\s*[:#-]?\s*(\$\d{1,3}(?:,\d{3})*|\$\d+|\b\d{1,3}(?:,\d{3})+\b)\b',
        "policy_id": "FIN-007",
        "category": "Financial Transaction Data"
    },

    # 6. Geographical & Postal Identifiers
    "ZIP_POSTCODE": {
        "pattern": r'(?i)\b(?:ZIP\s*(?:code)?|postal\s*code|pin\s*code|pincode)\s*[:#-]?\s*([A-Z0-9]{3,10}(?:[-\s][A-Z0-9]{3,4})?)\b',
        "policy_id": "GEO-001",
        "category": "Location & Postal Identifiers"
    },

    # 7. Personal Identifiers (PII)
    "EMAIL": {
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "policy_id": "PII-COMM-001",
        "category": "Personal Communication Data"
    },
    "PHONE": {
        "pattern": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "policy_id": "PII-COMM-002",
        "category": "Personal Communication Data"
    },
    "PASSPORT": {
        "pattern": r'\b[A-PR-WYA-Z][0-9]{7,8}\b',
        "policy_id": "PII-GLOBAL-003",
        "category": "International Travel / Identity Data"
    },
    "PERSON_NAME": {
        "pattern": r'(?i)\b(?:applicant|customer|user|client|borrower|for|contact)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b',
        "policy_id": "PII-GEN-001",
        "category": "Direct Personal Names"
    },

    # 8. Credentials, API Keys & System Leaks
    "AWS_KEY": {
        "pattern": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
        "policy_id": "SEC-KEY-001",
        "category": "Cloud Credentials / Infrastructure Secrets"
    },
    "API_KEY": {
        "pattern": r'(?i)(api[_-]?key|secret|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
        "policy_id": "SEC-KEY-002",
        "category": "API Credentials & Secrets"
    },
    "JWT_TOKEN": {
        "pattern": r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
        "policy_id": "SEC-AUTH-001",
        "category": "Session & Authentication Tokens"
    },
    "IP_ADDRESS": {
        "pattern": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "policy_id": "SEC-NET-001",
        "category": "Network Infrastructure Data"
    },
}


def run_regex_redaction(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Handles structured PII, Foreign/Domestic IDs, Financial Attributes, and Secrets via Regex matching."""
    sanitized_text = text
    detected_violations = []

    for rule_key, rule_meta in POLICY_RULES.items():
        pattern = rule_meta["pattern"]
        matches = re.findall(pattern, sanitized_text)
        
        if matches:
            for match in set(matches):
                val_str = match[0] if isinstance(match, tuple) else match
                if val_str and len(val_str.strip()) > 1:
                    # Explicit policy violation object
                    detected_violations.append({
                        "type": rule_key,
                        "value": val_str,
                        "policy_id": rule_meta["policy_id"],
                        "policy_category": rule_meta["category"],
                        "engine": "Deterministic Engine",
                        "action_taken": "Redacted"
                    })
                    sanitized_text = sanitized_text.replace(val_str, f"[{rule_key}_REDACTED]")

    return sanitized_text, detected_violations


def run_lane1_deterministic_engine(text: str) -> Tuple[str, List[Dict[str, Any]], bool]:
    """
    Main Lane 1 Entrypoint: Runs sequential Regex & Pattern filtering.
    Returns: (sanitized_text, list_of_violations, is_flagged)
    """
    final_sanitized_text, violations = run_regex_redaction(text)
    is_flagged = len(violations) > 0

    return final_sanitized_text, violations, is_flagged
