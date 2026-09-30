import re

def run_lane1_deterministic_engine(text: str) -> tuple[bool, str, str, str]:
    """
    Lane 1: Deterministic Engine for PII and Financial Patterns (Regex-based).
    Detects credit cards, SSNs, and explicit raw sensitive formats.
    """
    if not text:
        return True, "CLEAN", "No text provided.", "ALLOWED"
        
    # Standard Regex patterns for sensitive data
    cc_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    
    if re.search(cc_pattern, text) or re.search(ssn_pattern, text):
        return False, "DETERMINISTIC_PII_VIOLATION", "Matched sensitive PII/Financial pattern.", "BLOCKED"
        
    return True, "CLEAN", "No deterministic violations found.", "ALLOWED"
