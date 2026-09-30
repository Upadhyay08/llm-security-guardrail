import re
import spacy
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load lightweight spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

def run_lane1_deterministic_engine(text: str) -> tuple[str, bool, dict]:
    """
    Lane 1 Engine: Combines baseline regex scrubbing with dynamic spaCy NER.
    Redacts PERSON, MONEY, GPE (Location), DATE, and ORG entities dynamically.
    """
    if not text or not text.strip():
        return text, False, {}

    redacted_text = text
    entities_detected = []

    # 1. Dynamic NER Redaction
    doc = nlp(text)
    target_labels = {"PERSON", "MONEY", "GPE", "DATE", "ORG"}

    # Process entities in reverse order to preserve string character offsets
    for ent in sorted(doc.ents, key=lambda x: x.start_char, reverse=True):
        if ent.label_ in target_labels:
            entities_detected.append((ent.text, ent.label_))
            start, end = ent.start_char, ent.end_char
            redacted_text = redacted_text[:start] + f"[{ent.label_}_REDACTED]" + redacted_text[end:]

    # 2. Baseline Fallback Regex (Standard Identifiers: SSN, PAN, Aadhaar)
    baseline_patterns = {
        "SSN_REDACTED": r"\b\d{3}-\d{2}-\d{4}\b",
        "PAN_REDACTED": r"\b[A-Z]{5}\d{4}[A-Z]{1}\b",
        "AADHAAR_REDACTED": r"\b\d{4}\s\d{4}\s\d{4}\b"
    }

    for label, pattern in baseline_patterns.items():
        if re.search(pattern, redacted_text, re.IGNORECASE):
            redacted_text = re.sub(pattern, f"[{label}]", redacted_text, flags=re.IGNORECASE)
            entities_detected.append(("Pattern Match", label))

    has_pii = len(entities_detected) > 0
    metadata = {"detected_entities": entities_detected}

    return redacted_text, has_pii, metadata
