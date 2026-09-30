import re
import logging

# Configure structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# DYNAMIC SPACY MODEL LOADING WITH AUTOMATED STARTUP DOWNLOAD
# ----------------------------------------------------------------------
try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        logger.info("Downloading 'en_core_web_sm' model on startup...")
        from spacy.cli import download
        download("en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")
except ImportError:
    logger.warning("spaCy module not installed. Running in fallback regex mode.")
    nlp = None


def run_lane1_deterministic_engine(text: str = "") -> tuple[str, bool, dict]:
    """
    Lane 1: Deterministic & Named Entity Recognition (NER) Redaction Engine.

    Combines spaCy NER for contextual entities (PERSON, MONEY, GPE, DATE, ORG)
    with baseline regex patterns for structured identifiers (SSN, PAN, Aadhaar).

    Parameters:
        text (str): Raw input prompt string to evaluate and sanitize.

    Returns:
        tuple[str, bool, dict]:
            - redacted_text (str): The sanitized prompt with sensitive entities replaced.
            - has_pii (bool): True if PII or sensitive patterns were detected and scrubbed.
            - metadata (dict): Diagnostics containing lists of detected entity types.
    """
    if not text or not text.strip():
        logger.info("Lane 1 Engine: Empty query string received.")
        return text, False, {"detected_entities": [], "redaction_count": 0}

    try:
        redacted_text = text
        entities_detected = []

        # ----------------------------------------------------------------------
        # 1. DYNAMIC NAMED ENTITY RECOGNITION (NER REDACTION)
        # ----------------------------------------------------------------------
        if nlp is not None:
            doc = nlp(text)
            target_labels = {"PERSON", "MONEY", "GPE", "DATE", "ORG"}

            # Process entities in reverse character offset order to maintain correct string slicing
            for ent in sorted(doc.ents, key=lambda x: x.start_char, reverse=True):
                if ent.label_ in target_labels:
                    entities_detected.append((ent.text, ent.label_))
                    start, end = ent.start_char, ent.end_char
                    redacted_text = (
                        redacted_text[:start]
                        + f"[{ent.label_}_REDACTED]"
                        + redacted_text[end:]
                    )

        # ----------------------------------------------------------------------
        # 2. BASELINE PATTERN REGEX FALLBACK (STRUCTURED IDENTIFIERS)
        # ----------------------------------------------------------------------
        baseline_patterns = {
            "SSN_REDACTED": r"\b\d{3}-\d{2}-\d{4}\b",
            "PAN_REDACTED": r"\b[A-Z]{5}\d{4}[A-Z]{1}\b",
            "AADHAAR_REDACTED": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
            "ZIP_CODE_REDACTED": r"\b\d{5}(?:-\d{4})?\b",
            "MORTGAGE_ID_REDACTED": r"\b#?MA-\d{4,6}\b",
            "INCOME_REDACTED": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b"
        }

        for label, pattern in baseline_patterns.items():
            if re.search(pattern, redacted_text, re.IGNORECASE):
                matches = re.findall(pattern, redacted_text, re.IGNORECASE)
                for match in matches:
                    # Avoid duplicate logging if already scrubbed by NER
                    if match not in [e[0] for e in entities_detected]:
                        entities_detected.append((match, label))
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
        logger.error(f"Lane 1 Processing Failure: {str(e)}")
        return text, False, {"error": str(e), "detected_entities": [], "redaction_count": 0}


if __name__ == "__main__":
    # Sample verification prompt
    sample_prompt = (
        "I'm reviewing mortgage application #MA-58210 for applicant Jordan Reyes: "
        "annual income $72,000, credit score 640, ZIP code 48212, and 3 years at current employer."
    )
    sanitized, pii_found, meta = run_lane1_deterministic_engine(sample_prompt)
    
    print("Sanitized Output:\n", sanitized)
    print("\nPII Detected:", pii_found)
    print("Metadata:", meta)
