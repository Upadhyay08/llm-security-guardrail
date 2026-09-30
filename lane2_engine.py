import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_lane2_semantic_engine(sanitized_text: str = "") -> tuple[bool, str, str, str]:
    """
    Lane 2 Engine: Semantic Safety and Policy Evaluator.
    Evaluates prompts for prompt injection, system overrides, and dynamic PII metric leakage.
    """
    if not sanitized_text or not sanitized_text.strip():
        return True, "Compliant Query", "No input prompt provided for semantic evaluation.", "ALLOWED"

    try:
        text_lower = sanitized_text.lower().strip()

        # 1. Prompt Injection / System Override Triggers
        override_triggers = [
            "system override", "ignore all", "ignore previous", "maintenance mode",
            "developer mode", "jailbreak", "security system logs", "admin configs",
            "system logs", "bypass safety", "root access", "show credentials"
        ]

        # 2. Dynamic Financial & Applicant PII Metric Triggers
        # Catches combinations of metrics even if exact names/IDs were missed in Lane 1
        applicant_metric_triggers = [
            "annual income", "credit score", "zip code", "mortgage application",
            "loan application", "applicant", "full ssn", "bank account", "social security"
        ]

        # Count detected semantic PII indicator terms
        metric_match_count = sum(1 for trigger in applicant_metric_triggers if trigger in text_lower)

        # Execution Rules Matrix
        if any(trigger in text_lower for trigger in override_triggers):
            return (
                False,
                "Prompt Injection / System Override",
                "Security Alert: System Override or Jailbreak attempt detected. Execution denied.",
                "BLOCKED"
            )

        # If 2 or more sensitive financial/applicant metrics are present in the prompt context
        if metric_match_count >= 2:
            return (
                False,
                "Financial Privacy Policy",
                "Dynamic PII Policy Violation: Prompt contains multiple identifiable applicant/financial metrics. Data extraction denied.",
                "BLOCKED"
            )

        if "[PERSON_REDACTED]" in sanitized_text or "[MONEY_REDACTED]" in sanitized_text or "[POLICY_REDACTED]" in sanitized_text:
            return (
                True,
                "Financial Privacy Policy",
                "Privacy Analysis: Sensitive entities dynamically scrubbed by Lane 1. Safe context allowed.",
                "ALLOWED"
            )

        return (
            True,
            "Compliant Query",
            "Security Diagnostic: Input query scanned. Intent is safe and compliant with enterprise policies.",
            "ALLOWED"
        )

    except Exception as e:
        logger.error(f"Lane 2 Engine Failure: {str(e)}")
        return False, "System Error", f"Semantic engine execution failed: {str(e)}", "FLAGGED"
