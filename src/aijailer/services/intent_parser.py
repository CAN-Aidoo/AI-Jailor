"""Intent Parser service.

Converts natural language or structured prompts into a typed,
security-aware CodeIntent representation using the Anthropic
Claude API for structured extraction.

Key Rule: If the intent parser cannot classify an intent into a
known-safe category, generation is BLOCKED — not degraded.
"""

import json
import structlog

from aijailer.schemas.intent import (
    ActionType,
    AuthRequirement,
    CodeIntent,
    ConcurrencyType,
    DataClass,
    ErrorClass,
    InputSource,
    OutputTarget,
)

logger = structlog.get_logger(__name__)

# System prompt that instructs Claude to extract structured intent
INTENT_EXTRACTION_PROMPT = """You are a security-aware code intent analyzer. Given a developer's
prompt describing code they want to generate, extract a structured intent representation.

You MUST respond with valid JSON matching this exact schema:
{
  "action": one of ["create", "read", "update", "delete", "auth", "payment", "file_io", "network", "crypto"],
  "data_classification": list of ["pii", "phi", "pci", "public", "internal"],
  "trust_boundary_crossing": boolean,
  "auth_context": one of ["none", "session", "token", "mtls", "mfa"],
  "compliance_domains": list of strings like ["HIPAA", "SOC2", "PCI-DSS"],
  "input_sources": list of ["user_input", "api", "database", "file"],
  "output_targets": list of ["browser", "api_response", "database", "log"],
  "concurrency_model": one of ["sync", "async", "parallel"],
  "error_sensitivity": one of ["fail_open", "fail_closed", "fail_safe"],
  "description": brief description of what the code should do,
  "target_framework": framework name or null
}

Rules:
- If the prompt involves user-submitted data, mark trust_boundary_crossing as true.
- If the prompt mentions health data, add "phi" to data_classification and "HIPAA" to compliance.
- If the prompt mentions payment/credit card, add "pci" and "PCI-DSS".
- If the prompt mentions personal data (email, name, address), add "pii".
- Default error_sensitivity to "fail_closed" for security-sensitive operations.
- If you cannot determine the action type, respond with {"error": "unclassifiable intent"}.
- ONLY output JSON, no explanation."""


class IntentParser:
    """Extracts structured CodeIntent from natural language prompts."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key
        self._client = None

    def _get_client(self):
        """Lazy-initialize the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise RuntimeError(
                    "anthropic package is required for intent parsing. "
                    "Install with: pip install anthropic"
                )
        return self._client

    async def parse_intent(self, prompt: str) -> CodeIntent | None:
        """Parse a natural language prompt into a structured CodeIntent.

        Returns None if the intent cannot be safely classified,
        which signals the constraint engine to BLOCK generation.
        """
        try:
            client = self._get_client()

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": f"{INTENT_EXTRACTION_PROMPT}\n\nDeveloper prompt: {prompt}",
                    }
                ],
            )

            # Extract the text response
            raw_text = message.content[0].text.strip()

            # Parse JSON response
            intent_data = json.loads(raw_text)

            # Check for unclassifiable intent
            if "error" in intent_data:
                logger.warning(
                    "intent.unclassifiable",
                    prompt=prompt[:100],
                    error=intent_data["error"],
                )
                return None

            # Validate and construct CodeIntent
            code_intent = CodeIntent(
                action=ActionType(intent_data["action"]),
                data_classification=[
                    DataClass(d) for d in intent_data.get("data_classification", [])
                ],
                trust_boundary_crossing=intent_data.get("trust_boundary_crossing", False),
                auth_context=AuthRequirement(
                    intent_data.get("auth_context", "none")
                ),
                compliance_domains=intent_data.get("compliance_domains", []),
                input_sources=[
                    InputSource(s) for s in intent_data.get("input_sources", [])
                ],
                output_targets=[
                    OutputTarget(t) for t in intent_data.get("output_targets", [])
                ],
                concurrency_model=ConcurrencyType(
                    intent_data.get("concurrency_model", "sync")
                ),
                error_sensitivity=ErrorClass(
                    intent_data.get("error_sensitivity", "fail_closed")
                ),
                description=intent_data.get("description"),
                target_framework=intent_data.get("target_framework"),
                target_language=prompt_language_hint(prompt),
            )

            logger.info(
                "intent.parsed",
                action=code_intent.action.value,
                data_classes=[d.value for d in code_intent.data_classification],
                compliance=code_intent.compliance_domains,
            )
            return code_intent

        except json.JSONDecodeError as e:
            logger.error("intent.json_parse_error", error=str(e), prompt=prompt[:100])
            return None
        except (ValueError, KeyError) as e:
            logger.error("intent.validation_error", error=str(e), prompt=prompt[:100])
            return None
        except Exception as e:
            logger.error("intent.unexpected_error", error=str(e), prompt=prompt[:100])
            return None


def prompt_language_hint(prompt: str) -> str:
    """Extract language hint from prompt text."""
    prompt_lower = prompt.lower()
    for lang in ["typescript", "javascript", "java", "go", "python", "rust", "ruby"]:
        if lang in prompt_lower:
            return lang
    return "python"


# Singleton
_intent_parser: IntentParser | None = None


def get_intent_parser(api_key: str | None = None) -> IntentParser:
    global _intent_parser
    if _intent_parser is None:
        _intent_parser = IntentParser(api_key=api_key)
    return _intent_parser
