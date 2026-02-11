"""Certified Component Registry.

Manages the catalog of certified components, providing
lookup by intent, category, and compliance requirements.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from aijailer.schemas.intent import ActionType, CodeIntent, DataClass

logger = structlog.get_logger(__name__)


class ComponentCategory(str, Enum):
    """Categories of certified components."""

    AUTH = "auth"
    DATA_ACCESS = "data_access"
    CRYPTO = "crypto"
    NETWORK = "network"
    PRIMITIVES = "primitives"
    COMPLIANCE = "compliance"


@dataclass(frozen=True)
class ComponentInfo:
    """Metadata about a certified component."""

    name: str
    version: str
    category: ComponentCategory
    module_path: str              # Python import path
    description: str
    prevents_cwes: list[str]      # CWE IDs this component prevents
    compliance_certs: list[str]   # Compliance frameworks satisfied
    language: str = "python"
    status: str = "active"

    @property
    def qualified_name(self) -> str:
        return f"{self.name}@{self.version}"


# Pre-registered certified components
_CERTIFIED_COMPONENTS: list[ComponentInfo] = [
    ComponentInfo(
        name="session_manager",
        version="1.0.0",
        category=ComponentCategory.AUTH,
        module_path="aijailer.certified_components.auth.session_manager",
        description="Secure session handling with HttpOnly cookies and CSRF tokens",
        prevents_cwes=["CWE-384", "CWE-614", "CWE-1004", "CWE-613"],
        compliance_certs=["SOC2", "HIPAA"],
    ),
    ComponentInfo(
        name="jwt_handler",
        version="1.0.0",
        category=ComponentCategory.AUTH,
        module_path="aijailer.certified_components.auth.jwt_handler",
        description="JWT creation/validation with approved algorithms only",
        prevents_cwes=["CWE-347", "CWE-613", "CWE-327"],
        compliance_certs=["SOC2"],
    ),
    ComponentInfo(
        name="safe_query_builder",
        version="1.0.0",
        category=ComponentCategory.DATA_ACCESS,
        module_path="aijailer.certified_components.data_access.safe_query_builder",
        description="Parameterized SQL queries — injection impossible by design",
        prevents_cwes=["CWE-89", "CWE-564", "CWE-943"],
        compliance_certs=["SOC2", "PCI-DSS", "HIPAA"],
    ),
    ComponentInfo(
        name="input_validator",
        version="1.0.0",
        category=ComponentCategory.DATA_ACCESS,
        module_path="aijailer.certified_components.data_access.input_validator",
        description="Type-safe input validation with sanitization",
        prevents_cwes=["CWE-20", "CWE-1284", "CWE-1285"],
        compliance_certs=["SOC2", "PCI-DSS"],
    ),
    ComponentInfo(
        name="output_encoder",
        version="1.0.0",
        category=ComponentCategory.DATA_ACCESS,
        module_path="aijailer.certified_components.data_access.output_encoder",
        description="Context-aware output encoding for XSS prevention",
        prevents_cwes=["CWE-79", "CWE-838", "CWE-116"],
        compliance_certs=["SOC2", "PCI-DSS"],
    ),
    ComponentInfo(
        name="encryption",
        version="1.0.0",
        category=ComponentCategory.CRYPTO,
        module_path="aijailer.certified_components.crypto.encryption",
        description="AES-256-GCM encryption with vault-backed keys",
        prevents_cwes=["CWE-327", "CWE-328", "CWE-326"],
        compliance_certs=["SOC2", "PCI-DSS", "HIPAA"],
    ),
    ComponentInfo(
        name="hashing",
        version="1.0.0",
        category=ComponentCategory.CRYPTO,
        module_path="aijailer.certified_components.crypto.hashing",
        description="Argon2id password hashing with safe defaults",
        prevents_cwes=["CWE-916", "CWE-328", "CWE-261"],
        compliance_certs=["SOC2", "PCI-DSS"],
    ),
    ComponentInfo(
        name="http_client",
        version="1.0.0",
        category=ComponentCategory.NETWORK,
        module_path="aijailer.certified_components.network.http_client",
        description="SSRF-preventing, TLS-enforced HTTP client",
        prevents_cwes=["CWE-918", "CWE-295", "CWE-319"],
        compliance_certs=["SOC2"],
    ),
    ComponentInfo(
        name="safe_file_io",
        version="1.0.0",
        category=ComponentCategory.PRIMITIVES,
        module_path="aijailer.certified_components.primitives.safe_file_io",
        description="Path traversal prevention with directory allowlisting",
        prevents_cwes=["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
        compliance_certs=["SOC2"],
    ),
    ComponentInfo(
        name="safe_subprocess",
        version="1.0.0",
        category=ComponentCategory.PRIMITIVES,
        module_path="aijailer.certified_components.primitives.safe_subprocess",
        description="Command injection prevention with command allowlisting",
        prevents_cwes=["CWE-78", "CWE-77", "CWE-88"],
        compliance_certs=["SOC2"],
    ),
]


class ComponentRegistry:
    """Registry for discovering and selecting certified components.

    Components are matched to intents based on:
    - Action type (auth actions → auth components)
    - Data classification (PII/PHI → compliance-certified components)
    - Compliance requirements (HIPAA → HIPAA-certified components)
    """

    def __init__(self) -> None:
        self._components: dict[str, ComponentInfo] = {
            c.name: c for c in _CERTIFIED_COMPONENTS
        }

    def get_all(self) -> list[ComponentInfo]:
        """Get all registered certified components."""
        return [c for c in self._components.values() if c.status == "active"]

    def get_by_name(self, name: str) -> ComponentInfo | None:
        """Get a component by name."""
        return self._components.get(name)

    def get_by_category(self, category: ComponentCategory) -> list[ComponentInfo]:
        """Get all components in a category."""
        return [
            c for c in self._components.values()
            if c.category == category and c.status == "active"
        ]

    def get_for_intent(self, intent: CodeIntent) -> list[ComponentInfo]:
        """Select components needed to satisfy an intent's security requirements.

        Maps intent properties to required component categories:
        - Database actions → safe_query_builder + input_validator
        - User input → input_validator + output_encoder
        - Auth requirements → session_manager or jwt_handler
        - Crypto operations → encryption + hashing
        - File operations → safe_file_io
        - Network operations → http_client
        - Compliance → matching compliance-certified components
        """
        selected: dict[str, ComponentInfo] = {}

        # Always include input_validator for user input
        from aijailer.schemas.intent import InputSource
        if InputSource.USER_INPUT in intent.input_sources:
            self._add(selected, "input_validator")
            self._add(selected, "output_encoder")

        # Database operations
        if intent.action in (ActionType.CREATE, ActionType.READ, ActionType.UPDATE, ActionType.DELETE):
            self._add(selected, "safe_query_builder")
            self._add(selected, "input_validator")

        # Auth requirements
        if intent.auth_context.value != "none" or intent.trust_boundary_crossing:
            if intent.auth_context.value == "token":
                self._add(selected, "jwt_handler")
            else:
                self._add(selected, "session_manager")

        # Crypto operations
        if intent.action == ActionType.CRYPTO:
            self._add(selected, "encryption")
            self._add(selected, "hashing")

        # Password-related actions
        if intent.action == ActionType.AUTH:
            self._add(selected, "hashing")
            self._add(selected, "session_manager")

        # File I/O
        if intent.action == ActionType.FILE_IO:
            self._add(selected, "safe_file_io")

        # Network
        if intent.action == ActionType.NETWORK:
            self._add(selected, "http_client")

        # Browser output
        from aijailer.schemas.intent import OutputTarget
        if OutputTarget.BROWSER in intent.output_targets:
            self._add(selected, "output_encoder")

        # Compliance-based additions
        for domain in intent.compliance_domains:
            for comp in self._components.values():
                if domain in comp.compliance_certs:
                    selected[comp.name] = comp

        logger.info(
            "registry.components_selected",
            intent_action=intent.action.value,
            selected=[c.name for c in selected.values()],
            count=len(selected),
        )

        return list(selected.values())

    def search(
        self,
        query: str | None = None,
        category: str | None = None,
        cwe: str | None = None,
        compliance: str | None = None,
    ) -> list[ComponentInfo]:
        """Search components by various criteria."""
        results = list(self._components.values())

        if query:
            q = query.lower()
            results = [
                c for c in results
                if q in c.name.lower() or q in c.description.lower()
            ]

        if category:
            results = [c for c in results if c.category.value == category]

        if cwe:
            results = [c for c in results if cwe in c.prevents_cwes]

        if compliance:
            results = [c for c in results if compliance in c.compliance_certs]

        return results

    def _add(self, selected: dict[str, ComponentInfo], name: str) -> None:
        """Add a component to the selection if it exists."""
        comp = self._components.get(name)
        if comp and comp.status == "active":
            selected[name] = comp


# Singleton
_registry: ComponentRegistry | None = None


def get_component_registry() -> ComponentRegistry:
    global _registry
    if _registry is None:
        _registry = ComponentRegistry()
    return _registry
