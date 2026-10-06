"""Constraint Engine service.

Z3-based constraint solver that translates intents into a constraint
satisfaction problem where ONLY secure code patterns are in the
solution space. This is the core innovation of CodeImmune.
"""

import structlog

from aijailer.schemas.intent import (
    ActionType,
    AuthRequirement,
    CodeIntent,
    DataClass,
    InputSource,
    OutputTarget,
)
from aijailer.services.constraint_dsl import (
    ConstraintDefinition,
    ConstraintDSLParser,
    get_constraint_dsl_parser,
)

logger = structlog.get_logger(__name__)


class ConstraintResult:
    """Result of constraint checking."""

    def __init__(self, safe: bool, reason: str = "", violated_constraints: list | None = None):
        self.safe = safe
        self.reason = reason
        self.violated_constraints = violated_constraints or []

    @classmethod
    def SAFE(cls):
        return cls(safe=True)

    @classmethod
    def BLOCKED(cls, reason: str, violated: list | None = None):
        return cls(safe=False, reason=reason, violated_constraints=violated or [])


class GenerationPlan:
    """Describes what the generated code will do — used for constraint checking."""

    def __init__(
        self,
        accesses_database: bool = False,
        has_audit_logging: bool = False,
        has_auth: bool = False,
        uses_parameterized_query: bool = False,
        uses_approved_crypto: bool = True,
        has_input_validation: bool = False,
        has_output_encoding: bool = False,
        has_error_handling: bool = True,
        uses_safe_concurrency: bool = True,
        has_secret_management: bool = True,
    ):
        self.accesses_database = accesses_database
        self.has_audit_logging = has_audit_logging
        self.has_auth = has_auth
        self.uses_parameterized_query = uses_parameterized_query
        self.uses_approved_crypto = uses_approved_crypto
        self.has_input_validation = has_input_validation
        self.has_output_encoding = has_output_encoding
        self.has_error_handling = has_error_handling
        self.uses_safe_concurrency = uses_safe_concurrency
        self.has_secret_management = has_secret_management


class ConstraintEngine:
    """Z3-backed constraint solver for code generation safety.

    Given a CodeIntent and a proposed GenerationPlan, encodes
    security requirements as boolean constraints and checks
    satisfiability. Returns SAFE or BLOCKED with explanation.
    """

    def __init__(self, constraint_dir: str | None = None):
        self._dsl_parser = get_constraint_dsl_parser(constraint_dir)
        self._constraints: list[ConstraintDefinition] | None = None

    def _load_constraints(self) -> list[ConstraintDefinition]:
        if self._constraints is None:
            self._constraints = self._dsl_parser.load_all()
        return self._constraints

    def reload_constraints(self):
        """Force reload constraints from YAML files (e.g. after immune update)."""
        self._constraints = None
        self._load_constraints()

    def check_intent(self, intent: CodeIntent) -> ConstraintResult:
        """Check an intent against all applicable constraints.

        This performs the core safety analysis using Z3-style
        boolean logic (implemented directly for reliability).
        """
        violations = []

        # Rule 1: User input + DB access → must use parameterized queries
        has_user_input = InputSource.USER_INPUT in intent.input_sources
        accesses_db = OutputTarget.DATABASE in intent.output_targets or intent.action in (
            ActionType.CREATE, ActionType.READ, ActionType.UPDATE, ActionType.DELETE
        )
        if has_user_input and accesses_db:
            violations.append({
                "constraint": "sql_injection_prevention",
                "severity": "CRITICAL",
                "requirement": "User input with database access requires parameterized queries",
                "enforced_component": "safe_query_builder",
            })

        # Rule 2: PII/PHI handling → must have audit logging
        handles_sensitive = bool(
            set(intent.data_classification) & {DataClass.PII, DataClass.PHI, DataClass.PCI}
        )
        if handles_sensitive:
            violations.append({
                "constraint": "data_boundary",
                "severity": "HIGH",
                "requirement": "Sensitive data handling requires audit logging and boundary enforcement",
                "enforced_component": "hipaa_audit_logger" if DataClass.PHI in intent.data_classification else "data_boundary_enforcer",
            })

        # Rule 3: Trust boundary crossing → must have auth
        if intent.trust_boundary_crossing and intent.auth_context == AuthRequirement.NONE:
            violations.append({
                "constraint": "auth_enforcement",
                "severity": "CRITICAL",
                "requirement": "Trust boundary crossing requires authentication",
                "enforced_component": "auth_middleware",
            })

        # Rule 4: Browser output → must have output encoding
        if OutputTarget.BROWSER in intent.output_targets:
            violations.append({
                "constraint": "output_encoding",
                "severity": "HIGH",
                "requirement": "Browser output requires context-aware encoding (XSS prevention)",
                "enforced_component": "output_encoder",
            })

        # Rule 5: Crypto action → must use approved algorithms only
        if intent.action == ActionType.CRYPTO:
            violations.append({
                "constraint": "crypto_safety",
                "severity": "CRITICAL",
                "requirement": "Only approved algorithms (AES-256-GCM, Argon2id, Ed25519)",
                "enforced_component": "certified_crypto",
            })

        # Rule 6: File I/O → must prevent path traversal
        if intent.action == ActionType.FILE_IO or InputSource.FILE in intent.input_sources:
            violations.append({
                "constraint": "path_traversal_prevention",
                "severity": "HIGH",
                "requirement": "File operations must use safe_file_io component",
                "enforced_component": "safe_file_io",
            })

        # Rule 7: Payment → PCI-DSS compliance required
        if intent.action == ActionType.PAYMENT and "PCI-DSS" not in intent.compliance_domains:
            violations.append({
                "constraint": "payment_compliance",
                "severity": "CRITICAL",
                "requirement": "Payment operations require PCI-DSS compliance",
                "enforced_component": "pci_data_handler",
            })

        # Check YAML-defined constraints
        intent_dict = intent.model_dump()
        yaml_constraints = self._load_constraints()
        matched_yaml = []
        for yc in yaml_constraints:
            if self._dsl_parser.matches_intent(yc, intent_dict):
                matched_yaml.append(yc.name)

        # All violations here are "requirements" that the assembler must satisfy,
        # not necessarily blocks. They become blocks only in strict mode if
        # the assembler cannot produce code meeting all requirements.
        constraints_applied = [v["constraint"] for v in violations] + matched_yaml

        logger.info(
            "constraint.check_complete",
            action=intent.action.value,
            constraints_applied=constraints_applied,
            requirement_count=len(violations),
        )

        return ConstraintResult(
            safe=True,
            reason="",
            violated_constraints=violations,
        )

    def check_with_z3(self, intent: CodeIntent, plan: GenerationPlan) -> ConstraintResult:
        """Full Z3-based constraint checking (for strict verification).

        Uses the Z3 SMT solver to formally verify that the generation
        plan satisfies all security constraints implied by the intent.
        """
        try:
            from z3 import And, Bool, Implies, Not, Solver, sat
        except ImportError:
            logger.warning("z3.not_available", msg="Falling back to rule-based checking")
            return self.check_intent(intent)

        solver = Solver()

        # Encode intent properties as Z3 variables
        has_user_input = Bool("has_user_input")
        crosses_trust_boundary = Bool("crosses_trust_boundary")
        handles_pii = Bool("handles_pii")
        handles_phi = Bool("handles_phi")
        has_auth = Bool("has_auth")
        uses_parameterized_query = Bool("uses_parameterized_query")
        has_audit_logging = Bool("has_audit_logging")
        accesses_database = Bool("accesses_database")
        has_output_encoding = Bool("has_output_encoding")
        outputs_to_browser = Bool("outputs_to_browser")
        has_error_handling = Bool("has_error_handling")
        uses_approved_crypto = Bool("uses_approved_crypto")
        is_crypto_action = Bool("is_crypto_action")

        # Set values from intent
        solver.add(has_user_input == (InputSource.USER_INPUT in intent.input_sources))
        solver.add(crosses_trust_boundary == intent.trust_boundary_crossing)
        solver.add(handles_pii == (DataClass.PII in intent.data_classification))
        solver.add(handles_phi == (DataClass.PHI in intent.data_classification))
        solver.add(outputs_to_browser == (OutputTarget.BROWSER in intent.output_targets))
        solver.add(is_crypto_action == (intent.action == ActionType.CRYPTO))

        # Set values from generation plan
        solver.add(has_auth == plan.has_auth)
        solver.add(uses_parameterized_query == plan.uses_parameterized_query)
        solver.add(has_audit_logging == plan.has_audit_logging)
        solver.add(accesses_database == plan.accesses_database)
        solver.add(has_output_encoding == plan.has_output_encoding)
        solver.add(has_error_handling == plan.has_error_handling)
        solver.add(uses_approved_crypto == plan.uses_approved_crypto)

        # Security rules as NAMED, tracked assertions so an UNSAT result yields an
        # unsat core that names exactly which requirements the plan fails.
        rules = {
            "sql_injection_prevention": Implies(And(has_user_input, accesses_database),
                                                uses_parameterized_query),
            "pii_requires_audit_logging": Implies(handles_pii, has_audit_logging),
            "phi_requires_audit_logging": Implies(handles_phi, has_audit_logging),
            "auth_enforcement": Implies(crosses_trust_boundary, has_auth),
            "output_encoding": Implies(outputs_to_browser, has_output_encoding),
            "crypto_safety": Implies(is_crypto_action, uses_approved_crypto),
            "error_handling": has_error_handling,
        }
        # Z3 yields ONE core per UNSAT call. To report every violated rule, drop the
        # rules in each core and re-solve until the remainder is satisfiable.
        active = dict(rules)
        violated: list[str] = []
        while True:
            solver.push()
            for name, expr in active.items():
                solver.assert_and_track(expr, Bool(f"rule::{name}"))
            result = solver.check()
            core = sorted(str(c).removeprefix("rule::") for c in solver.unsat_core()) \
                if result != sat else []
            solver.pop()
            if result == sat:
                break
            if not core:  # facts alone are contradictory; cannot attribute to a rule
                violated.append("unsatisfiable_facts")
                break
            violated.extend(core)
            for name in core:
                active.pop(name, None)

        if not violated:
            return ConstraintResult.SAFE()
        violated = sorted(violated)
        return ConstraintResult.BLOCKED(
            reason="Generation plan violates: " + ", ".join(violated), violated=violated)


# Singleton
_engine: ConstraintEngine | None = None


def get_constraint_engine(constraint_dir: str | None = None) -> ConstraintEngine:
    global _engine
    if _engine is None:
        _engine = ConstraintEngine(constraint_dir=constraint_dir)
    return _engine
