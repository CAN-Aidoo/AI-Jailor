# The Immune System for Software — Complete Build Specification

## 1. System Overview

**Codename:** CodeImmune
**One-liner:** A constrained code generation engine where vulnerable code is architecturally impossible to produce.

The system intercepts AI code generation at the intent layer, enforces security through generative constraints (not post-hoc scanning), and assembles output from pre-certified composable patterns. Every attack attempt feeds a global immune memory that strengthens all deployments.

---

## 2. Architecture — Three-Layer Model

```
┌─────────────────────────────────────────────────────┐
│  LAYER 3: Immune Memory (Global Threat Intelligence) │
│  - Attack pattern DB    - Adaptive constraint updates │
│  - Cross-tenant learning - Zero-day response engine   │
├─────────────────────────────────────────────────────┤
│  LAYER 2: Constraint Engine (Generation-Time Safety)  │
│  - AST constraint solver - Pattern allowlists         │
│  - Intent→SecurePattern mapper - Taint propagation    │
├─────────────────────────────────────────────────────┤
│  LAYER 1: Certified Component Library (Pre-Verified)  │
│  - Auth modules  - Data access patterns  - API stubs  │
│  - Crypto wrappers - Input validators - Output encoders│
└─────────────────────────────────────────────────────┘
```

### Data Flow (per request)

```
Developer Prompt
      │
      ▼
┌─────────────┐
│ Intent Parser│──→ Extracts: action, data types, auth context,
└──────┬──────┘    compliance domain, trust boundaries
       │
       ▼
┌──────────────────┐
│ Constraint Solver │──→ Maps intent to ALLOWED generation patterns
│ (SAT/SMT-based)  │    Rejects intents that have no safe realization
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Secure Assembler  │──→ Composes code from certified components +
│                   │    constrained generated glue code
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Formal Verifier   │──→ Lightweight proof that output satisfies
│ (sub-100ms)      │    security properties (belt + suspenders)
└──────┬───────────┘
       │
       ▼
  Secure Code Output + Security Certificate (JSON attestation)
```

---

## 3. Core Components — Detailed Specifications

### 3.1 Intent Parser

**Purpose:** Convert natural language or structured prompts into a typed security-aware intent representation.

**Tech:** PydanticAI + custom intent schema + LLM extraction (Claude/GPT as backbone)

```python
# Intent Schema
class CodeIntent(BaseModel):
    action: ActionType           # CRUD, auth, payment, file_io, network, crypto
    data_classification: list[DataClass]  # PII, PHI, PCI, public, internal
    trust_boundary_crossing: bool         # Does this cross a trust boundary?
    auth_context: AuthRequirement         # none, session, token, mTLS, MFA
    compliance_domains: list[str]         # ["HIPAA", "SOC2", "PCI-DSS"]
    input_sources: list[InputSource]      # user_input, api, database, file
    output_targets: list[OutputTarget]    # browser, api_response, database, log
    concurrency_model: ConcurrencyType    # sync, async, parallel
    error_sensitivity: ErrorClass         # fail_open, fail_closed, fail_safe
```

**Key Rule:** If the intent parser cannot classify an intent into a known-safe category, generation is BLOCKED — not degraded.

### 3.2 Constraint Engine (The Core Innovation)

**Purpose:** Translate intents into a constraint satisfaction problem where ONLY secure code patterns are in the solution space.

**Tech:** Z3 SMT Solver (Python bindings) + custom constraint DSL

#### Constraint Categories

| Category | Example Constraint | Enforcement |
|---|---|---|
| **Injection Prevention** | All user inputs must pass through typed validators before any string interpolation | AST rule: no raw string concat with tainted vars |
| **Auth Enforcement** | Every route handler must have auth middleware in call chain | Call-graph analysis at generation time |
| **Crypto Safety** | Only approved algorithms (AES-256-GCM, Argon2id, Ed25519) | Allowlist — unapproved crypto functions don't exist in generation vocabulary |
| **Data Boundary** | PHI/PII cannot appear in log statements or error messages | Taint tracking on data classification labels |
| **Output Encoding** | All outputs to browser must pass context-aware encoder | AST rule: output functions require encoder wrapper |
| **Error Handling** | Sensitive operations must have explicit error handling with safe defaults | Pattern: try/except blocks are mandatory for tagged operations |
| **Race Conditions** | Shared mutable state must use provided concurrency primitives | Only certified concurrent patterns available |
| **Secret Management** | No string literals matching secret patterns; must use vault references | Lexical + pattern constraint |

#### Constraint DSL Example

```yaml
# constraints/injection_prevention.yaml
constraint:
  name: sql_injection_prevention
  severity: CRITICAL
  applies_when:
    intent.action: [READ, WRITE, DELETE]
    intent.input_sources: [user_input]
    target: database
  rules:
    - type: FORBID_PATTERN
      pattern: "string_concat(tainted_var, sql_fragment)"
      message: "Direct string concatenation with user input in SQL context"
    - type: REQUIRE_PATTERN
      pattern: "parameterized_query(sql_template, typed_params)"
      message: "Must use parameterized queries"
    - type: REQUIRE_WRAPPER
      wrapper: "input_validator({data_type})"
      on: "all tainted inputs before database operations"
```

### 3.3 Certified Component Library (CCL)

**Purpose:** Pre-verified, formally proven building blocks that handle security-critical operations.

**Structure:**

```
certified_components/
├── auth/
│   ├── session_manager.py        # Certified session handling
│   ├── jwt_handler.py            # JWT with safe defaults
│   ├── oauth2_flow.py            # Complete OAuth2 implementation
│   ├── rbac_enforcer.py          # Role-based access control
│   └── mfa_handler.py            # Multi-factor auth
├── data_access/
│   ├── safe_query_builder.py     # Parameterized queries only
│   ├── orm_wrapper.py            # ORM with injection protection
│   ├── input_validator.py        # Type-safe input validation
│   └── output_encoder.py         # Context-aware output encoding
├── crypto/
│   ├── encryption.py             # AES-256-GCM only
│   ├── hashing.py                # Argon2id for passwords
│   ├── signing.py                # Ed25519 signatures
│   └── key_management.py         # Vault-backed key ops
├── network/
│   ├── http_client.py            # TLS-enforced, timeout-safe
│   ├── rate_limiter.py           # Token bucket implementation
│   ├── cors_handler.py           # Strict CORS defaults
│   └── csp_builder.py            # Content Security Policy
├── compliance/
│   ├── hipaa_audit_logger.py     # HIPAA-compliant audit trail
│   ├── pci_data_handler.py       # PCI-DSS data handling
│   ├── gdpr_consent_manager.py   # GDPR consent tracking
│   └── sox_change_tracker.py     # SOX compliance logging
└── primitives/
    ├── safe_file_io.py           # Path traversal prevention
    ├── safe_subprocess.py        # Command injection prevention
    ├── safe_serialization.py     # Deserialization attack prevention
    └── safe_concurrency.py       # Deadlock-free concurrency
```

**Each component ships with:**
- Formal specification (TLA+ or Dafny)
- Property-based test suite (Hypothesis)
- Fuzz test results (minimum 1M iterations)
- CVE coverage map (which known vulnerabilities it prevents)
- Compliance certificate (which frameworks it satisfies)

### 3.4 Secure Assembler

**Purpose:** Compose certified components + constrained glue code into complete, working programs.

**Process:**
1. Receive constrained intent + selected components from Constraint Engine
2. Generate ONLY glue code (business logic wiring between certified components)
3. Glue code is constrained: no direct I/O, no crypto, no auth — only data transformation and control flow
4. Output is a complete module with certified components as dependencies

```python
# Example: Secure Assembler output for "create user signup endpoint"
# GLUE CODE (generated, constrained)
from certified_components.auth import session_manager, mfa_handler
from certified_components.data_access import safe_query_builder, input_validator
from certified_components.crypto import hashing
from certified_components.compliance import hipaa_audit_logger

async def signup_user(request: ValidatedRequest) -> SecureResponse:
    # All inputs already validated by middleware (certified component)
    user_data = input_validator.validate(request.body, schema=UserSignupSchema)

    # Password hashing uses ONLY certified implementation
    password_hash = await hashing.hash_password(user_data.password)

    # Database access through safe query builder ONLY
    user_id = await safe_query_builder.insert(
        table="users",
        data={"email": user_data.email, "password_hash": password_hash}
    )

    # Audit logging for compliance
    await hipaa_audit_logger.log_event(
        action="USER_CREATED", entity_id=user_id, actor="system"
    )

    # Session creation through certified session manager
    session = await session_manager.create(user_id=user_id)

    return SecureResponse(status=201, data={"session_token": session.token})
```

### 3.5 Immune Memory System

**Purpose:** Global learning from attack attempts, vulnerability reports, and emerging threats.

**Architecture:**

```
┌──────────────────────────────────────────────┐
│            Immune Memory Database             │
│  (ClickHouse for analytics, Redis for RT)    │
├──────────────────────────────────────────────┤
│ attack_patterns     │ Observed attack vectors │
│ constraint_updates  │ New rules from attacks  │
│ component_patches   │ Updated certified comps │
│ threat_intel_feeds  │ CVE, NVD, MITRE ATT&CK │
│ generation_telemetry│ What was blocked & why  │
└──────────────────────────────────────────────┘
```

**Immune Response Cycle:**
1. **Detection:** New attack pattern observed (blocked generation, customer report, CVE feed)
2. **Analysis:** Automated analysis extracts the underlying vulnerability class
3. **Constraint Generation:** New constraint rule auto-generated and tested
4. **Propagation:** Constraint pushed to all tenant deployments within minutes
5. **Verification:** All previously generated code re-checked against new constraint
6. **Reporting:** Affected customers notified with remediation guidance

---

## 4. Technology Stack

| Component | Technology | Reason |
|---|---|---|
| **Backend API** | FastAPI (Python 3.12+) | Async, typed, fast |
| **Constraint Solver** | Z3 (via z3-solver pip) | Industry-standard SMT solver |
| **Intent Parsing** | PydanticAI + Claude API | Structured extraction |
| **AST Analysis** | tree-sitter (multi-language) | Fast, incremental AST parsing |
| **Formal Verification** | Lightweight custom prover | Sub-100ms property checking |
| **Component Registry** | PostgreSQL + Redis cache | Versioned, fast retrieval |
| **Immune Memory** | ClickHouse + Redis | Analytics + real-time |
| **Message Queue** | Celery + Redis | Async constraint propagation |
| **Taint Tracking** | Custom dataflow engine | Label propagation on AST |
| **API Gateway** | Kong or custom FastAPI middleware | Rate limiting, auth, metering |
| **Deployment** | Docker + Kubernetes | Standard cloud deployment |
| **CI/CD** | GitHub Actions | Component certification pipeline |
| **Monitoring** | Prometheus + Grafana | Constraint engine performance |
| **Database** | Supabase (PostgreSQL) | Rapid development, auth built-in |

---

## 5. Database Schema (Core Tables)

```sql
-- Certified components registry
CREATE TABLE certified_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version SEMVER NOT NULL,
    language VARCHAR(50) NOT NULL,       -- python, typescript, java, go
    category VARCHAR(100) NOT NULL,      -- auth, crypto, data_access, etc.
    source_code TEXT NOT NULL,
    formal_spec TEXT,                     -- TLA+ or Dafny spec
    compliance_certs JSONB DEFAULT '[]', -- ["HIPAA", "SOC2", "PCI-DSS"]
    cve_coverage JSONB DEFAULT '[]',     -- CVEs this component prevents
    fuzz_report_url TEXT,
    status VARCHAR(20) DEFAULT 'active', -- active, deprecated, revoked
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security constraints
CREATE TABLE constraints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,       -- CRITICAL, HIGH, MEDIUM, LOW
    applies_when JSONB NOT NULL,         -- Condition predicates
    rules JSONB NOT NULL,                -- Constraint rules
    source VARCHAR(50) NOT NULL,         -- manual, immune_response, cve_feed
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Generation audit log
CREATE TABLE generation_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    intent JSONB NOT NULL,
    constraints_applied UUID[] NOT NULL,
    components_used UUID[] NOT NULL,
    output_hash VARCHAR(64) NOT NULL,
    security_certificate JSONB NOT NULL,
    blocked BOOLEAN DEFAULT FALSE,
    block_reason TEXT,
    latency_ms INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Immune memory: attack patterns
CREATE TABLE attack_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_signature VARCHAR(255) NOT NULL,
    vulnerability_class VARCHAR(100) NOT NULL,  -- OWASP category
    attack_vector TEXT NOT NULL,
    generated_constraint_id UUID REFERENCES constraints(id),
    severity VARCHAR(20) NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'active'
);

-- Tenant/customer management
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL,           -- starter, professional, enterprise
    compliance_requirements JSONB DEFAULT '[]',
    custom_constraints JSONB DEFAULT '[]',
    api_key_hash VARCHAR(64) NOT NULL,
    monthly_generation_limit INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security certificates (attestation for generated code)
CREATE TABLE security_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    generation_id UUID REFERENCES generation_log(id),
    tenant_id UUID REFERENCES tenants(id),
    constraints_satisfied JSONB NOT NULL,
    compliance_frameworks JSONB NOT NULL,
    components_versions JSONB NOT NULL,
    certificate_hash VARCHAR(64) NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 6. API Specification

### Core Endpoints

```
POST   /v1/generate              — Generate secure code from intent
POST   /v1/generate/stream       — Stream generation (SSE)
POST   /v1/verify                — Verify existing code against constraints
GET    /v1/components             — List certified components
GET    /v1/components/{id}        — Get component details + cert
GET    /v1/constraints            — List active constraints
POST   /v1/constraints/custom     — Add tenant-specific constraint
GET    /v1/certificates/{id}      — Retrieve security certificate
POST   /v1/immune/report          — Report a vulnerability (feeds immune system)
GET    /v1/immune/status           — Current threat level + recent updates
GET    /v1/compliance/report       — Generate compliance report for audit
GET    /v1/metrics/dashboard       — Generation stats, blocks, threat intel
```

### Generate Endpoint Detail

```python
# POST /v1/generate
class GenerateRequest(BaseModel):
    prompt: str                           # Natural language or structured
    language: str = "python"              # Target language
    framework: str | None = None          # e.g., "fastapi", "django", "express"
    compliance: list[str] = []            # Required compliance frameworks
    context: dict | None = None           # Existing codebase context
    strict_mode: bool = True              # Block on ANY constraint violation
    max_latency_ms: int = 5000            # Latency budget

class GenerateResponse(BaseModel):
    code: str                             # Generated secure code
    certificate: SecurityCertificate      # Attestation
    components_used: list[ComponentRef]   # Which certified components
    constraints_applied: list[str]        # Which constraints enforced
    warnings: list[str]                   # Non-blocking advisories
    latency_ms: int
    immune_version: str                   # Current immune memory version
```

---

## 7. Constraint Engine — Implementation Detail

### Taint Tracking Algorithm

```python
class TaintLabel(Enum):
    USER_INPUT = "user_input"       # From HTTP request, form, CLI
    DATABASE = "database"           # From DB query results
    FILE_SYSTEM = "file_system"     # From file reads
    ENVIRONMENT = "environment"     # From env vars
    SANITIZED = "sanitized"         # Passed through validator
    CERTIFIED = "certified"         # Output of certified component

class TaintTracker:
    """Tracks data flow labels through the AST."""

    def propagate(self, ast_node: ASTNode) -> TaintLabel:
        # Rule: taint propagates through operations
        # Rule: taint is removed ONLY by certified sanitizers
        # Rule: CERTIFIED + USER_INPUT = USER_INPUT (conservative)
        ...

    def check_sink(self, ast_node: ASTNode, sink_type: SinkType) -> Violation | None:
        # Check if tainted data reaches a sensitive sink
        # Sinks: SQL query, HTML output, file path, subprocess arg,
        #         log message (for PII), error response (for secrets)
        ...
```

### Constraint Solver Integration

```python
from z3 import Solver, Bool, And, Or, Not, Implies

class ConstraintSolver:
    def __init__(self):
        self.solver = Solver()

    def check_generation_plan(self, intent: CodeIntent, plan: GenerationPlan) -> Result:
        # Encode intent properties as Z3 variables
        has_user_input = Bool('has_user_input')
        crosses_trust_boundary = Bool('crosses_trust_boundary')
        handles_pii = Bool('handles_pii')
        has_auth = Bool('has_auth')
        uses_parameterized_query = Bool('uses_parameterized_query')

        # Add constraints
        # Rule: user input + DB access → must use parameterized queries
        self.solver.add(Implies(
            And(has_user_input, plan.accesses_database),
            uses_parameterized_query
        ))

        # Rule: PII handling → must have audit logging
        self.solver.add(Implies(handles_pii, plan.has_audit_logging))

        # Rule: trust boundary crossing → must have auth
        self.solver.add(Implies(crosses_trust_boundary, has_auth))

        # Check satisfiability
        if self.solver.check() == sat:
            return Result.SAFE
        else:
            return Result.BLOCKED(reason=self.solver.unsat_core())
```

---

## 8. Implementation Roadmap (8 Weeks)

### Phase 1: Foundation (Weeks 1-2)
- FastAPI project scaffold with auth, rate limiting, metering
- PostgreSQL schema + Supabase setup
- Intent parser with PydanticAI (Claude API integration)
- Basic constraint DSL parser (YAML → internal representation)
- 10 core certified components (auth, SQL, crypto, input validation)
- Unit + property-based test suites for all components

### Phase 2: Constraint Engine (Weeks 3-4)
- Z3-based constraint solver integration
- Taint tracking engine on tree-sitter ASTs
- Secure Assembler: component composition + glue code generation
- 30+ constraint rules covering OWASP Top 10
- `/v1/generate` endpoint (non-streaming)
- Security certificate generation

### Phase 3: Immune System (Weeks 5-6)
- ClickHouse setup for attack pattern analytics
- Immune response pipeline (detect → analyze → constrain → propagate)
- CVE/NVD feed integration
- Constraint auto-generation from attack patterns
- Real-time constraint propagation (Redis pub/sub)
- `/v1/immune/*` endpoints

### Phase 4: Enterprise & Polish (Weeks 7-8)
- Multi-language support (Python, TypeScript, Java, Go)
- Compliance report generator (HIPAA, SOC 2, PCI-DSS)
- Streaming generation (SSE)
- Dashboard UI (React + Tailwind)
- SDK packages (Python, Node.js)
- Load testing (target: <2s p95 for generation)
- Documentation + API reference

---

## 9. File Structure

```
codeimmune/
├── api/
│   ├── main.py                  # FastAPI app entry
│   ├── routes/
│   │   ├── generate.py          # /v1/generate
│   │   ├── verify.py            # /v1/verify
│   │   ├── components.py        # /v1/components
│   │   ├── constraints.py       # /v1/constraints
│   │   ├── immune.py            # /v1/immune
│   │   ├── compliance.py        # /v1/compliance
│   │   └── metrics.py           # /v1/metrics
│   ├── middleware/
│   │   ├── auth.py              # API key validation
│   │   ├── rate_limiter.py      # Rate limiting
│   │   └── metering.py          # Usage tracking
│   └── dependencies.py          # FastAPI deps
├── core/
│   ├── intent_parser.py         # Intent extraction
│   ├── constraint_engine.py     # Z3 solver + constraint logic
│   ├── constraint_dsl.py        # YAML constraint parser
│   ├── taint_tracker.py         # Dataflow taint analysis
│   ├── secure_assembler.py      # Code composition engine
│   ├── formal_verifier.py       # Lightweight property checker
│   └── certificate_generator.py # Security attestation
├── immune/
│   ├── memory.py                # Attack pattern storage
│   ├── analyzer.py              # Vulnerability class extraction
│   ├── constraint_generator.py  # Auto-generate constraints
│   ├── propagator.py            # Push constraints to tenants
│   ├── cve_feed.py              # NVD/CVE integration
│   └── telemetry.py             # Generation analytics
├── components/
│   ├── registry.py              # Component lookup + versioning
│   ├── auth/                    # Certified auth components
│   ├── crypto/                  # Certified crypto components
│   ├── data_access/             # Certified data access
│   ├── network/                 # Certified network components
│   ├── compliance/              # Compliance-specific components
│   └── primitives/              # Safe low-level operations
├── constraints/
│   ├── owasp_top10/             # OWASP constraints
│   ├── compliance/              # Compliance-specific constraints
│   └── custom/                  # Tenant custom constraints
├── models/
│   ├── intent.py                # Pydantic intent models
│   ├── constraint.py            # Constraint models
│   ├── component.py             # Component models
│   ├── certificate.py           # Certificate models
│   └── tenant.py                # Tenant models
├── db/
│   ├── connection.py            # Database connection
│   ├── migrations/              # Alembic migrations
│   └── queries/                 # SQL queries
├── tests/
│   ├── test_intent_parser.py
│   ├── test_constraint_engine.py
│   ├── test_taint_tracker.py
│   ├── test_assembler.py
│   ├── test_components/         # Per-component test suites
│   └── test_integration/        # End-to-end tests
├── sdk/
│   ├── python/                  # Python SDK
│   └── node/                    # Node.js SDK
├── dashboard/                   # React dashboard
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## 10. Key Metrics to Track

| Metric | Target | Tool |
|---|---|---|
| Generation latency (p50) | <1s | Prometheus |
| Generation latency (p95) | <2s | Prometheus |
| Constraint evaluation time | <200ms | Custom timer |
| Block rate (% of generations blocked) | 5-15% | ClickHouse |
| False positive rate (safe code blocked) | <1% | Manual review |
| Immune response time (CVE → constraint) | <4 hours | Alert pipeline |
| Component coverage (% of OWASP Top 10) | 100% | Compliance dashboard |
| Certificate verification time | <50ms | Prometheus |

---

## 11. Security Properties Guaranteed

1. **No SQL Injection** — All DB access through parameterized queries only
2. **No XSS** — All outputs context-aware encoded
3. **No Path Traversal** — File ops through safe_file_io only
4. **No Command Injection** — Subprocess through safe_subprocess only
5. **No Insecure Crypto** — Only approved algorithms available
6. **No Hardcoded Secrets** — Vault references enforced
7. **No Auth Bypass** — Auth middleware in every trust boundary crossing
8. **No Insecure Deserialization** — Safe serialization primitives only
9. **No SSRF** — Network calls through allowlist-enforced http_client
10. **No Race Conditions** — Certified concurrency primitives only

---

## 12. Business Model Implementation

### Pricing Tiers
- **Starter:** $0/month — 100 generations, Python only, basic constraints
- **Professional:** $49/dev/month — unlimited, multi-language, full OWASP
- **Enterprise:** $149/dev/month — compliance certs, custom constraints, SLA, SSO
- **Insurance Partner:** Revenue share on premium reduction from certified code

### Metering
Track per-tenant: generations, components used, constraints evaluated, certificates issued.
Bill monthly via Stripe. Usage-based overage for Starter/Professional.

---

## 13. Compliance Certificate Format

```json
{
  "certificate_id": "cert_abc123",
  "generation_id": "gen_xyz789",
  "timestamp": "2026-02-10T14:30:00Z",
  "tenant_id": "tenant_456",
  "code_hash": "sha256:abcdef...",
  "security_properties": {
    "injection_safe": true,
    "xss_safe": true,
    "auth_enforced": true,
    "crypto_approved": true,
    "secrets_managed": true
  },
  "compliance_frameworks": ["HIPAA", "SOC2"],
  "constraints_applied": ["sql_injection_prevention", "hipaa_audit_logging", "..."],
  "components_used": [
    {"name": "safe_query_builder", "version": "1.2.0", "cert": "comp_cert_001"},
    {"name": "hipaa_audit_logger", "version": "1.0.3", "cert": "comp_cert_002"}
  ],
  "immune_memory_version": "imm_v2026.02.10.1430",
  "valid_until": "2026-08-10T14:30:00Z",
  "signature": "ed25519:..."
}
```

---
---

# 5 PROMPTS TO BUILD THIS — Step by Step

Use these prompts sequentially with an AI coding assistant (Claude, Cursor, etc.). Each prompt references this spec file.

---

## PROMPT 1: Foundation — Project Scaffold + Database + Intent Parser

```
I'm building "CodeImmune" — a constrained secure code generation engine. Read the attached spec file (immune-system-for-software.md).

Build Phase 1 foundation:

1. **Project scaffold**: Create the full directory structure from Section 9. Use FastAPI, Python 3.12+, pyproject.toml with dependencies: fastapi, uvicorn, pydantic, pydantic-ai, sqlalchemy, alembic, redis, z3-solver, tree-sitter, anthropic, clickhouse-connect, celery.

2. **Database**: Create Alembic migrations for ALL tables in Section 5 (certified_components, constraints, generation_log, attack_patterns, tenants, security_certificates). Use Supabase PostgreSQL connection string from env var DATABASE_URL.

3. **Intent Parser** (core/intent_parser.py): Implement the CodeIntent schema from Section 3.1 exactly. Use PydanticAI with Claude API to extract structured intents from natural language prompts. Include the full enum types for ActionType, DataClass, AuthRequirement, InputSource, OutputTarget, ConcurrencyType, ErrorClass. Add a parse_intent(prompt: str) -> CodeIntent async function.

4. **API skeleton**: Create api/main.py with all route stubs from Section 6. Add middleware for API key auth, rate limiting (100 req/min default), and request metering. Wire up the /v1/generate endpoint to call the intent parser and return the parsed intent (generation will come in Prompt 2).

5. **Docker**: Create Dockerfile + docker-compose.yml with services: api, postgres, redis.

Include comprehensive tests for the intent parser with 10+ test cases covering different prompt types (CRUD operations, auth flows, file operations, payment processing).
```

---

## PROMPT 2: Constraint Engine + Taint Tracking

```
Continue building CodeImmune. The project scaffold, database, and intent parser are complete from Prompt 1. Read the spec file for Sections 3.2 and 7.

Build the Constraint Engine:

1. **Constraint DSL Parser** (core/constraint_dsl.py): Parse YAML constraint files from the constraints/ directory into internal ConstraintRule objects. Support the format shown in Section 3.2 (applies_when conditions, FORBID_PATTERN, REQUIRE_PATTERN, REQUIRE_WRAPPER rule types).

2. **Seed constraints**: Create YAML constraint files for ALL items in the Section 3.2 table:
   - constraints/owasp_top10/injection_prevention.yaml
   - constraints/owasp_top10/auth_enforcement.yaml
   - constraints/owasp_top10/crypto_safety.yaml
   - constraints/owasp_top10/data_boundary.yaml
   - constraints/owasp_top10/output_encoding.yaml
   - constraints/owasp_top10/error_handling.yaml
   - constraints/owasp_top10/race_conditions.yaml
   - constraints/owasp_top10/secret_management.yaml

3. **Taint Tracker** (core/taint_tracker.py): Implement the TaintLabel enum and TaintTracker class from Section 7. Use tree-sitter to parse Python ASTs. Implement propagate() for tracking taint through assignments, function calls, string operations. Implement check_sink() for detecting tainted data reaching SQL queries, HTML output, file paths, subprocess args, log messages.

4. **Z3 Constraint Solver** (core/constraint_engine.py): Implement the ConstraintSolver from Section 7. Given a CodeIntent and a proposed GenerationPlan, encode as Z3 boolean variables and check satisfiability. Return SAFE or BLOCKED with unsat_core explanation. Load constraints from the YAML files.

5. **Wire it together**: Update /v1/generate to: parse intent → load applicable constraints → run constraint solver → return constraint check result. If blocked, return 422 with detailed explanation of which constraints failed and why.

Include tests: test that SQL injection intent is blocked, test that parameterized query intent passes, test taint propagation through 5+ code patterns.
```

---

## PROMPT 3: Certified Components + Secure Assembler

```
Continue building CodeImmune. Intent parser and constraint engine are done. Read spec Sections 3.3 and 3.4.

Build the Certified Component Library and Secure Assembler:

1. **Component Registry** (components/registry.py): CRUD for certified components in PostgreSQL. Each component has: name, version, language, category, source_code, compliance_certs, cve_coverage. Include get_components_for_intent(intent: CodeIntent) that returns matching components based on action type and compliance requirements.

2. **Build 10 core certified components** (Python implementations):
   - components/auth/session_manager.py — Secure session creation/validation with httponly cookies, CSRF tokens
   - components/auth/jwt_handler.py — JWT with RS256, short expiry, refresh rotation
   - components/data_access/safe_query_builder.py — Parameterized queries ONLY, no string interpolation possible by API design
   - components/data_access/input_validator.py — Type-safe validation with Pydantic, regex sanitization, length limits
   - components/data_access/output_encoder.py — Context-aware encoding (HTML, URL, JS, SQL, CSS contexts)
   - components/crypto/encryption.py — AES-256-GCM only, key from vault reference
   - components/crypto/hashing.py — Argon2id with safe defaults (time_cost=3, memory_cost=65536)
   - components/network/http_client.py — TLS-enforced, timeout-safe, SSRF-preventing HTTP client
   - components/primitives/safe_file_io.py — Path traversal prevention, allowlist-based
   - components/primitives/safe_subprocess.py — Command injection prevention, allowlist-based

   Each component must: use type hints everywhere, raise SecurityViolation on misuse, include docstrings referencing which CWEs/CVEs it prevents.

3. **Secure Assembler** (core/secure_assembler.py): Takes a CodeIntent + constraint-approved plan + selected components. Uses Claude API to generate ONLY glue code (business logic between components). The prompt to Claude must include strict instructions: no raw I/O, no crypto, no auth logic — only data transformation and control flow using the provided certified component APIs. Output is a complete Python module.

4. **Certificate Generator** (core/certificate_generator.py): After successful assembly, generate a SecurityCertificate (Section 13 format). Hash the output code, list constraints satisfied, components used with versions, sign with Ed25519 key.

5. **Complete /v1/generate flow**: Intent → Constraints → Component Selection → Assembly → Verification → Certificate → Response. Return the GenerateResponse from Section 6.

Test: Send "create a user signup endpoint with email/password that stores in PostgreSQL, needs HIPAA compliance" and verify the full pipeline produces secure, working code with certificate.
```

---

## PROMPT 4: Immune Memory System + Threat Intelligence

```
Continue building CodeImmune. Generation pipeline is complete. Read spec Sections 3.5 and 8 (Phase 3).

Build the Immune Memory System:

1. **ClickHouse setup**: Add ClickHouse to docker-compose. Create tables for:
   - attack_patterns (high-write, time-series optimized)
   - generation_telemetry (what was generated, blocked, and why)
   - constraint_effectiveness (which constraints block the most, false positive rates)

2. **Immune Memory** (immune/memory.py): Store and query attack patterns. Implement similarity matching — when a new pattern is similar to existing ones, link them. Track occurrence_count, first_seen, last_seen, affected_tenants.

3. **Vulnerability Analyzer** (immune/analyzer.py): Given a reported vulnerability or blocked attempt, extract:
   - Vulnerability class (map to CWE)
   - Attack vector pattern
   - Required constraint to prevent
   - Affected component (if any)

4. **Constraint Auto-Generator** (immune/constraint_generator.py): From an analyzed vulnerability, automatically generate a new YAML constraint rule. Use Claude API to draft the constraint, then validate it against test cases (must block the attack, must not block 100 known-safe patterns). Requires human approval flag before activation (safety net).

5. **CVE Feed Integration** (immune/cve_feed.py): Poll NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0) every hour. For each new CVE related to code vulnerabilities (CWE-based filtering), run the analyzer and check if existing constraints cover it. If not, trigger auto-generation.

6. **Propagator** (immune/propagator.py): When a new constraint is approved, push it to all tenant deployments via Redis pub/sub. Each API instance subscribes and hot-reloads constraints without restart.

7. **Telemetry Pipeline** (immune/telemetry.py): Every generation event (success or block) gets logged to ClickHouse. Include: tenant_id, intent hash, constraints applied, components used, blocked (bool), block_reason, latency_ms, timestamp.

8. **API endpoints**: Implement /v1/immune/report (submit vulnerability), /v1/immune/status (current threat level + recent constraint updates), /v1/metrics/dashboard (generation stats).

Test: Simulate an attack pattern submission → verify it flows through analyzer → generates a constraint → constraint blocks similar future attempts.
```

---

## PROMPT 5: Multi-Language Support + Dashboard + SDK + Production Hardening

```
Continue building CodeImmune. All core systems are working for Python. Read spec Sections 8 (Phase 4), 10, and 12.

Build the final production layer:

1. **Multi-language support**: Extend the Secure Assembler and Certified Components to support TypeScript/Node.js:
   - Add tree-sitter-typescript for AST analysis
   - Port the 10 certified components to TypeScript equivalents
   - Update constraint engine to handle TS-specific patterns (prototype pollution, type coercion issues)
   - Intent parser already language-agnostic; add `language` field routing

2. **Streaming generation** (api/routes/generate.py): Add /v1/generate/stream using Server-Sent Events. Stream: intent_parsed → constraints_checked → components_selected → generating → code_chunk_1..N → certificate → done.

3. **Compliance Report Generator** (api/routes/compliance.py): /v1/compliance/report generates a PDF-ready JSON report for auditors. Include: all generations in date range, constraints applied, certificates issued, immune events, component versions used. Format for HIPAA, SOC 2, and PCI-DSS templates.

4. **React Dashboard** (dashboard/): Build with React + Tailwind + Recharts:
   - Real-time generation activity feed
   - Constraint effectiveness charts (blocks over time, by category)
   - Immune system status (active threats, recent constraints added)
   - Compliance overview (% of generations fully certified)
   - Tenant usage metrics
   - Component library browser

5. **Python SDK** (sdk/python/): Publish-ready package `codeimmune`:
   ```python
   from codeimmune import CodeImmune
   client = CodeImmune(api_key="...")
   result = client.generate("create user signup with HIPAA compliance", language="python")
   print(result.code)
   print(result.certificate.compliance_frameworks)
   ```

6. **Production hardening**:
   - Add request validation + error handling on ALL endpoints
   - Structured logging (JSON) with correlation IDs
   - Health check endpoint (/health)
   - Graceful shutdown handling
   - Environment-based config (dev/staging/prod)
   - Rate limiting per tier (Starter: 100/day, Pro: unlimited, Enterprise: unlimited + priority)
   - Prometheus metrics for all Section 10 targets
   - Load test script (locust) targeting <2s p95

7. **Stripe billing integration**: Metered billing based on generation count. Webhook handlers for subscription changes. Usage reporting to Stripe.

Test the complete system end-to-end: sign up tenant → generate secure Python code → generate secure TypeScript code → verify certificates → check compliance report → confirm dashboard shows activity.
```
