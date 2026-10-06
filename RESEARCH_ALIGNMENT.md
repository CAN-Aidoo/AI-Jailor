# Research Alignment & Build-vs-Adopt (ADR-001)

*Status: accepted · Date: 2026-10-06*

The two specs in this repo (AI Jailer isolation, CodeImmune constrained generation)
overlap with several problems that are now **solved by mature projects or
standards**. This record fixes what we adopt, what we build, and why, so effort goes
only into the parts nobody else covers.

## Decision matrix

| Concern | State of the art (2026) | Decision |
|---|---|---|
| Hardware isolation of untrusted code | Firecracker/Kata microVMs are the consensus standard; gVisor is the lighter alternative; ~28 ms restore from pre-warmed snapshots ([guide](https://manveerc.substack.com/p/ai-agent-sandboxing-guide), [comparison](https://www.agenticwire.news/article/gvisor-vs-firecracker)) | **Adopt Firecracker + official `jailer`.** Do not write a VMM. `engine/firecracker.py` is a thin, fail-closed controller over the real Firecracker API. |
| Sandbox as a Kubernetes primitive, warm pools | [kubernetes-sigs/agent-sandbox](https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox) (Sandbox CRD, SandboxWarmPool, gVisor/Kata runtimes) | **Adopt, do not rebuild** our own warm-pool scheduler for the K8s deployment mode. Planned: an `agent-sandbox` backend behind the same `MicroVMEngine` interface. Our bespoke Placement Scheduler/Warm Pool Manager (ARCHITECTURE.md §2) is **deprioritised**. |
| Snapshot / restore | Native Firecracker snapshot API | **Adopt** (`snapshot_vm`). No custom snapshot format. |
| Attestation / provenance format | in-toto Statement + DSSE, signed via Sigstore ([GitHub attestations](https://github.blog/2024-05-02-introducing-artifact-attestations-now-in-public-beta/)) | **Adopt.** Certificates are in-toto statements in DSSE envelopes (`services/attestation.py`), Ed25519 today, `Signer` interface lets us move to keyless Sigstore. The earlier bespoke "certificate" with an unkeyed SHA-256 was forgeable and has been removed. |
| Policy language for tool/agent authorization | Cedar is the emerging default (AWS AgentCore Policy, [Strands Cedar](https://strandsagents.com/docs/user-guide/concepts/agents/interventions/cedar-authorization/)); default-deny, analysable | **Adopt Cedar (planned)** for tool/egress authorization instead of growing our own policy YAML. The egress broker's rule model maps 1:1 onto Cedar permit/forbid. |
| Static taint / vulnerability analysis | CodeQL, Semgrep exist | **Do not compete on rule breadth.** We keep a small in-process dataflow pass for the *generation-time gate* (latency budget) and treat CodeQL/Semgrep as pluggable second opinions. |
| Prompt-injection resistance | CaMeL: capabilities + information-flow control around the LLM, deterministic policies ([arXiv 2503.18813](https://arxiv.org/pdf/2503.18813), [CUA follow-up](https://arxiv.org/pdf/2601.09923)). Model-level defences are probabilistic. | **Build (differentiator).** `agentsec/flow.py`: labelled values (provenance + readers), readers intersect on combine so secrets can't be laundered. |
| Secrets & exfiltration from agent code | MCP ecosystem is weak: 82 % of surveyed servers vulnerable to path traversal, 34 % to command injection; tool poisoning ([OWASP MCP Top 10](https://cycode.com/blog/owasp-mcp-top-10/)) | **Build (differentiator).** `agentsec/egress.py`: the only path to the network; allowlist, SSRF/DNS-rebinding pinning, metadata-endpoint block, **credential injection so the cell never holds the secret**, flow-label check, redacted audit. |
| Secure code generation | Constrained decoding beats post-hoc fixing ([arXiv 2405.00218](https://arxiv.org/html/2405.00218v1)), but grammar-constrained decoding is itself an attack surface ([CodeSpear](https://arxiv.org/pdf/2503.24191)) | **Keep the architecture, narrow the claim.** Generated code is never trusted on the strength of generation-time constraints alone: it passes the verifier + taint pass, and the execution gate still jails it. |
| Audit integrity | Transparency-log style signed checkpoints | **Build small.** Per-event hash over *all* fields + signed (head, length) checkpoints, so truncation and full-chain rebuild are detected (`services/audit_service.py`). Shipping to ClickHouse/SIEM stays as designed. |

## Principles that follow

1. **Verification never replaces isolation.** Static analysis is undecidable in general
   (Rice's theorem). `services/execution_gate.py` uses verification only to choose a
   *tighter* containment tier; unanalysable code (non-Python) gets maximum
   containment. Every cell is a microVM regardless.
2. **Fail closed, never fake.** The previous Firecracker engine returned
   `exit_code=0` without running anything, and the factory always returned the
   simulator. Now: simulated engine refused unless `AIJAILER_ENV=dev`; Firecracker
   engine raises `EngineUnavailable` without `/dev/kvm`.
3. **Secrets never enter the jail.** Placeholders in, real value injected by the broker
   for bound hosts only.
4. **Deterministic policy, not model judgement,** at every enforcement point.

## What was built in this change

| Area | Change |
|---|---|
| Baseline | 44 failing/erroring tests fixed (Postgres-only column types now portable; missing FKs; model registry; test fixtures). Suite: 186 passing. |
| Taint | Replaced substring heuristic with AST dataflow (assignment, f-strings, branches, loops, comprehension, sanitizers, parameterised SQL, `shell=True`); unparseable or non-Python code is never reported clean. |
| Attestation | Ed25519 over in-toto/DSSE; `verify()` checks signature, field tamper, code swap, expiry. |
| Constraint engine | Z3 path now reports *every* violated rule by name via iterated unsat cores (was a generic "z3_unsat"). |
| Engine | Real Firecracker API client, per-cell rootfs copy (base never writable), unique vsock CIDs, jailer argv (non-root, cgroup v2, PID ns), vsock agent protocol, pause/resume/snapshot. Verified against a fake Firecracker API and agent; **not yet exercised on a real KVM host.** |
| Agent security | Flow labels + egress broker (new). |
| Guest agent | `guest-agent/` (Go, static, PID 1): framed-JSON vsock protocol (exec/ping/put_file/get_file), uid drop + no_new_privs, process-group kill, orphan reaping, output/frame caps, symlink-safe files; Go tests (race detector) + Python end-to-end tests. |
| Gate | `EXECUTION_GATE_MODE=off|observe|enforce` wired into `execute_script`. |
| Audit | Full-field hashing + signed checkpoints. |

## Known gaps / next (ordered)

1. **Run the Firecracker path on a KVM host** (needs guest kernel, rootfs with `guest-agent/` installed, TAP + nftables). Highest risk item: the guest agent is now written and tested end-to-end against the Python host client over a Firecracker-style vsock proxy, but nothing has run inside a real microVM.
2. Wire the egress broker into the data plane (nftables DROP-all except the broker's
   per-cell proxy address) so the allowlist is enforced by the host, not by code in the cell.
3. Cedar policy backend for tool/egress rules; Sigstore (keyless) signer; checkpoint
   publication to an external append-only store.
4. `agent-sandbox` (K8s) engine backend; gVisor tier for lower-risk tenants.
5. Multi-language: tree-sitter taint for TypeScript (Python-only today, other languages
   now refuse rather than pass).
6. Certified-component claims (formal specs, 1M-iteration fuzz reports in
   `immune-system-for-software.md` §3.3) are **not yet produced**; do not advertise them until they are.
7. Dependency-confusion / supply chain: pin and hash-lock the guest base images (cosign).
