# AI Jailer — Isolation-as-a-Service for Untrusted AI Code

## What Is This?

AI Jailer is a specialized infrastructure platform that provides secure, hardware-isolated execution environments for untrusted AI-generated code. It is the "padded cell" that every AI agent builder needs—ensuring that when an agent goes rogue, it destroys only its own disposable cell, not the company database.

## The Problem

AI agents generate and execute code at scale. This code can hallucinate filesystem access, leak secrets through network calls, execute malicious payloads, or consume unbounded resources. Current solutions are inadequate:

- **Standard Docker containers** share the host kernel. A container escape compromises the entire host.
- **Existing sandboxing providers** (E2B, etc.) impose 24-hour session limits, making them unusable for long-running enterprise agent workflows.
- **DIY approaches** require deep infrastructure expertise most AI teams don't have, and lack the audit trails enterprises require for compliance (SOC 2, HIPAA).
- **25–30% of AI-generated code contains vulnerabilities**, and this percentage increases with agent autonomy.

## The Solution

AI Jailer provides microVM-based isolation where every agent session runs in its own dedicated virtual machine with its own kernel. This is not container isolation—it is hardware-level isolation using technologies like Firecracker and Kata Containers.

### Core Capabilities

- **Hardware-Level Isolation**: Dedicated kernel per session via microVMs. No shared kernel attack surface.
- **Unlimited Session Duration**: No 24-hour limits. Agents can run for days, weeks, or indefinitely with persistent state.
- **Snapshot & Restore**: Full VM state can be frozen, stored, and resumed on demand.
- **Audit Logging**: Every syscall, file access, network request, and resource consumption event is captured for compliance.
- **Resource Governance**: CPU, memory, disk, network quotas enforced at the hypervisor level. Cost controls prevent runaway spend.
- **Framework Agnostic**: REST/gRPC API integrates with any agent framework—LangChain, CrewAI, AutoGen, OpenHands, custom systems.

## Target Users

1. **AI Agent Builders** — Teams building autonomous agents that execute code (the primary market).
2. **Enterprise AI Teams** — Organizations deploying agents internally that must meet compliance requirements.
3. **AI Platform Companies** — Companies like Devin, OpenHands, Cursor that need sandboxing infrastructure but don't want to build it.
4. **Code Execution APIs** — Any service that runs user-submitted or AI-generated code.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│                     API Gateway                          │
│              (REST + gRPC + WebSocket)                   │
├─────────────────────────────────────────────────────────┤
│                  Session Manager                         │
│         (Lifecycle, Routing, Load Balancing)             │
├─────────────────────────────────────────────────────────┤
│                  MicroVM Engine                          │
│        (Firecracker / Kata Containers VMM)              │
├──────────┬──────────┬──────────┬───────────────────────┤
│  Cell 1  │  Cell 2  │  Cell 3  │  ...Cell N            │
│ (Agent)  │ (Agent)  │ (Agent)  │  (Agent)              │
│ Own kern │ Own kern │ Own kern │  Own kernel            │
├──────────┴──────────┴──────────┴───────────────────────┤
│              State & Snapshot Store                      │
│           (Object Storage + Metadata DB)                │
├─────────────────────────────────────────────────────────┤
│              Audit & Observability                       │
│      (Event Stream → Audit Log → Compliance Reports)    │
├─────────────────────────────────────────────────────────┤
│              Resource Governor                           │
│       (Quotas, Metering, Cost Controls, Alerts)         │
└─────────────────────────────────────────────────────────┘
```

## Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| MicroVM Runtime | Firecracker (primary), Kata Containers (fallback) | Sub-second boot, hardware isolation, battle-tested by AWS Lambda |
| API Layer | FastAPI (REST) + gRPC | High performance, async, strong typing |
| Session State | PostgreSQL + Redis | Relational metadata + fast session lookup |
| Object Storage | MinIO (self-hosted) / S3 (cloud) | Snapshots, filesystem persistence |
| Audit Pipeline | Kafka → ClickHouse | High-throughput event streaming + analytical queries |
| Orchestration | Kubernetes + custom scheduler | MicroVM scheduling, node management |
| Networking | CNI plugins + iptables/nftables | Per-cell network policy enforcement |
| Auth | JWT + API Keys + mTLS | Multi-layer authentication |
| Metering | Custom collector → TimescaleDB | Usage-based billing data |

## Project Status (honest)

- Control plane (API, auth, policies, audit, constraint engine, certified components, taint/verification): implemented and tested (186 tests).
- Firecracker data plane: controller implemented and unit-tested against a fake VMM; **not yet validated on real KVM hardware**. The simulated engine is refused outside `AIJAILER_ENV=dev`.
- See [RESEARCH_ALIGNMENT.md](./RESEARCH_ALIGNMENT.md) for what we adopt from existing standards (Firecracker, in-toto/DSSE, Cedar, K8s agent-sandbox) versus build (flow control, egress broker, execution gate).

## Documentation Index

| Document | Description |
|---|---|
| [PRODUCT_REQUIREMENTS.md](./PRODUCT_REQUIREMENTS.md) | Product requirements and user stories |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System architecture and component design |
| [MICROVM_ENGINE.md](./MICROVM_ENGINE.md) | MicroVM isolation layer specification |
| [SECURITY_MODEL.md](./SECURITY_MODEL.md) | Security architecture and threat model |
| [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) | REST, gRPC, and WebSocket API specs |
| [DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md) | Database design and data models |
| [AUDIT_SYSTEM.md](./AUDIT_SYSTEM.md) | Audit logging and compliance framework |
| [PEER_LINKS.md](./PEER_LINKS.md) | Attested, end-to-end encrypted cell-to-cell channels (two-sided consent, threat model) |
| [STATE_MANAGEMENT.md](./STATE_MANAGEMENT.md) | Snapshot, restore, and persistent state |
| [RESOURCE_MANAGEMENT.md](./RESOURCE_MANAGEMENT.md) | Quotas, metering, and cost controls |
| [SDK_SPECIFICATION.md](./SDK_SPECIFICATION.md) | Client SDK design for Python, Node, Go |
| [NETWORKING.md](./NETWORKING.md) | Network isolation and policy enforcement |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Infrastructure and deployment architecture |
| [RESEARCH_ALIGNMENT.md](./RESEARCH_ALIGNMENT.md) | Build-vs-adopt decisions, research alignment, roadmap |

## Key Design Principles

1. **Defense in Depth**: Multiple isolation layers—hypervisor, kernel, network, filesystem, syscall filtering.
2. **Zero Trust by Default**: Every cell starts with no permissions. Access is explicitly granted.
3. **Audit Everything**: If it happened inside a cell, there's a record of it.
4. **Sub-Second Startup**: MicroVMs must boot in under 200ms to not bottleneck agent workflows.
5. **Stateful by Design**: Unlike ephemeral serverless, cells maintain state across interactions.
6. **Framework Agnostic**: No opinions on which agent framework you use. We isolate the execution, not the orchestration.
