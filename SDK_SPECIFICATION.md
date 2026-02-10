# SDK Specification — AI Jailer

## Overview

AI Jailer provides official SDKs for Python (primary), Node.js, and Go. The SDKs wrap the REST and gRPC APIs with ergonomic, language-idiomatic interfaces that make common workflows trivial.

## Design Principles

1. **Common operations should be one-liners.** Creating a cell, running a command, and getting the output should be 3 lines of code.
2. **Async-first.** All SDKs support async/await natively. Sync wrappers available for convenience.
3. **Type-safe.** Full type annotations (Python type hints, TypeScript types, Go structs).
4. **Error handling is explicit.** Errors are typed and actionable, not generic exceptions.
5. **Streaming is native.** Real-time stdout/stderr streaming is a first-class pattern.

## Python SDK

### Installation

```bash
pip install aijailer
```

### Quick Start

```python
from aijailer import AiJailer

client = AiJailer(api_key="aj_live_xxxxxxxxxxxx")

# Create and run in one shot
result = client.run(
    image="base-python",
    command="python3 -c 'print(2+2)'"
)
print(result.stdout)  # "4\n"
print(result.exit_code)  # 0
```

### Client Initialization

```python
from aijailer import AiJailer, AiJailerConfig

# Simple
client = AiJailer(api_key="aj_live_xxxx")

# Full configuration
client = AiJailer(
    config=AiJailerConfig(
        api_key="aj_live_xxxx",
        base_url="https://api.aijailer.com",  # or self-hosted URL
        timeout=30.0,
        max_retries=3,
        retry_backoff_factor=0.5,
    )
)

# Async client
from aijailer import AsyncAiJailer
async_client = AsyncAiJailer(api_key="aj_live_xxxx")
```

### Cell Management

```python
# Create a cell
cell = client.cells.create(
    name="my-agent",
    image="base-python",
    resources={"vcpus": 2, "memory_mb": 1024},
    security_policy_id="pol_restrictive",
    environment={"API_KEY": "sk-xxxx"},
    persistent_volume={"size_mb": 5120, "mount_path": "/data"},
    tags={"project": "backend"},
)

# Cell is an object with all properties
print(cell.id)       # "cell_abc123"
print(cell.status)   # "running"
print(cell.internal_ip)

# Get cell
cell = client.cells.get("cell_abc123")

# List cells
cells = client.cells.list(status="running", tag="project=backend")
for c in cells:
    print(f"{c.name}: {c.status}")

# Stop
client.cells.stop("cell_abc123", grace_period_seconds=10)

# Pause / Resume
client.cells.pause("cell_abc123")
client.cells.resume("cell_abc123")

# Destroy
client.cells.destroy("cell_abc123", destroy_persistent=False)
```

### Command Execution

```python
# Simple execution
result = client.exec("cell_abc123", command="ls -la /data")
print(result.stdout)
print(result.exit_code)

# Script execution
result = client.exec_script(
    "cell_abc123",
    script="""
import os
for f in os.listdir('/data'):
    print(f)
""",
    interpreter="/usr/bin/python3",
    timeout_seconds=60,
)

# Streaming execution
for event in client.exec_stream("cell_abc123", command="pip install pandas"):
    if event.type == "stdout":
        print(event.text, end="")
    elif event.type == "stderr":
        print(f"ERR: {event.text}", end="")
    elif event.type == "exit":
        print(f"\nExit code: {event.exit_code}")

# Async streaming
async for event in async_client.exec_stream("cell_abc123", command="npm install"):
    ...
```

### File Operations

```python
# Upload a file
client.files.upload("cell_abc123", local_path="./main.py", remote_path="/data/main.py")

# Upload from string
client.files.write("cell_abc123", path="/data/config.json", content='{"key": "value"}')

# Download a file
client.files.download("cell_abc123", remote_path="/data/output.csv", local_path="./output.csv")

# Read file contents
content = client.files.read("cell_abc123", path="/data/main.py")

# List directory
entries = client.files.list("cell_abc123", path="/data", recursive=True)
for entry in entries:
    print(f"{'DIR' if entry.is_dir else 'FILE'} {entry.path} ({entry.size})")
```

### Snapshots

```python
# Create snapshot
snapshot = client.snapshots.create(
    "cell_abc123",
    name="after-setup",
    description="Environment configured with all dependencies"
)

# Wait for completion
snapshot.wait_until_ready(timeout=60)

# List snapshots
snapshots = client.snapshots.list("cell_abc123")

# Restore
cell = client.snapshots.restore("snap_abc123")

# Clone (create new cell from snapshot)
new_cell = client.snapshots.clone(
    "snap_abc123",
    name="cloned-agent",
    resources={"vcpus": 4, "memory_mb": 2048}
)
```

### Security Policies

```python
from aijailer import NetworkPolicy, ResourcePolicy

# Create a policy
policy = client.policies.create(
    name="web-scraper-policy",
    network=NetworkPolicy(
        default="deny",
        egress=[
            {"action": "allow", "destinations": [{"domain": "*.example.com"}], "ports": [443]},
        ]
    ),
    resources=ResourcePolicy(
        max_vcpus=2,
        max_memory_mb=2048,
        max_pids=256
    )
)

# Apply to a cell
cell = client.cells.create(
    image="base-python",
    security_policy_id=policy.id
)
```

### Audit Logs

```python
from datetime import datetime, timedelta

# Query events
events = client.audit.query(
    cell_id="cell_abc123",
    event_type="policy_violation",
    start_time=datetime.utcnow() - timedelta(hours=24),
    end_time=datetime.utcnow(),
    severity="critical"
)

for event in events:
    print(f"[{event.timestamp}] {event.event_type}: {event.details}")

# Export for compliance
client.audit.export(
    start_time=datetime(2025, 1, 1),
    end_time=datetime(2025, 2, 1),
    format="csv",
    output_path="./audit_january.csv"
)
```

### Webhooks

```python
webhook = client.webhooks.create(
    url="https://my-service.com/hooks/aijailer",
    events=["cell.stopped", "policy.violation", "spending.threshold"],
    secret="my-webhook-secret"
)
```

### Context Manager Pattern

```python
# Cell automatically destroyed on exit
with client.cell(image="base-python", name="temp-session") as cell:
    result = cell.exec("python3 -c 'print(42)'")
    print(result.stdout)
# Cell destroyed here

# Async version
async with async_client.cell(image="base-python") as cell:
    result = await cell.exec("echo hello")
```

### Error Handling

```python
from aijailer.exceptions import (
    AiJailerError,
    CellNotFoundError,
    CellNotRunningError,
    PolicyViolationError,
    ResourceLimitError,
    SpendingCapError,
    RateLimitError,
    AuthenticationError,
)

try:
    result = client.exec("cell_abc123", command="curl evil.com")
except PolicyViolationError as e:
    print(f"Blocked by policy: {e.policy_id}")
    print(f"Violation: {e.violation_type}")
    print(f"Details: {e.details}")
except CellNotRunningError:
    print("Cell is not running")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
```

## Node.js SDK

### Installation

```bash
npm install @aijailer/sdk
```

### Quick Start

```typescript
import { AiJailer } from '@aijailer/sdk';

const client = new AiJailer({ apiKey: 'aj_live_xxxx' });

const result = await client.run({
  image: 'base-node',
  command: 'node -e "console.log(2+2)"',
});
console.log(result.stdout); // "4\n"
```

### Key Patterns

```typescript
// Cell management
const cell = await client.cells.create({
  name: 'my-agent',
  image: 'base-node',
  resources: { vcpus: 2, memoryMb: 1024 },
});

// Streaming execution
const stream = client.execStream(cell.id, { command: 'npm install express' });
for await (const event of stream) {
  if (event.type === 'stdout') process.stdout.write(event.text);
}

// Context manager equivalent
await client.withCell({ image: 'base-node' }, async (cell) => {
  const result = await cell.exec('echo hello');
  console.log(result.stdout);
});
// Cell destroyed here
```

## Go SDK

### Installation

```bash
go get github.com/aijailer/sdk-go
```

### Quick Start

```go
package main

import (
    "context"
    "fmt"
    "github.com/aijailer/sdk-go"
)

func main() {
    client := aijailer.NewClient("aj_live_xxxx")

    result, err := client.Run(context.Background(), &aijailer.RunParams{
        Image:   "base-python",
        Command: "python3 -c 'print(2+2)'",
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(result.Stdout) // "4\n"
}
```

## Agent Framework Integration Examples

### LangChain Integration

```python
from aijailer import AiJailer
from langchain.tools import Tool

client = AiJailer(api_key="aj_live_xxxx")

def execute_code(code: str) -> str:
    """Execute Python code in a secure sandbox."""
    with client.cell(image="base-python") as cell:
        result = cell.exec(f"python3 -c '{code}'", timeout_seconds=30)
        if result.exit_code != 0:
            return f"Error: {result.stderr}"
        return result.stdout

code_executor = Tool(
    name="code_executor",
    description="Execute Python code in a secure sandbox",
    func=execute_code,
)
```

### CrewAI Integration

```python
from aijailer import AiJailer
from crewai import Agent, Task

client = AiJailer(api_key="aj_live_xxxx")
cell = client.cells.create(image="base-full", name="crew-workspace")

def sandboxed_exec(command: str) -> str:
    result = client.exec(cell.id, command=command, timeout_seconds=60)
    return result.stdout if result.exit_code == 0 else f"Error: {result.stderr}"

coder = Agent(
    role="Senior Developer",
    tools=[sandboxed_exec],
    allow_code_execution=True,
)
```

### OpenAI Function Calling

```python
from aijailer import AiJailer
import openai

jailer = AiJailer(api_key="aj_live_xxxx")

tools = [{
    "type": "function",
    "function": {
        "name": "execute_code",
        "description": "Execute code in a secure sandbox",
        "parameters": {
            "type": "object",
            "properties": {
                "language": {"type": "string", "enum": ["python", "node", "bash"]},
                "code": {"type": "string"},
            },
            "required": ["language", "code"]
        }
    }
}]

def handle_tool_call(call):
    args = json.loads(call.function.arguments)
    interpreters = {"python": "python3", "node": "node", "bash": "bash"}

    with jailer.cell(image="base-full") as cell:
        result = cell.exec_script(
            script=args["code"],
            interpreter=interpreters[args["language"]]
        )
        return result.stdout if result.exit_code == 0 else f"Error: {result.stderr}"
```

## SDK Versioning

- SDKs follow semantic versioning (semver).
- API version is pinned per SDK major version.
- Breaking API changes increment the SDK major version.
- New API features increment the SDK minor version.
- Bug fixes increment the SDK patch version.
