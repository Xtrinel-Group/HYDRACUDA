<p align="center">
  <img src="https://assets.xtrinel.com/hydracuda-full.svg" alt="HYDRACUDA" width="480" />
</p>

# HYDRACUDA

Hybrid Runtime Access Control for Untrusted Delegated Actions.

HYDRACUDA is a lightweight, open source policy enforcement layer for AI tool calls.  
Define a YAML policy file, drop HYDRACUDA in front of any MCP server or LLM tool layer, and every call is either allowed, denied, or held for review before it executes.

The goal is simple: prevent tool-call abuse and out-of-scope actions while keeping everything local, auditable, and easy to reason about.

---

## Features

- **Language-agnostic policy file**  
  Human-readable `hydracuda.yaml` drives all decisions. Version-controlled, reviewable, and independent of any specific model or framework.

- **Pre-dispatch enforcement**  
  Tool calls are intercepted before they execute, not after. The model cannot bypass the decision by reprompting.

- **Three decisions: allow, deny, review**  
  - `allow` forwards the call to your handler  
  - `deny` blocks the call with a clear reason  
  - `review` is reserved for high-risk actions that will require human approval in a later version

- **Local audit logging**  
  Every decision is written to a SQLite audit log on disk. No telemetry, no external service, no cloud dependency.

- **Two primary use cases**
  - **Production guardrail** for AI-integrated applications
  - **Engagement scope enforcement** for red teams using AI assistants during assessments

---

## Installation

HYDRACUDA targets Python 3.10 and above.

```bash
pip install hydracuda
```

To work on the project locally:

```bash
git clone https://github.com/Xtrinel-Group/HYDRACUDA.git
cd HYDRACUDA
pip install -e .
```

---

## Quick Start

From a new or existing project directory:

```bash
hydracuda init
```

This writes a starter `hydracuda.yaml` with commented examples.

Validate the policy:

```bash
hydracuda check hydracuda.yaml
```

If validation passes, you can integrate HYDRACUDA into your tool-calling layer.

### Minimal integration example

```python
import asyncio
from hydracuda.policy import load_policy
from hydracuda.engine import PolicyEngine
from hydracuda.proxy import ToolCallProxy


async def handle_tool_call(tool_name: str, params: dict) -> dict:
    # Your existing tool dispatch logic goes here.
    # For example, calling into an MCP server or a local command.
    return {"status": "ok", "tool": tool_name, "params": params}


async def main() -> None:
    policy = load_policy("hydracuda.yaml")
    engine = PolicyEngine(policy)
    proxy = ToolCallProxy(engine, audit_path=policy.audit_path)

    # This is what your LLM agent would have requested.
    tool_name = "read_file"
    params = {"path": "/tmp/example.txt"}

    result = await proxy.call(tool_name, params, handler=handle_tool_call)
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
```

In your real application, the LLM agent calls `proxy.call(...)` instead of invoking tools directly.

---

## Policy File

HYDRACUDA policies are defined in YAML. The file created by `hydracuda init` looks similar to this:

```yaml
version: 1
mode: enforce   # enforce | shadow | review

tools:
  read_file:
    allow: true
    parameterRules:
      path:
        denyPatterns:
          - "\\.\\."          # block path traversal
          - "/etc/"
          - "/root/"

  delete_record:
    allow: false
    reason: "Destructive operation. Blocked by default."

  execute_shell:
    allow: review
    rateLimit: "3/minute"

audit:
  path: .hydracuda/audit.db
```

Key concepts:

- **mode**
  - `enforce`: violations are blocked
  - `shadow`: violations are logged but not blocked
  - `review`: intended for future human-approval workflows

- **tools**  
  Each tool has an `allow` value:
  - `true`  → allowed (subject to parameter rules)
  - `false` → always denied
  - `"review"` → queued for human review in a future release

- **parameterRules**  
  `denyPatterns` are Python regular expressions evaluated against the string value of the parameter.

- **audit.path**  
  Path to the SQLite audit database. The parent directory is created automatically if it does not exist.

---

## Audit Log

HYDRACUDA writes one row per tool call decision to a local SQLite database.

Table schema:

- `id` (integer primary key)
- `timestamp` (ISO 8601 string)
- `tool` (tool name)
- `action` (`allow`, `deny`, `review`)
- `reason` (short explanation)
- `params` (JSON-encoded parameters)

This makes it easy to:

- Review which tools are actually used in production
- See which policies are firing most often
- Build dashboards or alerts on top of the audit data

---

## Relationship to VAAST

HYDRACUDA is maintained by Xtrinel, the team behind **VAAST**, an AI security scanner focused on AI attack surfaces and MCP tool-call abuse.

- VAAST is **offensive**: it discovers tool-call abuse and prompt injection vulnerabilities in AI-integrated applications before they reach production.
- HYDRACUDA is **defensive**: it enforces the policies that prevent those same vulnerabilities from being exploited at runtime.

They are fully decoupled. HYDRACUDA does not require VAAST, but future versions will support importing VAAST findings to auto-generate policy templates.

---

## Documentation

For full documentation, examples, and integration guides:

- https://docs.xtrinel.com/hydracuda

---

## Logo and Branding

HYDRACUDA assets are available under the Xtrinel brand guidelines:

- Full wordmark: `https://assets.xtrinel.com/hydracuda-full.svg`
- Icon: `https://assets.xtrinel.com/hydracuda.svg`

You can use these in dashboards, internal docs, or integrations that surface HYDRACUDA decisions.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Add tests for any new behavior
4. Run `pytest`
5. Open a pull request with a clear description of the change

Please keep new features focused and security-oriented. If you are proposing a change to the policy format, open an issue first for discussion.

---

## License

HYDRACUDA is released under the MIT License. See `LICENSE` for details.
