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
  - `review` blocks the call and raises `ReviewRequired`, carrying the decision, for you to route into an approval workflow

- **Strict validation, no silent no-ops**  
  An unrecognized key is a load error, not a warning. A typo'd rule used to fail open — you believed a rule was active when it was not.

- **Read-only introspection**  
  `hydracuda validate` reports rules that do not mean what they appear to. `hydracuda plan` prints the decision for every declared resource without executing anything.

- **Local audit logging**  
  Every decision is written to a SQLite audit log on disk. No telemetry, no external service, no cloud dependency. Policy evaluation is local and does not phone home.

- **Deterministic engine**  
  Decisions are a pure function of the policy, the request, and the context. No model call, no clock read, no network in the decision loop — which is what makes `plan` reproducible.

- **Two primary use cases**
  - **Production guardrail** for AI-integrated applications
  - **Engagement scope enforcement** for red teams using AI assistants during assessments

---

## Installation

HYDRACUDA targets Python 3.10 and above.

```bash
pip install hydracuda
```

That installs the runtime and the CLI. The optional dashboard is not part of the
package — it is a development tool you run from a checkout, see
[Dashboard](#dashboard).

To work on the project locally:

```bash
git clone https://github.com/Xtrinel-Group/HYDRACUDA.git
cd HYDRACUDA
pip install -e ".[dev]"
```

---

## Quick Start

From a new or existing project directory:

```bash
hydracuda init
```

This writes a starter `hydracuda.yaml`.

Check it, then see what it decides:

```bash
hydracuda validate          # schema errors, conflicting and unreachable rules
hydracuda plan              # ALLOW/DENY/REVIEW for every declared resource
```

Both default to `hydracuda.yaml` in the current directory and both are read-only: no tool runs, no audit record is written, nothing on disk changes.

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

In your real application, the LLM agent calls `proxy.call(...)` instead of invoking tools directly. A denied call raises `PermissionError`; a call needing approval raises `ReviewRequired`.

---

## CLI

```
hydracuda init                          Write a starter hydracuda.yaml
hydracuda validate [file] [--strict]    Check a policy
hydracuda plan     [file] [--reasons]   Show what it decides
```

`validate` exits non-zero on an error. Warnings are reported but do not fail the
command unless you pass `--strict`, which is what you want in CI.

```
$ hydracuda validate
Policy: hydracuda.yaml
Version 2, mode enforce, default deny, 2 rule(s), 1 adapter(s)

warning: unpinned-when-field [rules[0] untrusted-agents-cannot-write]
  tests context field(s) ['trust'], which are not listed in `pinned_context`.
  Those values are supplied per call, so this rule can only be trusted if the
  calling code never derives them from model output. Add them to
  `pinned_context` to make HYDRACUDA enforce that.

0 error(s), 1 warning(s)
Policy is valid.
```

Eleven diagnostics are reported, from unreachable rules to blocking rules that a
missing field slips past. The full table is in
[the spec](docs/policy-spec.md#validate).

`plan` walks the declared resource surface and prints one line per resource.
Each is evaluated **with no parameters and no context**, which is all a policy
file supplies on its own; rules that could change the outcome for a real call
are flagged rather than guessed at.

```
$ hydracuda plan examples/policy.yaml
Policy: examples/policy.yaml
Version 2, mode enforce, default deny, 4 rule(s), 1 adapter(s)

Declared surface: 3 resource(s). Evaluated with no parameters and no context.

  ALLOW   read_file      allow-file-reads  [conditional: block-sensitive-paths]
  DENY    delete_record  block-destructive-deletes
  REVIEW  execute_shell  shell-requires-approval

1 allow, 1 deny, 1 review
1 resource(s) have a conditional outcome: the action above holds for a call with
no parameters and no context, and the listed rules can change it for a real call.
```

`hydracuda check` still works as a deprecated alias for `validate`.

---

## Policy File

The full specification is [`docs/policy-spec.md`](docs/policy-spec.md). What
follows is an orientation, not the authority.

Policy is a separate, version-controllable YAML file. **Adapters** declare what
exists — the resources and actions your integration exposes. **Rules** declare
what is allowed. The two are deliberately separate: adding a tool is not the
same act as permitting it.

```yaml
version: 2
mode: enforce          # enforce | shadow | review
default_action: deny   # what happens when no rule matches
audit_path: .hydracuda/audit.db

# Context fields the caller must not be able to influence. Listing a field here
# makes HYDRACUDA enforce that it is pinned rather than supplied per call.
pinned_context: [agent, trust]

adapters:
  - name: fs
    type: local_tools
    resources: [read_file, write_file]
    config:
      root: ./workspace   # paths are canonicalized and confined to this root

rules:
  # Ordered. First match wins.
  - name: block-sensitive-paths
    resource: read_file
    action: deny
    where:                      # request parameters — agent-controlled
      path:
        matches: ["/etc/", "/root/"]

  - name: untrusted-agents-cannot-write
    resource: write_file
    action: deny
    when:                       # evaluation context — integrator-controlled
      trust:
        equals: untrusted

  - name: allow-file-reads
    resource: read_file
    action: allow
```

Key concepts:

- **mode**
  - `enforce`: a denied call is blocked
  - `shadow`: the decision is computed and logged, and **the call executes anyway**. Use it to trial a policy against real traffic. A shadow policy enforces nothing, and `validate` warns about that.
  - `review`: reserved; currently behaves as `enforce`

- **default_action**  
  What happens when no rule matches. Defaults to `deny`, so adding a tool without adding a rule fails closed.

- **rules**  
  Evaluated in order, first match wins. `where` tests request parameters, which the agent controls. `when` tests evaluation context, which your code supplies. The distinction is a security boundary, not a naming convention — see [Trust model](docs/policy-spec.md#trust-model).

- **resource patterns**  
  Dot-separated namespaces. `*` matches one segment, `**` matches zero or more.

- **audit_path**  
  Path to the SQLite audit database. The parent directory is created automatically if it does not exist.

Version 1 files still load. They are translated to version 2 rules at load time
and evaluated by the same engine, so decisions are identical to v0.2.0.

### Keys that changed

The v0.2.0 README documented several keys that do not exist. They were never
read, so a policy using them was not doing what it said:

| README said | Reality |
|---|---|
| `parameterRules` | `parameter_rules` |
| `denyPatterns` | `deny_patterns` |
| `rateLimit` | **Not implemented.** Now a load error rather than silently discarded. |
| `audit: {path: ...}` | `audit_path`. The nested form is honoured as an alias, which it was not before. |

Unknown keys are now rejected with a suggestion, so these fail loudly instead of
being ignored:

```
$ hydracuda validate
Policy: hydracuda.yaml
error: schema
  Tool 'read_file': unrecognized key(s) ['parameterRules']. 'parameterRules' —
  did you mean 'parameter_rules'? Allowed: ['allow', 'parameter_rules', 'reason']
Policy is invalid.
```

---

## Audit Log

HYDRACUDA writes one row per decision to a local SQLite database.

| Column | Meaning |
|---|---|
| `id` | integer primary key |
| `timestamp` | ISO 8601, UTC |
| `tool` | resource the agent asked for |
| `action` | `allow`, `deny`, `review` |
| `reason` | short explanation |
| `params` | JSON-encoded parameters, after normalization |
| `rule` | name of the rule that decided, or null for the default |
| `mode` | policy mode at the time of the decision |
| `enforced` | whether the decision was acted on — `0` for a shadow-mode block |
| `normalization` | what the adapter changed, e.g. a path canonicalization |

An existing database from v0.1.0 or v0.2.0 is migrated in place on first write;
the four columns after `params` are added with `ALTER TABLE`. Rows written
before the migration have `NULL` there, and every decision back then was
enforced.

`enforced` is the column to read before drawing conclusions. Under `mode:
shadow` a row can say `deny` for a call that ran to completion, so a count of
denies is not a count of calls blocked.

This makes it easy to:

- Review which tools are actually used in production
- See which rules are firing most often
- Build dashboards or alerts on top of the audit data

> **The audit log is untrusted input.** `tool` is whatever name the agent asked
> for, `reason` quotes that name back, and `params` is the raw arguments the
> agent supplied. A blocked call is still a recorded call, so refusing an action
> does not keep its payload out of the log. Escape these fields before rendering
> them anywhere — unescaped, they were a stored XSS in the bundled dashboard up
> to and including v0.2.0.

---

## Dashboard

Optional, and downstream of everything else. HYDRACUDA runs fully headless: the
runtime and both CLI commands behave identically whether the dashboard is
running or absent.

It is **not shipped in the wheel or the sdist**, so `pip install hydracuda` does
not give you `dashboard.app`. It is a development tool, run from a clone:

```bash
git clone https://github.com/Xtrinel-Group/HYDRACUDA.git
cd HYDRACUDA
pip install -e ".[dashboard]"
HYDRACUDA_AUDIT_DB=/path/to/.hydracuda/audit.db python -m dashboard.app
# http://localhost:8321
```

It reads the audit log at `$HYDRACUDA_AUDIT_DB`, which can be any project's log
— the dashboard does not have to live beside the agent it is reporting on.

It is a read-only consumer of the audit log and holds no policy state: it never
imports `hydracuda`, never reads a policy file, and cannot influence a decision.
Its SQLite connections are opened `mode=ro`, so that is enforced by the driver —
which matters because the audit log has a live writer.

Single-user, localhost, no auth. Do not expose it.

---

## Relationship to VAAST

HYDRACUDA is maintained by Xtrinel, the team behind **VAAST**, an AI security scanner focused on AI attack surfaces and MCP tool-call abuse.

- VAAST is **offensive**: it discovers tool-call abuse and prompt injection vulnerabilities in AI-integrated applications before they reach production.
- HYDRACUDA is **defensive**: it enforces the policies that prevent those same vulnerabilities from being exploited at runtime.

They are fully decoupled. HYDRACUDA does not require VAAST, but future versions will support importing VAAST findings to auto-generate policy templates.

---

## Documentation

- [`docs/policy-spec.md`](docs/policy-spec.md) — policy format, trust model, adapters, diagnostics
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
