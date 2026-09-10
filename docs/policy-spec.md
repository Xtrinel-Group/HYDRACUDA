# HYDRACUDA Policy Specification

Version 2 of the `hydracuda.yaml` policy format.

A policy file is the single source of truth for what an agent is allowed to
do. It is plain YAML, version-controlled, and evaluated entirely locally —
nothing in this specification requires network access.

Version 1 files (the flat `tools:` map shipped in v0.1.0–v0.2.0) are still
loaded and still work; see [Version 1 compatibility](#version-1-compatibility).

---

## Evaluation model

1. The proposed action arrives as a **resource** name plus a map of
   **parameters**, optionally accompanied by a **context** map.
2. Rules are evaluated **in file order**. The first rule whose `resource`
   pattern, `where` conditions, and `when` conditions all match wins.
3. If no rule matches, `default_action` applies.
4. `mode` then decides whether the outcome is enforced or only recorded.

Evaluation is pure and deterministic. The engine does no I/O, does not read
the clock, and contains no model-based decision making — the same inputs
always yield the same decision.

---

## Top-level keys

```yaml
version: 2
mode: enforce
default_action: deny
audit_path: .hydracuda/audit.db
adapters: []
rules: []
```

| Key | Required | Default | Meaning |
|---|---|---|---|
| `version` | yes | — | Must be `1` or `2`. |
| `mode` | no | `enforce` | `enforce`, `shadow`, or `review`. |
| `default_action` | no | `deny` | Applied when no rule matches. `allow`, `deny`, or `review`. Defaults to `deny` so an incomplete policy fails closed. |
| `default_reason` | no | built-in | Template used for the no-rule-matched reason. `{resource}` and `{action}` are substituted. |
| `audit_path` | no | `.hydracuda/audit.db` | SQLite audit log location. |
| `adapters` | no | `[]` | Declares the resource surface. See [Adapters](#adapters). |
| `rules` | no | `[]` | Ordered rule list. An empty list means every request falls through to `default_action`. |
| `pinned_context` | no | `[]` | Context fields that must be established out of band before enforcement starts. See [Trust model](#trust-model). |

Any key not listed here is a **hard error**. A misspelled key used to be
silently ignored, which meant a policy could appear to have a rule that was
never active — a fail-open condition. Where a rejected key looks like a
misspelling of a real one, the error names the intended key.

`tests` is **not** in the table above, and is therefore currently rejected like
any other unknown key. Its schema is specified in [Test cases](#test-cases-tests)
and implemented in 0.4.0; the table gains a row when the loader does.

### Rejected keys

`rate_limit` is **rejected**. It was accepted and discarded in v0.1.0–v0.2.0,
so a policy declaring it asserted a control that did not exist. Rate limiting
is stateful, which the decision engine deliberately is not (see
[Evaluation model](#evaluation-model)), so it belongs in the calling layer.
Remove the key; there is no supported spelling of it.

This is a breaking change for version 1 policies that carry the key. The load
error names the key and the reason.

### `mode`

| Value | Effect |
|---|---|
| `enforce` | `deny` blocks the call, `review` halts it for human approval. |
| `shadow` | The real decision is computed and written to the audit log, but the call is **executed anyway**. Use this to trial a policy against live traffic. |
| `review` | Reserved for the human-approval workflow. Currently behaves as `enforce`. |

In `shadow` mode the audit log still records the true verdict (`deny` /
`review`), plus a `mode` column recording that it was not enforced. So a
shadow-mode log answers both "what would this policy have blocked?" and "what
did we actually block?"

---

## Rules

```yaml
rules:
  - name: block-sensitive-paths
    resource: filesystem.read_file
    action: deny
    reason: "reads outside the project tree are not permitted"
    where:
      path:
        matches:
          - "^/etc/"
          - "\\.\\."
    when:
      agent:
        in: [research-bot, triage-bot]
```

| Key | Required | Meaning |
|---|---|---|
| `resource` | yes | Resource pattern. See [Resource patterns](#resource-patterns). |
| `action` | yes | `allow`, `deny`, or `review`. |
| `name` | no | Label for logs, `plan` output, and `validate` diagnostics. |
| `reason` | no | Human-readable explanation attached to the decision. A default is supplied per action if omitted. |
| `where` | no | Conditions on the request **parameters**. |
| `when` | no | Conditions on the evaluation **context**. |

Order matters. Put narrow `deny` rules above broad `allow` rules — the first
match wins and later rules are never consulted.

### Resource patterns

Resources are dot-separated segments (`filesystem.read_file`,
`github.repository.read`). Patterns match segment by segment:

| Pattern | Matches |
|---|---|
| `filesystem.read_file` | exactly that resource |
| `filesystem.*` | one further segment: `filesystem.read_file`, not `filesystem.file.read` |
| `filesystem.read_*` | `filesystem.read_file`, `filesystem.read_dir` |
| `filesystem.**` | zero or more further segments |
| `**` | everything |

A flat name with no dots (`read_file`) is a single-segment resource and
matches normally — that is how version 1 tool names keep working.

---

## Trust model

HYDRACUDA restricts an agent that is assumed to be capable of trying to evade
it — via prompt injection, a compromised upstream tool description, or its own
choice of arguments. So the question of which inputs the agent can influence
is load-bearing, not incidental.

### What the agent controls

| Input | Controlled by | Tested by |
|---|---|---|
| `params` | **The agent.** Assume every value is hostile. | `where` |
| resource name | **The agent chooses among declared resources.** | `resource` |
| `context` | **The integrator, never the agent.** | `when` |

`params` is the untrusted side and is meant to be: constraining hostile
arguments is the tool's job. `when` exists for the opposite kind of fact —
who is calling, at what trust level, in which environment — which is only
meaningful if the caller cannot assert it about itself.

### The guarantee, and how it is enforced

**The agent cannot influence its own `context` values, provided the fields
that matter are pinned.** Four mechanisms, all in `ToolCallProxy`:

1. **Separate arguments, never merged.** `params` and `context` are distinct
   parameters of `ToolCallProxy.call()`. The engine reads `where` only from
   `params` and `when` only from `context`. Neither falls back to the other,
   and an absent context field fails every condition except `absent`/`present`
   — so a `when` condition can never be satisfied by a same-named parameter.

2. **Pinned context.** `ToolCallProxy(engine, pinned_context={...})` fixes
   context at construction time, from a source the agent cannot reach — a
   server-side session record, a verified credential, a deployment environment
   variable. Pinned values are merged **over** per-call context on every call,
   so they cannot be changed by anything on the request path.

3. **Override attempts are errors.** A `call(..., context=...)` naming a
   pinned field raises `ContextError` rather than being silently discarded.
   An attempt to set a pinned field is indistinguishable from the bypass it
   would be if pinning were absent, so it fails closed and loudly instead of
   being ignored.

4. **`pinned_context` in the policy file.** Fields listed there must be
   supplied to `ToolCallProxy(pinned_context=...)` or construction fails. This
   is what turns the guarantee from a convention into a precondition: a policy
   that gates on `trust` cannot be deployed with `trust` arriving from an
   unpinned per-call source.

```yaml
version: 2
default_action: deny

# Enforcement will not start unless these are supplied out of band.
pinned_context: [agent, trust]

rules:
  - name: untrusted-agents-read-only
    resource: "**"
    action: deny
    when:
      trust:
        equals: untrusted
    where:
      mode:
        not_equals: read
```

```python
# `trust` is derived from the session, not from anything the model emitted.
proxy = ToolCallProxy(
    engine,
    pinned_context={"agent": session.agent_id, "trust": session.trust_level},
)
```

### What is *not* guaranteed

Stated plainly, because these are the ways a deployment can still be wrong:

- **Unpinned `when` fields are the integrator's responsibility.** A `when`
  field absent from `pinned_context` is read from per-call context, and
  HYDRACUDA cannot tell whether the integrator sourced that value from a
  session record or from model output. `hydracuda validate` reports every
  unpinned `when` field for exactly this reason. Pin anything security-relevant.

- **`PolicyEngine.evaluate()` enforces nothing.** It is a pure decision
  function and will evaluate any context handed to it. The trust boundary is
  `ToolCallProxy`. Code calling the engine directly — including `plan` and
  `test`, which are read-only by design — takes on the boundary itself.

- **The engine matches parameters literally.** Conditions test the value as the
  engine received it. A `deny` on `\.\.` does not catch `%2e%2e`, and a deny on
  `/etc/` does not catch a symlink pointing there. Closing that gap is the
  adapter's job, and `local_tools` does it: declared `path_parameters` are
  canonicalized and confined to `root` before evaluation, and the canonical
  value is what executes. Deny patterns are then defence in depth on top of
  confinement, not the control itself. See
  [Normalization](#normalization-and-canonicalization).

- **An adapter that declares no `path_parameters` canonicalizes nothing.** The
  omission is silent by construction — HYDRACUDA cannot know which of your
  parameters is a path. A custom adapter that skips `normalize()` gets literal
  matching and nothing more.

- **Canonicalization is a check, not a lock.** The path is resolved, confined,
  and then handed to the handler. Anything that changes the filesystem between
  those two moments — a symlink swapped in after the check — is outside what a
  decision engine can see. Narrow `root` rather than relying on the resolve
  step to survive a racing writer.

- **The agent picks which resource to request.** It cannot invent a resource,
  but it will find the most permissive one your rules allow. A broad
  `resource: "**"` with `action: allow` grants everything an adapter declares,
  present and future. Use `hydracuda plan` to see the full decided surface
  rather than inferring it from the rule list.

- **`mode: shadow` enforces nothing.** It records the decision and executes the
  call anyway. That is its purpose, and it means shadow mode is not a security
  boundary — it is a measurement tool.

---

## Conditions (`where` / `when`)

`where` tests the request parameters, which the agent controls. `when` tests
the evaluation context, which it must not — see [Trust model](#trust-model).
Both use the same grammar: a map of field name to a map of operators.

```yaml
where:
  path:
    matches: ["^/etc/"]
    not_matches: ["^/etc/hydracuda/"]
  recursive:
    equals: true
```

All fields must match, and all operators within a field must match — it is
`AND` throughout. An empty or omitted block matches everything.

| Operator | Argument | True when |
|---|---|---|
| `matches` | regex, or list of regexes | any regex finds a match in `str(value)` |
| `not_matches` | regex, or list of regexes | no regex finds a match |
| `equals` | any scalar | value equals the argument |
| `not_equals` | any scalar | value differs from the argument |
| `in` | list | value is in the list |
| `not_in` | list | value is not in the list |
| `present` | `true` / `false` | the field is / is not supplied |
| `absent` | `true` / `false` | the field is not / is supplied |

Regexes are **unanchored** — `matches: ["/etc/"]` is a substring test. Anchor
with `^` and `$` when you need to. Patterns are compiled at load time, so a
malformed regex is a policy validation error, not a runtime surprise.

A field that is absent from the subject fails every operator except
`present: false` and `absent: true`. So a `deny` rule keyed on a parameter
the request never supplied does not fire, and evaluation continues to the
next rule.

This is uniform and deliberate — it is what stops a `when` condition from being
satisfied by a same-named request parameter — but it has a consequence that
catches people out. A negative operator on a blocking rule reads as broader
than it behaves:

```yaml
# Reads as "deny writes outside the workspace".
# Behaves as "deny writes to a stated path outside the workspace".
- resource: filesystem.write_file
  action: deny
  where:
    path:
      not_matches: ["^/workspace/"]
```

A request with no `path` at all does not match, so this rule does not stop it.
Adding `present: true` alongside the negative operator documents the intent but
changes nothing, because operators are ANDed and the rule still needs the field
to be there. Cover the case with a second rule:

```yaml
- resource: filesystem.write_file
  action: deny
  where:
    path:
      absent: true
```

`hydracuda validate` reports the missing pairing as
`negative-condition-fails-open`.

Comparisons other than `matches` / `not_matches` use the YAML-parsed value,
so types must agree: `equals: true` does not match the string `"true"`.

---

## Adapters

An adapter declares the resource surface — what exists — separately from the
policy that decides what is permitted.

```yaml
adapters:
  - name: local
    type: local_tools
    resources:
      - filesystem.read_file
      - database.delete_record
      - shell.execute
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique instance name. |
| `type` | yes | Registered adapter type. |
| `resources` | no | Resources this instance declares. Some adapter types discover these themselves. |
| `config` | no | Free-form map handed to the adapter implementation. |

`hydracuda plan` walks the declared resource surface and reports the decision
for each entry, which is what makes an adapter's `resources` list worth
maintaining.

A resource no adapter declares is refused at the boundary before any rule is
consulted, with rule `adapter:undeclared` in the audit log. This is not a policy
denial — the resource does not exist — so a broad `resource: "**"` allow rule
cannot reach it.

### The interface

An adapter is a subclass of `hydracuda.Adapter` implementing two members and
optionally overriding two more:

| Member | Required | Purpose |
|---|---|---|
| `name` | yes | Instance name, used in diagnostics and audit records. |
| `resource_specs()` | yes | The `ResourceSpec` list this adapter exposes. |
| `normalize(resource, params)` | no | Canonicalize a request before evaluation. Identity by default. |
| `execute(resource, params)` | no | Perform the action. Only reached once policy allowed it. |

A `ResourceSpec` carries `name`, `description`, `parameters`, and
`path_parameters`. The last of these is security-relevant: it names the
parameters holding filesystem paths, and naming them is what causes them to be
canonicalized.

### Normalization and canonicalization

`normalize()` runs **before** evaluation, and its output is what both the engine
and the handler see. Two properties follow, and both are load-bearing:

- **The canonical value is the executed value.** Checking one string while
  passing a different one to the handler would not be a check at all.
- **Confinement beats blocklisting.** A path resolved with `realpath` and then
  required to sit under a root cannot escape via `..`, via a symlink, or via any
  encoding of either, because safety is decided by where the path lands rather
  than by what it looks like.

`normalize()` raises `CanonicalizationError` for input it cannot canonicalize
safely. The proxy treats that as a denial: audited under rule
`adapter:canonicalization`, then raised as `PermissionError`. It is enforced
even under `mode: shadow` — shadow mode trials a *policy*, and a request whose
target is unknown has no verdict to shadow.

### `local_tools`

The built-in adapter type. Exposes local Python callables under declared
resource names.

| Config key | Default | Meaning |
|---|---|---|
| `root` | none | Confines every declared path parameter. A value resolving outside it is refused. |
| `reject_encoded_paths` | `true` | Refuse percent-encoded path input outright. |
| `resolve_symlinks` | `true` | Resolve symlinks before the confinement check. |

```yaml
adapters:
  - name: fs
    type: local_tools
    resources: [read_file, write_file]
    config:
      root: /workspace
```

Set `root` whenever the tools touch the filesystem. Without it, `..` and
symlinks are still resolved, but nothing bounds where the result may land.

`reject_encoded_paths: true` refuses rather than decodes, because decoding would
silently rewrite the caller's request into a different one. Setting it to
`false` leaves the characters literal — `%2e%2e%2f` addresses a file with that
name — and relies on `root` for safety.

Unicode is handled the same way: NFC folding is applied, because both spellings
resolve to the same file, but NFKC compatibility characters (a fullwidth
solidus, say) are recorded in the audit note and **not** folded, since folding
would change which file is addressed.

Building an adapter from a policy file — which is what `validate` and `plan` do
— declares the resource surface without handlers. Such an adapter can be
planned against; it cannot execute.

---

## Introspection

Two read-only commands. Neither executes a tool, writes an audit record, or
needs the dashboard running.

```
hydracuda validate [policy.yaml] [--strict]
hydracuda plan     [policy.yaml] [--reasons]
```

Both default to `hydracuda.yaml`. `validate` exits non-zero on an error, and on
a warning too under `--strict`. `check` is a deprecated alias for `validate`.

A third read-only command, `hydracuda test`, is specified in
[Test cases](#test-cases-tests) but not implemented in 0.3.0.

### `validate`

Schema problems are already hard errors at load time, so everything `validate`
reports is a policy that parses but does not mean what it appears to.

| Code | Level | Meaning |
|---|---|---|
| `adapter-unbuildable` | error | An `adapters` entry names an unknown `type` or an unrecognized `config` key. |
| `unpinned-when-field` | warning | A rule tests a `when` field absent from `pinned_context`. See [Trust model](#trust-model). |
| `negative-condition-fails-open` | warning | A blocking rule uses `not_matches`/`not_equals`/`not_in` with no companion rule covering the field being absent. |
| `unreachable-rule` | warning | An earlier rule matches these resources first, so this rule never fires. |
| `conflicting-rules` | warning | Two rules cover the same resources under the same conditions and disagree. The earlier one wins. |
| `duplicate-rule` | warning | Same resources, same conditions, same action as an earlier rule. |
| `duplicate-rule-name` | warning | Two rules share a `name`, making an audit record ambiguous. |
| `unmatched-rule-resource` | warning | A rule's resource pattern matches nothing any adapter declares. |
| `shadow-mode` | warning | `mode: shadow` enforces nothing. |
| `default-allow` | warning | `default_action: allow` fails open for anything no rule mentions. |
| `no-rules` | warning | Every request falls through to `default_action`. |

Unreachability is only reported when it is provable. A broad pattern above a
narrow one is reported; two overlapping wildcard patterns are not, because a
false accusation against a working policy is worse than a missed one.

### `plan`

Walks the declared resource surface — every resource an adapter declares, plus
every non-wildcard rule resource — and prints the decision for each.

```
  ALLOW   read_file      allow-file-reads  [conditional: block-sensitive-paths]
  DENY    delete_record  block-destructive-deletes
  REVIEW  execute_shell  shell-requires-approval
```

Each resource is evaluated **with no parameters and no context**, which is all a
policy file supplies on its own. Rules that could change the outcome for a real
call are listed as `conditional` rather than guessed at, so the output is never
mistaken for a claim about every possible request.

---

## Test cases (`tests:`)

> **Status: specified, not yet implemented.** The 0.3.0 loader rejects `tests:`
> as an unrecognized key, and there is no `hydracuda test` command. This section
> is the reviewed schema that 0.4.0 implements against. Nothing here describes
> current behaviour — see [Top-level keys](#top-level-keys) for what loads today.

A policy file states what is allowed. A `tests:` block states what the author
*believed* it allowed, in a form the tool can check.

This is worth having because the failures Phase 1 fixed were not wrong rules —
they were rules that read as active and were not. A key typo'd to
`parameterRules` parsed and did nothing; `rate_limit` was accepted and
discarded; `mode: shadow` computed a decision and blocked nothing. Strict
validation catches the misspelling class. It cannot catch a correctly spelled
rule in the wrong order, and rule order is first-match-wins.

```yaml
tests:
  - name: agent-may-read-project-files
    resource: filesystem.read_file
    params:
      path: /workspace/src/main.py
    context:
      agent: research-bot
      trust: verified
    expect: allow

  - name: traversal-is-denied-even-for-verified-agents
    resource: filesystem.read_file
    params:
      path: /workspace/../etc/passwd
    context:
      agent: research-bot
      trust: verified
    expect: deny
    expect_rule: block-sensitive-paths
```

### Test case keys

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique label. Identifies the case in output. |
| `resource` | yes | An exact resource name, **never a pattern**. A test asserts one request. |
| `expect` | yes | `allow`, `deny`, `review`, or `refused`. |
| `params` | no | The request parameters, as literal values. Omitted means no parameters. |
| `context` | no | The evaluation context, as literal values. |
| `expect_rule` | no | `name` of the rule that must produce the decision. |

Any other key is a **hard error**, as everywhere else in the format.

### How `params` / `context` relate to `where` / `when`

They are the two sides of the same pair. A rule describes a *set* of requests
using operators; a test case describes *one* request using values.

| Rule key | holds | Test case key | holds | Controlled by |
|---|---|---|---|---|
| `where` | operators on parameters | `params` | literal parameter values | the **agent** |
| `when` | operators on context | `context` | literal context values | the **integrator** |

The names deliberately differ from `where` / `when`. Reusing them would put
operator maps and literal values under the same key, so this:

```yaml
# WRONG — this is not a condition. It sets `path` to the literal mapping
# {matches: [...]}, which matches no rule and makes the case pass or fail for
# a reason that has nothing to do with the policy.
params:
  path:
    matches: ["^/workspace/"]
```

...would be a silently wrong test rather than a schema error. `params` and
`context` are also the names the [trust model](#what-the-agent-controls) table
and `ToolCallProxy.call()` already use, so a test case reads as the call it
stands in for.

The trust boundary still means what it means. `params` is the untrusted side, so
tests should carry the hostile values you expect an agent to try — that is the
main thing this block is for. `context` is the trusted side, and a test setting
it is not a bypass: `hydracuda test` calls `PolicyEngine.evaluate()`, which is a
pure function with no proxy and no `ContextError`, exactly as `plan` does. See
[What is *not* guaranteed](#what-is-not-guaranteed).

### `expect: refused`

Two runtime outcomes are not policy decisions: a resource no adapter declares,
and a path that fails canonicalization or root confinement. Both are refused at
the adapter boundary before any rule is consulted, and both are enforced even
under `mode: shadow`.

`refused` is a separate expectation rather than folded into `deny` because they
are different mechanisms, and a test that accepts either would pass for the
wrong reason — reporting a policy rule as the control when confinement was
actually doing the work, or the reverse.

```yaml
  - name: undeclared-tools-are-refused-not-evaluated
    resource: filesystem.chmod
    expect: refused
```

Supporting `refused` means `hydracuda test` runs adapter normalization before
evaluation, mirroring the order the proxy uses. **That has a cost worth stating:
canonicalization touches the filesystem**, so a case with path parameters is
only as reproducible as the tree it runs on — a symlink or a missing `root`
changes the answer. That is a property of canonicalization, not of the test
runner (see [Canonicalization is a check, not a
lock](#what-is-not-guaranteed)). Point `root` at a fixture directory committed
alongside the policy when you need a case to mean the same thing on every
machine.

### `expect_rule`

Optional, and the reason to bother with it: `expect` alone cannot distinguish
the right answer from the right answer for the wrong reason. With first-match
wins, a rule reordered above another can leave every `expect` satisfied while
the policy has changed meaning. `expect_rule` pins the decision to a named rule,
so that reordering fails a test instead of passing silently.

There is deliberately no `expect_reason`. Reason strings are prose for humans
and the audit log; asserting on them would make every wording change a test
failure, which teaches people to stop writing tests.

### Names

`name` is required, and duplicate names are a **hard error**.

This is stricter than rules, where `duplicate-rule-name` is only a warning, and
the asymmetry is intentional: rule names may be generated by version 1
translation, but test names are always hand-written. Duplicates also matter more
here, because the output is per-case pass/fail and two cases sharing a name make
that report unreadable. This is the same defect as the v0.2.0 audit records that
could not say which of several identically named deny patterns had fired.

### Diagnostics

Reported by `validate` and by `test` before any case runs, using the codes and
levels of the [`validate` table](#validate).

| Code | Level | Meaning |
|---|---|---|
| `test-duplicate-name` | error | Two cases share a `name`. |
| `test-resource-is-a-pattern` | error | `resource` contains `*` or `**`. A test asserts one request. |
| `test-undeclared-resource` | warning | No adapter declares this `resource` and `expect` is not `refused`, so the case cannot pass. |
| `test-missing-pinned-context` | warning | `pinned_context` names a field the case does not set. Construction fails without it at runtime, so the case is evaluating a state that cannot occur. |
| `test-unread-context-field` | warning | The case sets a `context` field no rule's `when` reads. Usually a typo, and a typo'd field name makes the case assert something other than what it appears to. |
| `shadow-mode` | warning | Under `mode: shadow` every `expect: deny` can pass while nothing is blocked in production. Same code as `validate` reports, for the same reason. |

`test-missing-pinned-context` is the one worth dwelling on. It is the `tests:`
block's version of `unpinned-when-field`: a policy that gates on `trust` and a
test suite that never sets `trust` will agree with each other and tell you
nothing about the deployment.

### Running

```
hydracuda test [policy.yaml]
```

Exit code `0` when every case passes, `1` when any case fails, and the usual
non-zero on a load or schema error. Output is one line per case plus a summary
count, so a failure names the case, the expected decision, and the decision that
was actually produced.

`test` is read-only in the same sense `plan` is: no tool is executed, no audit
record is written, no network call is made, and the clock is not read. The
policy file is the only input. That is what makes a `tests:` block something CI
can run on every commit.

### Out of scope

Named because a test block invites all of it, and none of it is in this schema:

- **No fixtures, setup, or teardown.** Cases are independent and declarative.
- **No handler mocking.** Nothing is executed, so there is nothing to mock.
- **No assertions on audit rows.** `test` writes no audit record.
- **No reason-string matching.** See [`expect_rule`](#expect_rule).
- **No separate test file.** Tests live with the policy they describe, because a
  policy copied without its expectations is a policy with none.
- **No test-only rules or overrides.** A test that changes the policy to pass is
  not a test of the policy.

---

## Dashboard

The dashboard is optional and downstream. HYDRACUDA runs fully headless: the
core runtime and both CLI commands behave identically whether it is installed,
running, or absent.

```
pip install hydracuda[dashboard]
HYDRACUDA_AUDIT_DB=.hydracuda/audit.db python -m dashboard.app
```

It holds no policy state. It never imports `hydracuda`, never reads a policy
file, and cannot influence a decision — its only input is the audit database
named by `HYDRACUDA_AUDIT_DB`. The dependency runs one way, and the test suite
asserts that in both directions rather than leaving it to convention.

Its SQLite connections are opened `mode=ro`, so read-only is enforced by the
driver. That matters because the audit log has a live writer: a read-write
connection can create journal files beside it and take locks that block the
proxy.

Rows record whether a decision was **enforced**. Under `mode: shadow` a denied
call is logged and then executed anyway, so a decision count on its own would
read as calls that were stopped. The dashboard shows enforcement per row and
banners the total, because "40 denies" and "40 calls blocked" are not the same
claim.

### Audit records are untrusted input

Anything you build on the audit log has to treat its text fields as hostile.
`tool` is whatever name the agent asked for, `reason` quotes that name back, and
`params` is the raw arguments the agent supplied. A blocked call is still a
recorded call, so refusing an action does not keep its payload out of the log.

This is not hypothetical: interpolating those fields into `innerHTML` was a
stored cross-site scripting bug in the bundled dashboard up to and including
v0.2.0. One tool call named `<img src=x onerror=...>` gave the attacker two
injection points, because the engine's own reason string embedded the name. The
bundled page now escapes every value it renders, and the test suite fails on any
unescaped interpolation rather than on a list of the fields already fixed.

---

## Version 1 compatibility

A `version: 1` file is translated into version 2 rules at load time and then
evaluated by the same engine — there is only one code path. Decisions are
identical to v0.2.0.

```yaml
version: 1
mode: enforce
tools:
  read_file:
    allow: true
    parameter_rules:
      path:
        deny_patterns: ["/etc/", "\\.\\."]
  delete_record:
    allow: false
    reason: "Destructive operation."
  execute_shell:
    allow: "review"
```

Translation, per tool, in order:

| v1 form | v2 rule |
|---|---|
| `allow: false` | `action: deny` on the tool name |
| `allow: "review"` | `action: review` on the tool name |
| `allow: true` + `parameter_rules` | one `action: deny` rule per `deny_patterns` entry, in file order, then a trailing `action: allow` rule |
| tool absent from `tools` | falls through to `default_action: deny` |

Three v1 behaviours are worth calling out:

- Per-tool `reason` is now honoured. In v0.2.0 it was parsed and discarded, so
  a denial always read `tool blocked by policy` regardless of what the policy
  said.
- `audit.path` (the nested form in the v0.2.0 README) is now honoured as a
  deprecated alias for `audit_path`. In v0.2.0 it was silently ignored and the
  audit log went to the default location instead. Prefer `audit_path`.
- **`rate_limit` is now a load error.** See [Rejected keys](#rejected-keys).
  A v1 policy carrying it will not load until the key is removed. Removing it
  changes no decision, because it never affected one.

Version 1 has no `when` conditions, so the context trust question in
[Trust model](#trust-model) does not arise for v1 policies: they decide purely
on resource name and parameters.

Version 1 files cannot use `rules`, `adapters`, `default_action`, or
`pinned_context`. Set `version: 2` to use those.
