# Changelog

## Unreleased — Phase 1: policy as code

Policy moves into an external, version-controllable file; adapters declare what
exists separately from rules declaring what is allowed; two read-only CLI
commands make a policy inspectable before it runs. The core decision loop is
unchanged — `tests/test_migration_parity.py` pins the ALLOW/DENY/REVIEW outcomes
and reason strings recorded from v0.2.0 and asserts they still hold.

### Security

- **Fixed a stored cross-site scripting vulnerability in the bundled dashboard.**
  Audit values were interpolated into `innerHTML` unescaped. A tool name is
  chosen by the agent being policed, and the engine's reason string quotes that
  name back, so a single tool call named `<img src=x onerror=...>` gave two
  injection points; script then ran when a human opened the dashboard.

  Affected: the dashboard as introduced on 2026-07-25, through v0.2.0. The
  dashboard is **not** in the published wheel, so `pip install hydracuda` never
  delivered the vulnerable file — but it is in the v0.2.0 **sdist** and in the
  public repository, so anyone who built from source or cloned the repo and ran
  `python -m dashboard.app` was exposed.

  Impact is bounded: the server binds `127.0.0.1` with `debug=False` and has no
  auth, cookies, or tokens to steal, so this is same-origin access to data the
  viewer already had plus a browser foothold on localhost. Not remote code
  execution. Exploitation requires a local dashboard and user interaction.

  Workaround for anyone remaining on v0.2.0: do not run the dashboard.

  Every value the page renders was audited, not only the field that prompted the
  fix. All of it is escaped, the action CSS class is restricted to the three
  known actions, and a test now fails on *any* unescaped interpolation rather
  than on a list of the fields already fixed.

- Audit records are documented as untrusted input. A blocked call is still a
  recorded call, so denying an action does not keep its payload out of the log —
  anything built on that log has to escape `tool`, `reason`, and `params`.
- Dashboard SQLite connections are opened `mode=ro`. The audit log has a live
  writer, and a read-write handle could create journal files beside it and take
  locks that block the proxy.
- Adapters canonicalize declared path parameters before matching, and confine
  them to a configured root. A `..` deny can no longer be bypassed by percent
  encoding or a symlink, and the canonical value is what gets executed — not
  just what gets matched.
- `pinned_context` makes trust assumptions enforceable: a context field listed
  there cannot be supplied or overridden per call, and an attempt raises
  `ContextError`. `hydracuda validate` warns for every `when` field that is not
  pinned.
- A typo'd key no longer fails open. Any unrecognized key in a policy file is a
  load error with a suggested spelling, so a rule you believe is active cannot
  silently not exist.

### Added

- External policy format, `version: 2`: ordered `rules` with `resource`,
  `action`, `where` (request parameters, agent-controlled) and `when`
  (evaluation context, integrator-controlled), plus `default_action`, which
  defaults to `deny`.
- `adapters` block declaring the resource surface, with an `Adapter` ABC and a
  first concrete `local_tools` adapter. Adding a tool and permitting it are now
  separate acts.
- Resource namespaces: dot-separated segments with `*` for one segment and `**`
  for zero or more.
- `hydracuda validate` — schema errors plus eleven diagnostics, including
  unreachable rules, conflicting rules, unpinned `when` fields, and blocking
  rules that a missing field slips past. `--strict` treats warnings as failures
  for CI.
- `hydracuda plan` — the decision for every declared resource, with no execution
  and no audit write. Resources whose outcome depends on the request are flagged
  rather than guessed at.
- Audit columns `rule`, `mode`, `enforced`, and `normalization`. Existing
  databases are migrated in place with `ALTER TABLE` on first write.
- `docs/policy-spec.md`: the policy format, the trust model, adapters, the
  diagnostic table, and the dashboard boundary.

### Changed

- `mode: shadow` is wired up: the decision is computed and logged, and the call
  executes anyway. It previously had no effect. `validate` warns that a shadow
  policy enforces nothing.
- Boundary refusals — an undeclared resource, or a path that fails
  canonicalization — are enforced even under `mode: shadow`, because shadow mode
  trials a policy rather than disabling the proxy.
- Version 1 policy files are translated to version 2 rules at load time and
  evaluated by the same engine. There is one code path, and decisions are
  identical to v0.2.0.
- `hydracuda check` is a deprecated alias for `validate`. It also used to raise
  `TypeError` on any version 2 policy.
- Generated rule names from a version 1 file are indexed
  (`legacy:read_file:path:deny_pattern[0]`). Several deny patterns on one tool
  previously produced identically named rules, leaving an audit record unable to
  say which pattern fired.
- The dashboard reports whether each decision was **enforced**, and banners the
  unenforced total. A shadow-mode deny previously looked identical to a blocked
  call, so a count of denies read as a count of calls stopped.
- README corrected. `parameterRules`, `denyPatterns`, and `rateLimit` were
  documented but never read by the loader; `audit: {path: ...}` was documented,
  never read, and is now honoured as an alias for `audit_path`. Every policy
  example in the README and the spec is parsed by the real loader in
  `tests/test_docs.py`, which is how that drift is prevented rather than
  re-fixed.
- Dashboard: "Policy Hit Rates" showed top tools, so it says Top Tools.

### Removed

- `rate_limit` is rejected at load time. It was accepted and discarded in
  v0.1.0–v0.2.0, so a policy file asserted a control that did not exist. Rate
  limiting is stateful and belongs in the calling layer.

### Fixed

- Dashboard: `?limit=abc` returned a 500, and `?limit=` was unbounded. Query
  arguments are parsed defensively and capped.
- Dashboard: database connections leaked on any query error, because closing
  happened only on the success path.
- Dashboard: a database that exists but has no `audit_log` table yet — the state
  the proxy leaves before its first write — returned a 500 instead of the "no
  decisions" response.
- Dashboard: rows predating the `enforced` column count as enforced, which is
  what v0.2.0 did.

### Unchanged

- The public Python API. `load_policy`, `PolicyEngine`, and `ToolCallProxy.call`
  keep their existing signatures and behaviour; `ReviewRequired` subclasses the
  `NotImplementedError` that v0.2.0 raised, so existing handlers still catch it.
- The license, the PyPI package name, and the offline guarantee. Policy
  evaluation is local: no network call in the decision loop.

## v0.2.0 — 2026-07-25

- Added local dashboard for audit log visualization (`python -m dashboard.app`)
- Dashboard shows allow/deny/review counts, per-tool hit rates, searchable log table
- Read-only, single-user, no auth — ships as part of the open-source package

## v0.1.0 — 2026-05-30

- Initial release
- Policy engine with three-decision model: allow, deny, review
- YAML policy file parser with validation
- Parameter-level deny patterns using Python regex
- SQLite audit log for all decisions
- CLI: `hydracuda init` and `hydracuda check`
