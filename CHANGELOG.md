# Changelog

## 0.4.0 — 2026-09-10 — core extraction

The decision engine moves into a standalone Rust crate and the Python package
becomes a binding over it, with the pure-Python engine kept permanently as the
fallback. Nothing about the public Python API changes, and
`tests/test_backend_parity.py` plus a committed differential corpus hold the two
engines to identical decisions.

Distribution is unchanged in this release: the PyPI wheel is still pure Python,
and the `hcuda` binary is built from a checkout rather than downloaded. Publishing
prebuilt platform wheels and binaries is the next release.

### Added

- `tests:` blocks, specified in 0.3.1 and implemented here. A policy file states
  what is allowed; a `tests:` block states what the author *believed* it allowed,
  as cases the tool can check — `resource`, `params`, `context`, `expect` of
  `allow`/`deny`/`review`/`refused`, and an optional `expect_rule`. Strict
  validation catches a misspelled key; it cannot catch a correctly spelled rule in
  the wrong order, and rule order is first-match-wins. `expect_rule` is what
  closes that gap: a rule reordered above another leaves every `expect` satisfied
  while the policy has changed meaning.

  Run with `hydracuda test [policy.yaml]`, one line per case plus a summary count,
  exit 0 when every case passes and 1 when any fails. Read-only in the same sense
  `plan` is: nothing is executed, no audit record is written, the clock is not
  read, and no file is opened beyond the policy itself — so a `tests:` block is
  something CI can run on every commit and get the same answer.

  Version 2 only. A version 1 file gets no new surface, and `tests` there is an
  unrecognized key as it was before.

  Five diagnostics come with it, reported by `validate` and by `test` before any
  case runs: `test-duplicate-name`, `test-resource-is-a-pattern`,
  `test-undeclared-resource`, `test-missing-pinned-context` and
  `test-unread-context-field`. The first two are errors, which stop the run.

- `hcuda`, a standalone binary with `validate`, `plan` and `test` and no Python,
  no network and no runtime dependencies. Named `hcuda` rather than `hydracuda`
  because the Python package's console script already owns that name, and two
  executables sharing it would resolve by `PATH` order — silently running a
  different implementation than the one asked for.

  Its output is byte-identical to `hydracuda`'s apart from two lines, and
  `tests/test_cli_parity.py` holds it to that by running both and diffing.
  `hcuda validate` states the one check it cannot perform: building a declared
  adapter needs the type registry, which lives in the Python package, so that gap
  is printed rather than quietly skipped.

- `--engine python|rust` on `validate`, `plan` and `test`, and the engine named in
  every one of their outputs. One engine runs, not both, and the flag beats
  `HYDRACUDA_ENGINE` — a consumer pinning `HYDRACUDA_ENGINE=python` for
  reproducibility gets the same treatment from the CLI that the library gives it.
  `hcuda` refuses a `python` pin with an error naming `python -m hydracuda test`,
  rather than producing Rust decisions under a label nobody asked for.

  `hydracuda test --compare-engines` opts into running both and reporting any
  disagreement, exiting 3 — distinct from 1, because two engines diverging is a
  bug in HYDRACUDA and not a finding about the policy, and a CI job has to be able
  to tell those apart.

- `python -m hydracuda`, equivalent to the `hydracuda` console script. Needed
  because `hcuda` points at it by name, and that instruction has to work on a
  machine where the console script was never put on `PATH`.

- The decision engine can now run compiled. `hydracuda._core`, a PyO3 extension
  over the `hydracuda-core` crate, is used when it is present; the pure-Python
  engine is used when it is not. Both are supported, and both stay: a platform
  with no wheel installs the universal one and behaves identically, with no Rust
  toolchain needed. `hydracuda.engine_backend()` reports which is live and
  `HYDRACUDA_ENGINE=python|rust` forces one.

  What crosses into Rust is the verdict only — the `(action, reason, rule)`
  triple. Loading, validation, adapters, the proxy, the audit log and the
  `Decision` object are unchanged Python, so nothing about the public API moves.
  The full test suite passes on both engines and `tests/test_backend_parity.py`
  runs both in one process over the differential corpus, comparing every field of
  every decision.

  One deliberate difference: a request parameter the compiled engine cannot
  represent — a tuple, a set, an arbitrary object — is refused with an error
  rather than coerced. No policy file produces such a value. Coercing would mean
  a `matches` rule comparing against a different string than before, which is a
  rule that quietly stops firing.

  Nothing published changes yet: the wheels on PyPI remain pure Python. Building
  the extension locally is `python scripts/build_extension.py`.

### Documentation

- `docs/policy-spec.md`'s `tests:` section is no longer marked unimplemented, and
  its example is now a complete policy the loader accepts rather than a fragment.

  Two things in it were corrected against the implementation. Only one of the two
  refusals it described is reachable from a policy file: `build_adapter` declares
  resources with no `path_parameters` and `normalize` canonicalizes only those, so
  an adapter built from an `adapters:` block cannot refuse on confinement. A case
  expecting that fails against whatever the rules decide — assert traversal with a
  `deny` rule instead. The consequence is worth having, and is now stated: nothing
  is canonicalized, so `test` reads no files and is reproducible anywhere.

  Its `## Introspection` section said there were two read-only commands and that
  `hydracuda test` was unimplemented. Three, and it is.

  And `test-duplicate-name` and `test-resource-is-a-pattern` are hard errors
  reported as diagnostics rather than load failures. The specification assigns them
  codes and levels, and a diagnostic that can never fire — because loading already
  refused the file — is worse than no diagnostic. They stay hard: an error-level
  finding exits non-zero in both `validate` and `test`.

- README documents `test`, `--engine`, `--compare-engines` and `hcuda`, and its
  sample `validate`/`plan` output now shows the `Engine:` line the commands
  actually print. A README transcript that no longer matches the command is how a
  reader concludes their install is broken.

- `examples/policy.yaml` has a `tests:` block: six cases covering the ordering the
  file's comments already claimed mattered. The example previously asserted that
  the narrow deny rules must sit above the broad allow rule and left the reader to
  take that on faith; now reordering them fails. It is also what
  `tests/test_cli_parity.py` diffs `hcuda test` against, so a shipped document
  users copy is the fixture rather than a synthetic one.

## 0.3.1 — 2026-09-10

### Fixed

- Version 1 policies: `allow: 0` loaded without complaint and permitted the
  tool. Validation compared by value, where `0 == False` passes, but the branch
  that produces a deny rule compared by identity — and no integer is `False`, so
  the tool fell through to an allow rule. A tool written down as blocked ran, its
  `reason:` was discarded, and `hydracuda validate` reported no errors and no
  warnings. `allow: 0.0` behaved the same way.

  `allow` must now be a genuine boolean or the string `"review"`, so an integer
  is a load error instead of a silent permission. This also rejects `allow: 1`,
  which previously allowed by accident: a policy using integers where the schema
  documents `true`/`false` now fails to load rather than being guessed at, which
  points at the generator that emitted them. The YAML spellings of a boolean are
  unaffected — `no`, `off` and `false` all still deny, as do `yes`, `on` and
  `true` for allow.

  Present since 0.1.0. Only reachable through the version 1 `tools:` format, and
  only with a value no documentation or `hydracuda init` template has ever shown,
  so a hand-written policy is unlikely to hit it; a policy generated from a
  source that spells booleans as 0/1 — a SQLite column, a CSV, a template
  rendering an int — is the case that would.

## 0.3.0 — 2026-09-09 — Phase 1: policy as code

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

- **The published file list is now explicit, which is how the vulnerable file
  reached PyPI.** There was no sdist configuration, so hatchling's default —
  every file git does not ignore — shipped the dashboard in the v0.2.0 source
  distribution even though the wheel excluded it. The sdist now lists what it
  contains: `src/hydracuda`, `tests`, `examples`, `docs`, and the three root
  documents. What stopped shipping: `dashboard/`, the retired
  `deprecation/baracuda` package, and `.github/workflows`. `tests/test_packaging.py`
  fails if any of those returns, so a new directory in the repository cannot
  become part of a release by default.
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
- The dashboard is a development tool run from a checkout, and is documented as
  such. It is in neither artifact, so the `dashboard` extra installs Flask for a
  `pip install -e ".[dashboard]"` clone — it does not install the dashboard.
  Point it at any project's log with `HYDRACUDA_AUDIT_DB`.

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
