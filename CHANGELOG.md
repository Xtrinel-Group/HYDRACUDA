# Changelog

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
