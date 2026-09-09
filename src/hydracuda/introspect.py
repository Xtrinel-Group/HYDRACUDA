"""Read-only policy introspection.

Backs `hydracuda validate` and `hydracuda plan`. Everything here is pure
analysis of an already-loaded policy: no tool is executed, no audit record is
written, no file is touched. A policy author can run either command against
production policy without side effects.

`validate` answers "is this policy well-formed, and does it say what you think
it says". `plan` answers "what does it decide". They are separate because a
policy can be perfectly valid and still decide something surprising.
"""

from dataclasses import dataclass, field
from typing import Any

from hydracuda.adapters import AdapterError
from hydracuda.adapters.registry import build_adapter
from hydracuda.conditions import pattern_subsumes, resource_matches
from hydracuda.engine import PolicyEngine
from hydracuda.policy import Policy, Rule

ERROR = "error"
WARNING = "warning"

#: Operators that an absent field does not satisfy, even though the English
#: reading of them suggests it would. See `_check_negative_conditions`.
_NEGATIVE_OPERATORS = frozenset({"not_matches", "not_equals", "not_in"})

#: Actions where a rule failing to match means the call is not stopped.
_BLOCKING_ACTIONS = frozenset({"deny", "review"})


@dataclass(frozen=True)
class Diagnostic:
    """One finding about a policy."""

    level: str
    code: str
    message: str
    location: str | None = None

    def format(self) -> str:
        where = f" [{self.location}]" if self.location else ""
        return f"{self.level}: {self.code}{where}\n  {self.message}"


@dataclass(frozen=True)
class PlanEntry:
    """The decision for one resource on the declared surface."""

    resource: str
    action: str
    rule: str | None
    reason: str
    #: Rules that match this resource and carry `where`/`when` conditions. The
    #: reported action holds for a call with no parameters and no context; these
    #: are the rules that could change it for a real call.
    conditional_rules: tuple[str, ...] = ()

    @property
    def conditional(self) -> bool:
        return bool(self.conditional_rules)


@dataclass
class Report:
    """The result of validating a policy."""

    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.level == ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.level == WARNING]

    @property
    def ok(self) -> bool:
        return not self.errors


def _location(index: int, rule: Rule) -> str:
    return f"rules[{index}] {rule.label}"


def _conditions_key(rule: Rule) -> tuple[Any, Any]:
    """A comparable form of a rule's conditions.

    Normalized condition blocks hold only YAML scalars and lists — regexes are
    kept as pattern strings — so sorted items compare reliably.
    """

    def normalize(block: dict) -> tuple:
        return tuple(
            (field_name, tuple(sorted(ops.items(), key=lambda kv: kv[0])))
            for field_name, ops in sorted(block.items())
        )

    return normalize(rule.where), normalize(rule.when)


def analyze(policy: Policy) -> Report:
    """Inspect a loaded policy for anything that would surprise its author.

    Schema problems are already hard errors at load time, so everything found
    here is a policy that parses but does not mean what it appears to.
    """
    report = Report()
    _check_adapters(policy, report)
    _check_trust(policy, report)
    _check_negative_conditions(policy, report)
    _check_posture(policy, report)
    _check_rule_order(policy, report)
    _check_rules_against_surface(policy, report)
    return report


def _check_adapters(policy: Policy, report: Report) -> None:
    """Report adapters that cannot be built from their declaration.

    Duplicate adapter names are not checked here — `load_policy` already
    rejects those, and a check that can never fire is worse than no check.
    """
    for spec in policy.adapters:
        try:
            build_adapter(spec)
        except AdapterError as e:
            report.diagnostics.append(
                Diagnostic(
                    ERROR,
                    "adapter-unbuildable",
                    str(e),
                    location=f"adapters '{spec.name}'",
                )
            )


def _check_trust(policy: Policy, report: Report) -> None:
    """Report `when` fields the policy does not require to be pinned.

    An unpinned `when` field is read from per-call context, and HYDRACUDA
    cannot tell whether the integrator sourced that value from a session record
    or from model output. A rule gating on an unpinned field is therefore only
    as trustworthy as the calling code, which is worth saying out loud rather
    than leaving in the specification.
    """
    pinned = set(policy.pinned_context)
    for index, rule in enumerate(policy.rules):
        unpinned = sorted(set(rule.when) - pinned)
        if not unpinned:
            continue
        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "unpinned-when-field",
                f"tests context field(s) {unpinned}, which are not listed in "
                f"`pinned_context`. Those values are supplied per call, so this "
                f"rule can only be trusted if the calling code never derives "
                f"them from model output. Add them to `pinned_context` to make "
                f"HYDRACUDA enforce that.",
                location=_location(index, rule),
            )
        )


def _check_negative_conditions(policy: Policy, report: Report) -> None:
    """Report blocking rules that a missing field lets through.

    An absent field satisfies no value operator, including the negative ones.
    That is deliberate and load-bearing elsewhere — it is why a `when`
    condition can never be satisfied by a same-named request parameter — but it
    has a consequence worth stating: `deny ... where path not_matches
    ^/workspace/` does not fire on a call that omits `path` entirely, because
    the condition is false rather than true. The rule reads as "deny writes
    outside the workspace" and behaves as "deny writes to a stated path outside
    the workspace".
    """
    for index, rule in enumerate(policy.rules):
        if rule.action not in _BLOCKING_ACTIONS:
            continue

        exposed: list[str] = []
        for block_name, block in (("where", rule.where), ("when", rule.when)):
            for field_name, ops in block.items():
                negative = sorted(set(ops) & _NEGATIVE_OPERATORS)
                if not negative:
                    continue
                if _absence_is_covered(policy, rule, block_name, field_name):
                    continue
                exposed.append(f"{block_name}.{field_name} ({', '.join(negative)})")

        if not exposed:
            continue

        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "negative-condition-fails-open",
                f"{'; '.join(exposed)}: an absent field satisfies no value "
                f"operator, so this '{rule.action}' rule does not fire on a "
                f"request that omits the field entirely. Cover that case with a "
                f"separate '{rule.action}' rule testing `absent: true` on the "
                f"same field. Adding `present: true` here documents the intent "
                f"but changes nothing — conditions are ANDed, so the rule still "
                f"needs the field to be there.",
                location=_location(index, rule),
            )
        )


def _absence_is_covered(
    policy: Policy, rule: Rule, block_name: str, field_name: str
) -> bool:
    """True when another blocking rule handles the field being absent.

    Looks for the actual fix rather than an acknowledgement of the problem: a
    rule that blocks, covers at least the same resources, and tests the same
    field with `absent: true`.
    """
    for other in policy.rules:
        if other is rule or other.action not in _BLOCKING_ACTIONS:
            continue
        if not pattern_subsumes(other.resource, rule.resource):
            continue
        block = other.where if block_name == "where" else other.when
        if block.get(field_name, {}).get("absent") is True:
            return True
    return False


def _check_posture(policy: Policy, report: Report) -> None:
    if policy.mode == "shadow":
        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "shadow-mode",
                "`mode: shadow` computes and logs every decision but executes "
                "the call regardless. This policy enforces nothing.",
                location="mode",
            )
        )

    if policy.default_action == "allow":
        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "default-allow",
                "`default_action: allow` means a resource no rule mentions is "
                "permitted, so adding a tool without adding a rule fails open.",
                location="default_action",
            )
        )

    if not policy.rules:
        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "no-rules",
                f"the policy declares no rules, so every request falls through "
                f"to `default_action: {policy.default_action}`.",
                location="rules",
            )
        )


def _check_rule_order(policy: Policy, report: Report) -> None:
    """Find rules an earlier rule makes unreachable.

    First match wins, so a broad rule above a narrow one silently disables it.
    Only provable cases are reported — see `pattern_subsumes`.
    """
    names: dict[str, int] = {}

    for index, rule in enumerate(policy.rules):
        if rule.name:
            if rule.name in names:
                report.diagnostics.append(
                    Diagnostic(
                        WARNING,
                        "duplicate-rule-name",
                        f"another rule at rules[{names[rule.name]}] has the same "
                        f"name; names appear in decisions and audit records, so "
                        f"duplicates make a log ambiguous",
                        location=_location(index, rule),
                    )
                )
            else:
                names[rule.name] = index

        for earlier_index in range(index):
            earlier = policy.rules[earlier_index]
            if not pattern_subsumes(earlier.resource, rule.resource):
                continue

            same_conditions = _conditions_key(earlier) == _conditions_key(rule)
            # Equivalent patterns, not merely overlapping ones. A broad rule
            # above a narrow one shadows it, but it is not a conflict between
            # two rules about the same thing.
            same_resources = pattern_subsumes(rule.resource, earlier.resource)
            unconditional = not earlier.where and not earlier.when

            if same_resources and same_conditions:
                if earlier.action != rule.action:
                    report.diagnostics.append(
                        Diagnostic(
                            WARNING,
                            "conflicting-rules",
                            f"rules[{earlier_index}] {earlier.label} matches the "
                            f"same resources under the same conditions but "
                            f"decides '{earlier.action}' instead of "
                            f"'{rule.action}'. First match wins, so "
                            f"'{earlier.action}' is what happens.",
                            location=_location(index, rule),
                        )
                    )
                else:
                    report.diagnostics.append(
                        Diagnostic(
                            WARNING,
                            "duplicate-rule",
                            f"rules[{earlier_index}] {earlier.label} already "
                            f"decides '{rule.action}' for these resources under "
                            f"the same conditions; this rule never fires.",
                            location=_location(index, rule),
                        )
                    )
            elif unconditional or same_conditions:
                qualifier = (
                    "unconditionally"
                    if unconditional
                    else "under the same conditions as this rule"
                )
                report.diagnostics.append(
                    Diagnostic(
                        WARNING,
                        "unreachable-rule",
                        f"rules[{earlier_index}] {earlier.label} matches "
                        f"'{rule.resource}' {qualifier} and decides "
                        f"'{earlier.action}', so this rule is never reached. Move "
                        f"it above rules[{earlier_index}].",
                        location=_location(index, rule),
                    )
                )
            else:
                # The earlier rule covers these resources but only under its own
                # conditions, so this rule is still reachable.
                continue
            break


def _check_rules_against_surface(policy: Policy, report: Report) -> None:
    """Report rules that no declared resource can match.

    Only meaningful once adapters declare a surface. A version 1 policy, or one
    with no `adapters` block, has nothing to check against.
    """
    declared = [
        resource for spec in policy.adapters for resource in spec.resources
    ]
    if not declared:
        return

    for index, rule in enumerate(policy.rules):
        if any(resource_matches(rule.resource, name) for name in declared):
            continue
        report.diagnostics.append(
            Diagnostic(
                WARNING,
                "unmatched-rule-resource",
                f"resource pattern '{rule.resource}' matches nothing any adapter "
                f"declares. Either the pattern is misspelled, or the adapter's "
                f"`resources` list is incomplete — in which case the rule will "
                f"still apply at runtime but `plan` cannot show it.",
                location=_location(index, rule),
            )
        )


def plan(policy: Policy) -> list[PlanEntry]:
    """Decide every resource on the declared surface, without executing any.

    Each entry is evaluated with no parameters and no context, which is the only
    input a policy file supplies on its own. Rules that depend on either are
    listed in `conditional_rules` rather than guessed at.
    """
    engine = PolicyEngine(policy)
    entries: list[PlanEntry] = []

    for resource in policy.declared_resources():
        decision = engine.evaluate(resource)
        entries.append(
            PlanEntry(
                resource=resource,
                action=decision.action,
                rule=decision.rule,
                reason=decision.reason,
                conditional_rules=tuple(_conditional_rules(policy, resource)),
            )
        )

    return entries


def _conditional_rules(policy: Policy, resource: str) -> list[str]:
    """Rules whose applicability to `resource` depends on params or context.

    Rules below the first unconditional match are skipped: that match always
    wins, so nothing after it can change the outcome for this resource.
    """
    labels: list[str] = []
    for rule in policy.rules:
        if not resource_matches(rule.resource, resource):
            continue
        if rule.where or rule.when:
            labels.append(rule.label)
        else:
            break
    return labels
