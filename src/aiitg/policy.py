"""Policy engine — decide what to do with a scanned document.

M2 core: turn a scan + trust label into an *enforceable decision*. This is the
"Assume Compromise" execution layer: even if a prompt injection slips past
detection, the policy decides whether the document may reach an LLM/Agent at
all, and under what constraints.

Decision actions:
- ``allow``: document is trustworthy, feed to LLM directly.
- ``quarantine``: document has issues but is usable after sanitization
  (equivalent to "sanitize then allow").
- ``human_approval``: suspicious enough that a human must approve before use.
- ``block``: document is too dangerous to use at all.

Policies are ordered rules (first match wins). Each rule has:
- a condition (label value, min risk score, detector hit, or any combination)
- an action
- a reason template
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from aiitg.core.evidence import ScanReport, Severity, severity_at_least
from aiitg.trust_label import TrustLabelValue


class DecisionAction(StrEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    HUMAN_APPROVAL = "human_approval"
    BLOCK = "block"


@dataclass
class Decision:
    """The policy engine's verdict for a document."""

    action: DecisionAction
    rule_id: str
    reason: str
    policy_name: str = "default"

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "policy_name": self.policy_name,
        }

    @property
    def is_blocked(self) -> bool:
        return self.action == DecisionAction.BLOCK

    @property
    def needs_human(self) -> bool:
        return self.action == DecisionAction.HUMAN_APPROVAL


# Condition type: takes a report + label value + risk score → bool
Condition = Callable[[ScanReport, TrustLabelValue, float], bool]


@dataclass
class PolicyRule:
    """A single policy rule: if condition matches → action."""

    id: str
    action: DecisionAction
    reason: str
    condition: Condition

    def evaluate(self, report: ScanReport, label: TrustLabelValue, risk: float) -> bool:
        try:
            return bool(self.condition(report, label, risk))
        except Exception:  # noqa: BLE001 — a broken rule must not crash the engine
            return False


# --- condition helpers ---

def _label_is(*values: TrustLabelValue) -> Condition:
    def cond(report: ScanReport, label: TrustLabelValue, risk: float) -> bool:
        return label in values

    return cond


def _risk_at_least(threshold: float) -> Condition:
    def cond(report: ScanReport, label: TrustLabelValue, risk: float) -> bool:
        return risk >= threshold

    return cond


def _detector_hit(*detector_ids: str, min_severity: Severity = Severity.LOW) -> Condition:
    def cond(report: ScanReport, label: TrustLabelValue, risk: float) -> bool:
        for ev in report.evidence:
            if ev.detector_id in detector_ids and severity_at_least(ev.severity, min_severity):
                return True
        return False

    return cond


def _any_hidden_content() -> Condition:
    """True if any evidence of deliberate concealment exists."""

    def cond(report: ScanReport, label: TrustLabelValue, risk: float) -> bool:
        return len(report.evidence) > 0

    return cond


class PolicyEngine:
    """Evaluates ordered rules against a report; first match wins."""

    def __init__(self, rules: list[PolicyRule] | None = None, name: str = "default") -> None:
        self.rules = rules or []
        self.name = name

    def evaluate(self, report: ScanReport, label: TrustLabelValue) -> Decision:
        risk = report.risk_score
        for rule in self.rules:
            if rule.evaluate(report, label, risk):
                return Decision(action=rule.action, rule_id=rule.id, reason=rule.reason, policy_name=self.name)
        # default fallback: allow (empty policy = allow everything)
        return Decision(
            action=DecisionAction.ALLOW,
            rule_id="fallback-allow",
            reason="no rule matched",
            policy_name=self.name,
        )

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)


def default_policy() -> PolicyEngine:
    """The built-in conservative policy (Assume Compromise).

    Order matters — first match wins:
    1. dangerous label          → block
    2. hidden content detected  → quarantine (usable after sanitize)
    3. caution label            → human_approval (suspicious, needs a human)
    4. everything else          → allow (fallback in engine)
    """
    return PolicyEngine(
        name="default",
        rules=[
            PolicyRule(
                id="POL-001",
                action=DecisionAction.BLOCK,
                reason="document is dangerous (trust label); block before it reaches any LLM/Agent",
                condition=_label_is(TrustLabelValue.DANGEROUS),
            ),
            PolicyRule(
                id="POL-002",
                action=DecisionAction.QUARANTINE,
                reason="hidden content detected; sanitize before use",
                condition=_any_hidden_content(),
            ),
            PolicyRule(
                id="POL-003",
                action=DecisionAction.HUMAN_APPROVAL,
                reason="document is caution-tier (suspicious); require human approval before use",
                condition=_label_is(TrustLabelValue.CAUTION),
            ),
        ],
    )
