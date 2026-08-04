"""M2 tests: policy engine, audit log, approval queue, pipeline decision."""

from __future__ import annotations

from ai_input_trust_gateway.approval import ApprovalQueue
from ai_input_trust_gateway.audit import AuditLog
from ai_input_trust_gateway.pipeline import process_file
from ai_input_trust_gateway.policy import (
    DecisionAction,
    PolicyEngine,
    PolicyRule,
    _detector_hit,
    _label_is,
    _risk_at_least,
)
from ai_input_trust_gateway.trust_label import TrustLabelValue
from tests.fixtures import builders


class TestPolicyEngine:
    def test_default_policy_block_dangerous(self, tmp_path):
        # zero-width → high severity → structure ≤ 0.2 → dangerous → block
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = process_file(str(f))
        assert result.is_dangerous
        decision = result.decision
        assert decision is not None
        assert decision.action == DecisionAction.BLOCK

    def test_default_policy_quarantine_hidden_sheet(self, tmp_path):
        # hidden sheet → medium → caution tier → hidden content rule (POL-002)
        # fires first → quarantine
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        result = process_file(str(f))
        assert result.decision is not None
        assert result.decision.action == DecisionAction.QUARANTINE

    def test_default_policy_allow_benign(self, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        result = process_file(str(f))
        assert result.is_safe
        assert result.decision is not None
        assert result.decision.action == DecisionAction.ALLOW

    def test_custom_rule_first_match(self):
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    id="R1",
                    action=DecisionAction.BLOCK,
                    reason="r1",
                    condition=_label_is(TrustLabelValue.SAFE),
                ),
                PolicyRule(id="R2", action=DecisionAction.ALLOW, reason="r2", condition=lambda *_: True),
            ]
        )
        from ai_input_trust_gateway.core.evidence import ScanReport

        report = ScanReport(file="f", kind="docx")
        d = engine.evaluate(report, TrustLabelValue.SAFE)
        assert d.rule_id == "R1"
        assert d.action == DecisionAction.BLOCK

    def test_condition_helpers(self):
        from ai_input_trust_gateway.core.evidence import Evidence, ScanReport, Severity

        report = ScanReport(
            file="f",
            kind="docx",
            evidence=[
                Evidence(detector_id="DET-001", detector_name="z", severity=Severity.HIGH, title="t", description="d")
            ],
        )
        assert _detector_hit("DET-001")(report, TrustLabelValue.CAUTION, 0.5)
        assert not _detector_hit("DET-002")(report, TrustLabelValue.CAUTION, 0.5)
        assert _risk_at_least(0.2)(report, TrustLabelValue.SAFE, 0.5)
        assert not _risk_at_least(0.8)(report, TrustLabelValue.SAFE, 0.5)
        assert _label_is(TrustLabelValue.CAUTION)(report, TrustLabelValue.CAUTION, 0.5)

class TestAuditLog:
    def test_record_and_read(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        result = process_file(str(f))
        assert result.decision is not None
        entry = log.record(report=result.report, decision=result.decision, sanitized=True, note="test")
        assert entry["file"] == "clean.docx"
        assert entry["decision"]["action"] == "allow"
        entries = log.read()
        assert len(entries) == 1
        assert entries[0]["sanitized"] is True

    def test_read_empty(self, tmp_path):
        log = AuditLog(tmp_path / "empty.jsonl")
        assert log.read() == []
        assert log.count() == 0


class TestApprovalQueue:
    def test_request_and_approve(self, tmp_path):
        q = ApprovalQueue(tmp_path / "approvals.jsonl")
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = process_file(str(f))
        assert result.decision is not None
        entry = q.request(report=result.report, decision=result.decision, sanitized_text="cleaned")
        assert entry["status"] == "pending"
        assert len(q.pending()) == 1

        approved = q.approve(entry["id"], by="reviewer")
        assert approved is not None
        assert approved["status"] == "approved"
        assert approved["decision_by"] == "reviewer"
        assert len(q.pending()) == 0

    def test_request_and_reject(self, tmp_path):
        q = ApprovalQueue(tmp_path / "approvals.jsonl")
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        result = process_file(str(f))
        assert result.decision is not None
        entry = q.request(report=result.report, decision=result.decision)
        rejected = q.reject(entry["id"])
        assert rejected is not None
        assert rejected["status"] == "rejected"

    def test_approve_missing(self, tmp_path):
        q = ApprovalQueue(tmp_path / "approvals.jsonl")
        assert q.approve("nope") is None
        assert q.reject("nope") is None


class TestPipelineDecision:
    def test_report_carries_decision(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = process_file(str(f))
        assert result.report.decision is not None
        assert result.report.decision["action"] == "block"
        assert result.report.trust_label is not None
        assert result.report.trust_label["value"] == "dangerous"

    def test_is_blocked_property(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = process_file(str(f))
        assert result.is_blocked
