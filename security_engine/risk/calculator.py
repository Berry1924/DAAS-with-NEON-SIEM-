import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from backend.app.models.enums import Severity, EventOutcome
from backend.app.models.alert import Alert
from backend.app.models.event import Event
from backend.app.models.correlation import CorrelationGroup

logger = logging.getLogger(__name__)

SEVERITY_BASE_MAP = {
    Severity.INFO: 10,
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 60,
    Severity.CRITICAL: 80,
}

MAX_CORRELATION_BONUS = 15
COMPROMISE_INDICATOR_POINTS = 10
PRIVILEGE_ESCALATION_POINTS = 5

@dataclass
class RiskResult:
    """Deterministic risk calculation result and factor breakdown."""
    base_risk: int
    correlation_bonus: int
    compromise_indicator_bonus: int
    privilege_escalation_bonus: int
    asset_criticality_modifier: int
    final_score: int
    severity: Severity
    factors: List[Dict[str, Any]]
    explanation_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_risk": self.base_risk,
            "correlation_bonus": self.correlation_bonus,
            "compromise_indicator_bonus": self.compromise_indicator_bonus,
            "privilege_escalation_bonus": self.privilege_escalation_bonus,
            "asset_criticality_modifier": self.asset_criticality_modifier,
            "final_score": self.final_score,
            "severity": self.severity.value,
            "factors": self.factors,
            "explanation_summary": self.explanation_summary,
        }

class RiskCalculator:
    """Deterministic, server-authoritative risk scoring calculator."""

    def calculate(
        self,
        group: CorrelationGroup,
        alerts: List[Alert],
        events: Optional[List[Event]] = None,
        asset_criticality_modifier: int = 0
    ) -> RiskResult:
        """Calculate deterministic 0-100 risk score and factor breakdown from evidence."""
        factors: List[Dict[str, Any]] = []

        # 1. Base Risk from highest severity alert
        highest_severity = self._determine_highest_severity(alerts, group)
        base_risk = SEVERITY_BASE_MAP.get(highest_severity, 40)
        factors.append({
            "type": "base_risk",
            "label": f"Base severity {highest_severity.value} contributed {base_risk} points.",
            "points": base_risk
        })

        # 2. Correlation Bonus (+5 per additional alert, max +15)
        alert_count = len(alerts) if alerts else group.alert_count
        if alert_count > 1:
            raw_bonus = (alert_count - 1) * 5
            correlation_bonus = min(raw_bonus, MAX_CORRELATION_BONUS)
            if correlation_bonus >= MAX_CORRELATION_BONUS:
                corr_label = f"{alert_count} related alerts reached the correlation bonus cap of {MAX_CORRELATION_BONUS} points."
            else:
                corr_label = f"{alert_count} related alerts contributed {correlation_bonus} correlation points."
        else:
            correlation_bonus = 0
            corr_label = "Single alert contributed 0 correlation points."

        factors.append({
            "type": "correlation",
            "label": corr_label,
            "points": correlation_bonus
        })

        # 3. Compromise Indicator Bonus (+10 for failed + successful auth)
        has_failed, has_success = self._detect_compromise_indicators(alerts, events)
        if has_failed and has_success:
            compromise_indicator_bonus = COMPROMISE_INDICATOR_POINTS
            comp_label = f"Failed authentication followed by successful authentication contributed {COMPROMISE_INDICATOR_POINTS} compromise-indicator points."
        else:
            compromise_indicator_bonus = 0
            comp_label = "Compromise sequence not observed (0 points)."

        factors.append({
            "type": "compromise_indicator",
            "label": comp_label,
            "points": compromise_indicator_bonus
        })

        # 4. Privilege Escalation Bonus (+5)
        has_priv = self._detect_privilege_escalation(alerts, events)
        if has_priv:
            privilege_escalation_bonus = PRIVILEGE_ESCALATION_POINTS
            priv_label = f"Privilege escalation activity contributed {PRIVILEGE_ESCALATION_POINTS} points."
        else:
            privilege_escalation_bonus = 0
            priv_label = "Privilege escalation activity not observed (0 points)."

        factors.append({
            "type": "privilege_event",
            "label": priv_label,
            "points": privilege_escalation_bonus
        })

        # 5. Asset Criticality Modifier
        asset_mod = max(-50, min(50, asset_criticality_modifier))
        factors.append({
            "type": "asset_criticality",
            "label": f"Asset criticality modifier contributed {asset_mod} points.",
            "points": asset_mod
        })

        # 6. Final Score & Clamping (0 - 100)
        raw_total = base_risk + correlation_bonus + compromise_indicator_bonus + privilege_escalation_bonus + asset_mod
        final_score = max(0, min(100, raw_total))

        # 7. Severity Tier
        severity_tier = self._get_severity_tier(final_score)

        # 8. Explanation Summary
        explanation_summary = (
            f"Final risk score {final_score}/100 ({severity_tier.value}): "
            f"Base {base_risk} ({highest_severity.value}), "
            f"+{correlation_bonus} correlation, "
            f"+{compromise_indicator_bonus} compromise indicator, "
            f"+{privilege_escalation_bonus} privilege escalation, "
            f"{asset_mod:+d} asset modifier."
        )

        return RiskResult(
            base_risk=base_risk,
            correlation_bonus=correlation_bonus,
            compromise_indicator_bonus=compromise_indicator_bonus,
            privilege_escalation_bonus=privilege_escalation_bonus,
            asset_criticality_modifier=asset_mod,
            final_score=final_score,
            severity=severity_tier,
            factors=factors,
            explanation_summary=explanation_summary
        )

    def _determine_highest_severity(self, alerts: List[Alert], group: CorrelationGroup) -> Severity:
        """Determine highest severity from alerts list or group."""
        if alerts:
            sev_order = {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}
            highest = max(alerts, key=lambda a: sev_order.get(a.severity, 1))
            return highest.severity
        if hasattr(group, "severity") and group.severity:
            return group.severity
        return Severity.MEDIUM

    def _detect_compromise_indicators(self, alerts: List[Alert], events: Optional[List[Event]]) -> tuple[bool, bool]:
        """Check evidence for presence of both failed auth and successful auth."""
        rule_ids = set()
        for a in alerts:
            if a.rule:
                rule_ids.add(a.rule.rule_id)
            elif a.evidence and "rule_id" in a.evidence:
                rule_ids.add(a.evidence["rule_id"])

        has_failed = "CW-AUTH-001" in rule_ids
        has_success = "CW-LOGIN-001" in rule_ids

        if events:
            for e in events:
                e_type = getattr(e, "event_type", "").lower()
                outcome = getattr(e, "outcome", None)
                if e_type in ("authentication", "ssh_login_failed", "login_failed") or outcome == EventOutcome.FAILURE:
                    has_failed = True
                if e_type in ("authentication", "ssh_login_accepted", "login_success") or outcome == EventOutcome.SUCCESS:
                    has_success = True

        return has_failed, has_success

    def _detect_privilege_escalation(self, alerts: List[Alert], events: Optional[List[Event]]) -> bool:
        """Check evidence for privilege escalation activity."""
        rule_ids = set()
        for a in alerts:
            if a.rule:
                rule_ids.add(a.rule.rule_id)
            elif a.evidence and "rule_id" in a.evidence:
                rule_ids.add(a.evidence["rule_id"])

        if "CW-PRIV-001" in rule_ids:
            return True

        if events:
            for e in events:
                e_type = getattr(e, "event_type", "").lower()
                if e_type in ("privilege_escalation", "sudo", "su_command", "su"):
                    return True

        return False

    def _get_severity_tier(self, score: int) -> Severity:
        """Map score 0-100 to Severity tier."""
        if score >= 75:
            return Severity.CRITICAL
        elif score >= 50:
            return Severity.HIGH
        elif score >= 25:
            return Severity.MEDIUM
        return Severity.LOW

risk_calculator = RiskCalculator()
