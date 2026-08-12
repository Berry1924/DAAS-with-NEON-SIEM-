from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from backend.app.repositories.dashboard_repository import DashboardRepository
from backend.app.schemas.dashboard import DashboardSummary

class DashboardService:
    """Service orchestrating authoritative database-backed SOC dashboard metrics."""

    def get_summary(self, db: Session) -> DashboardSummary:
        """Calculate and return 24h dashboard summary from PostgreSQL/DB."""
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(hours=24)

        repo = DashboardRepository(db)

        total_events = repo.get_total_events_24h(window_start)
        active_alerts_by_sev = repo.get_active_alerts_by_severity()
        open_incidents = repo.get_open_incidents_count()
        top_rules = repo.get_top_detection_rules(limit=5)
        recent_incidents = repo.get_recent_incidents(limit=5)
        event_trend = repo.get_hourly_event_trend(now_utc, window_start)

        return DashboardSummary(
            total_events_24h=total_events,
            active_alerts_by_severity=active_alerts_by_sev,
            open_incidents=open_incidents,
            top_detection_rules=top_rules,
            recent_incidents=recent_incidents,
            event_trend=event_trend,
        )

dashboard_service = DashboardService()
