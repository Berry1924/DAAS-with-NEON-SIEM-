import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

from backend.app.models.incident import Incident
from backend.app.models.incident_alerts import IncidentAlert
from backend.app.models.incident_timeline import IncidentTimeline
from backend.app.models.incident_notes import IncidentNote
from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent
from backend.app.models.event import Event
from backend.app.models.user import User
from backend.app.models.enums import IncidentStatus, Severity, AuditResult
from backend.app.models.audit_log import AuditLog
from backend.app.models.correlation import CorrelationGroup
from backend.app.repositories.incident_repository import IncidentRepository
from backend.app.services.audit_service import audit_service
from backend.app.schemas.incident import (
    IncidentDetailRead,
    IncidentAlertLinkRead,
    IncidentEventEvidenceRead,
    IncidentTimelineRead,
    IncidentNoteRead,
)

logger = logging.getLogger(__name__)

# Valid Incident Lifecycle Transitions
VALID_TRANSITIONS = {
    IncidentStatus.NEW: {IncidentStatus.ACKNOWLEDGED, IncidentStatus.FALSE_POSITIVE},
    IncidentStatus.ACKNOWLEDGED: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE},
    IncidentStatus.RESOLVED: set(),        # Terminal
    IncidentStatus.FALSE_POSITIVE: set(),  # Terminal
}

class IncidentService:
    """Business orchestration service for Incident Management."""

    def process_correlation(self, group: CorrelationGroup, db: Session) -> Incident:
        """Create or update an incident from a correlated security finding (M08/M09 result)."""
        repo = IncidentRepository(db)

        # 1. Deduplication: Check if active incident exists for correlation_key
        existing_incident = repo.find_active_by_correlation_key(group.correlation_key)

        if not existing_incident:
            # Also check by source_ip / username if correlation_key match didn't find one
            existing_incident = repo.find_active_by_entities(
                source_ip=group.source_ip,
                username=group.username
            )

        if existing_incident:
            return self._update_existing_incident(existing_incident, group, db)
        else:
            return self._create_new_incident(group, db)

    def _create_new_incident(self, group: CorrelationGroup, db: Session) -> Incident:
        """Create a new evidence-backed incident from correlation & risk data."""
        repo = IncidentRepository(db)
        incident_key = repo.next_incident_key()
        now = datetime.now(timezone.utc)

        incident = Incident(
            incident_key=incident_key,
            title=group.title,
            incident_type=group.pattern_matched or "Correlated Security Incident",
            description=group.correlation_reason,
            severity=group.severity,
            risk_score=group.risk_score,
            risk_explanation=group.risk_explanation,
            status=IncidentStatus.NEW,
            source_ip=group.source_ip,
            destination_ip=group.destination_ip,
            username=group.username,
            correlation_rule=group.correlation_key,
            first_seen_at=group.first_seen_at,
            last_seen_at=group.last_seen_at,
            created_at=now,
            updated_at=now,
        )

        repo.create(incident)

        # Link alerts & build initial timeline
        self._sync_incident_alerts_and_timeline(incident, group, db)
        
        # Audit log creation
        audit_service.log(
            db=db,
            action=audit_service.INCIDENT_CREATED,
            actor_id=None,
            target_type="incident",
            target_id=str(incident.id),
            result=AuditResult.SUCCESS,
            metadata={
                "incident_key": incident.incident_key,
                "title": incident.title,
                "risk_score": incident.risk_score,
                "severity": incident.severity.value,
            }
        )

        logger.info(f"Created incident {incident.incident_key} ({incident.title}) with risk {incident.risk_score}")
        return incident


    def _update_existing_incident(self, incident: Incident, group: CorrelationGroup, db: Session) -> Incident:
        """Update existing active incident with new correlation evidence."""
        repo = IncidentRepository(db)
        
        incident.title = group.title
        incident.severity = group.severity
        incident.risk_score = group.risk_score
        incident.risk_explanation = group.risk_explanation
        incident.description = group.correlation_reason
        incident.first_seen_at = min(incident.first_seen_at, group.first_seen_at)
        incident.last_seen_at = max(incident.last_seen_at, group.last_seen_at)
        incident.updated_at = datetime.now(timezone.utc)

        repo.update(incident)

        self._sync_incident_alerts_and_timeline(incident, group, db)
        logger.info(f"Updated active incident {incident.incident_key} with correlation {group.correlation_key}")
        return incident

    def _sync_incident_alerts_and_timeline(self, incident: Incident, group: CorrelationGroup, db: Session) -> None:
        """Link alerts, fetch events, and add timeline entries."""
        repo = IncidentRepository(db)

        # 1. Fetch alerts
        alert_uuids = [uuid.UUID(aid) for aid in group.alert_ids if aid]
        alerts = list(db.scalars(select(Alert).where(Alert.id.in_(alert_uuids))).all()) if alert_uuids else []

        # Get existing linked alert IDs
        existing_linked_ids = set(
            db.scalars(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)).all()
        )

        new_alerts = [a for a in alerts if a.id not in existing_linked_ids]

        # Link new alerts
        for a in new_alerts:
            repo.link_alert(incident.id, a.id, role="contributing")

        # 2. Add creation timeline entry if empty timeline
        timeline_count = db.scalar(select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id))
        if not timeline_count:
            repo.add_timeline_entry(
                IncidentTimeline(
                    incident_id=incident.id,
                    timestamp=incident.created_at,
                    entry_type="INCIDENT_CREATED",
                    title=f"Incident Created: {incident.title}",
                    summary=f"Incident generated from correlation key {group.correlation_key} with risk score {incident.risk_score}/100.",
                    timeline_metadata={"correlation_key": group.correlation_key, "risk_score": incident.risk_score}
                )
            )

        # 3. Add timeline entries for new alerts and their primary events
        for a in new_alerts:
            repo.add_timeline_entry(
                IncidentTimeline(
                    incident_id=incident.id,
                    timestamp=a.created_at,
                    entry_type="ALERT_LINKED",
                    alert_id=a.id,
                    event_id=a.primary_event_id,
                    title=f"Alert Correlated: {a.title}",
                    summary=a.description,
                    timeline_metadata={"severity": a.severity.value, "risk_score": a.risk_score}
                )
            )

    def get_incident_detail(self, incident_id: uuid.UUID, db: Session) -> Optional[IncidentDetailRead]:
        """Fetch full incident detail with evidence chain, timeline, and notes."""
        repo = IncidentRepository(db)
        incident = repo.get_by_id(incident_id)
        if not incident:
            return None

        # Assignee name
        assignee_name = incident.assignee.display_name if incident.assignee else None

        # Linked alerts
        alert_links_stmt = (
            select(Alert, IncidentAlert.correlation_role)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident.id)
            .order_by(Alert.created_at.asc())
        )
        alert_rows = db.execute(alert_links_stmt).all()
        linked_alerts = []
        for alert, role in alert_rows:
            linked_alerts.append(
                IncidentAlertLinkRead(
                    alert_id=alert.id,
                    title=alert.title,
                    severity=alert.severity.value,
                    risk_score=alert.risk_score,
                    rule_id=alert.evidence.get("rule_id", "unknown") if alert.evidence else "unknown",
                    correlation_role=role,
                )
            )

        # Linked events (traversed via AlertEvent and primary_event_id for all linked alerts)
        alert_ids = [a.id for a, _ in alert_rows]
        linked_events = []
        if alert_ids:
            # 1. Query events linked via AlertEvent junction table
            event_stmt = (
                select(Event)
                .join(AlertEvent, AlertEvent.event_id == Event.id)
                .where(AlertEvent.alert_id.in_(alert_ids))
                .order_by(Event.timestamp.asc())
            )
            event_objs = list(db.scalars(event_stmt).all())

            # 2. Query primary events for linked alerts
            primary_event_ids = [a.primary_event_id for a, _ in alert_rows if a.primary_event_id]
            if primary_event_ids:
                primary_events = list(db.scalars(select(Event).where(Event.id.in_(primary_event_ids))).all())
                event_objs.extend(primary_events)

            seen_event_ids = set()
            for e in sorted(event_objs, key=lambda x: x.timestamp):
                if e.id not in seen_event_ids:
                    seen_event_ids.add(e.id)
                    linked_events.append(
                        IncidentEventEvidenceRead(
                            id=e.id,
                            timestamp=e.timestamp,
                            source_type=e.source_type,
                            event_type=e.event_type,
                            source_ip=e.source_ip,
                            destination_ip=e.destination_ip,
                            username=e.username,
                            hostname=e.hostname,
                            outcome=e.outcome.value,
                            severity=e.severity.value,
                        )
                    )


        # Timeline entries
        timeline_stmt = (
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident.id)
            .order_by(IncidentTimeline.timestamp.asc())
        )
        timeline_objs = list(db.scalars(timeline_stmt).all())
        timeline = [IncidentTimelineRead.model_validate(t) for t in timeline_objs]

        # Notes entries
        notes_stmt = (
            select(IncidentNote, User.display_name)
            .join(User, User.id == IncidentNote.author_id)
            .where(IncidentNote.incident_id == incident.id)
            .order_by(IncidentNote.created_at.asc())
        )
        note_rows = db.execute(notes_stmt).all()
        notes = []
        for note, author_name in note_rows:
            note_read = IncidentNoteRead.model_validate(note)
            note_read.author_name = author_name
            notes.append(note_read)

        detail = IncidentDetailRead(
            id=incident.id,
            incident_key=incident.incident_key,
            title=incident.title,
            incident_type=incident.incident_type,
            description=incident.description,
            severity=incident.severity,
            risk_score=incident.risk_score,
            status=incident.status,
            assigned_to=incident.assigned_to,
            assignee_name=assignee_name,
            source_ip=incident.source_ip,
            destination_ip=incident.destination_ip,
            username=incident.username,
            correlation_rule=incident.correlation_rule,
            first_seen_at=incident.first_seen_at,
            last_seen_at=incident.last_seen_at,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            resolved_at=incident.resolved_at,
            risk_explanation=incident.risk_explanation or {},
            linked_alerts=linked_alerts,
            linked_events=linked_events,
            timeline=timeline,
            notes=notes,
        )

        return detail

    def update_status(
        self,
        incident_id: uuid.UUID,
        new_status: IncidentStatus,
        comment: Optional[str],
        user: User,
        request_id: str,
        db: Session,
    ) -> Incident:
        """Update incident status following deterministic state machine rules."""
        repo = IncidentRepository(db)
        incident = repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        old_status = incident.status

        # Validate transition
        allowed = VALID_TRANSITIONS.get(old_status, set())
        if new_status not in allowed:
            raise ValueError(f"Invalid status transition from '{old_status.value}' to '{new_status.value}'")

        now = datetime.now(timezone.utc)
        incident.status = new_status
        incident.updated_at = now

        if new_status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
            incident.resolved_at = now

        repo.update(incident)

        # Timeline entry
        repo.add_timeline_entry(
            IncidentTimeline(
                incident_id=incident.id,
                timestamp=now,
                entry_type="STATUS_CHANGED",
                title=f"Status changed to {new_status.value}",
                summary=f"Changed by {user.display_name}. Comment: {comment or 'None'}",
                timeline_metadata={"old_status": old_status.value, "new_status": new_status.value, "comment": comment}
            )
        )

        # Audit log via AuditService
        audit_service.log(
            db=db,
            action=audit_service.INCIDENT_STATUS_CHANGED,
            actor_id=user.id,
            target_type="incident",
            target_id=str(incident.id),
            result=AuditResult.SUCCESS,
            request_id=request_id,
            metadata={
                "incident_key": incident.incident_key,
                "old_status": old_status.value,
                "new_status": new_status.value,
                "comment": comment,
            }
        )

        return incident

    def assign_analyst(
        self,
        incident_id: uuid.UUID,
        assigned_to: Optional[uuid.UUID],
        user: User,
        request_id: str,
        db: Session,
    ) -> Incident:
        """Assign or reassign an incident to an analyst."""
        repo = IncidentRepository(db)
        incident = repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        assignee = None
        if assigned_to:
            assignee = db.get(User, assigned_to)
            if not assignee:
                raise ValueError(f"Target assignee user '{assigned_to}' not found")

        now = datetime.now(timezone.utc)
        incident.assigned_to = assigned_to
        incident.updated_at = now

        repo.update(incident)

        assignee_name = assignee.display_name if assignee else "Unassigned"
        repo.add_timeline_entry(
            IncidentTimeline(
                incident_id=incident.id,
                timestamp=now,
                entry_type="ASSIGNED",
                title=f"Assigned to {assignee_name}",
                summary=f"Assigned by {user.display_name}",
                timeline_metadata={"assigned_to": str(assigned_to) if assigned_to else None}
            )
        )

        # Audit log via AuditService
        audit_service.log(
            db=db,
            action=audit_service.INCIDENT_ASSIGNED,
            actor_id=user.id,
            target_type="incident",
            target_id=str(incident.id),
            result=AuditResult.SUCCESS,
            request_id=request_id,
            metadata={
                "incident_key": incident.incident_key,
                "assigned_to": str(assigned_to) if assigned_to else None,
                "assignee_name": assignee_name,
            }
        )

        return incident

    def add_note(
        self,
        incident_id: uuid.UUID,
        body: str,
        user: User,
        request_id: str,
        db: Session,
    ) -> IncidentNote:
        """Add an analyst investigation note to an incident."""
        repo = IncidentRepository(db)
        incident = repo.get_by_id(incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        if not body or not body.strip():
            raise ValueError("Note body cannot be empty or whitespace-only")

        if len(body) > 5000:
            raise ValueError("Note body exceeds maximum allowable length of 5000 characters")

        now = datetime.now(timezone.utc)
        note = IncidentNote(
            incident_id=incident.id,
            author_id=user.id,
            body=body.strip(),
            created_at=now,
            updated_at=now,
        )

        repo.add_note(note)

        # Timeline entry
        repo.add_timeline_entry(
            IncidentTimeline(
                incident_id=incident.id,
                timestamp=now,
                entry_type="NOTE_ADDED",
                title=f"Investigation Note added by {user.display_name}",
                summary=body.strip()[:200],
                timeline_metadata={"note_id": str(note.id)}
            )
        )

        # Audit log via AuditService
        audit_service.log(
            db=db,
            action=audit_service.INCIDENT_NOTE_ADDED,
            actor_id=user.id,
            target_type="incident",
            target_id=str(incident.id),
            result=AuditResult.SUCCESS,
            request_id=request_id,
            metadata={
                "incident_key": incident.incident_key,
                "note_id": str(note.id),
            }
        )

        return note

incident_service = IncidentService()

