"""Initial Cyberwolf SIEM database schema migration

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-07-31

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('username', sa.String(length=120), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('display_name', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('role', sa.Enum('ADMIN', 'ANALYST', 'VIEWER', name='userrole'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # 2. assets
    op.create_table(
        'assets',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('os', sa.String(length=120), nullable=True),
        sa.Column('asset_type', sa.String(length=80), nullable=True),
        sa.Column('criticality', sa.SmallInteger(), nullable=False, server_default='50'),
        sa.Column('status', sa.Enum('ACTIVE', 'INACTIVE', 'UNKNOWN', name='assetstatus'), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_hostname'), 'assets', ['hostname'], unique=False)
    op.create_index(op.f('ix_assets_ip_address'), 'assets', ['ip_address'], unique=False)
    op.create_index(op.f('ix_assets_last_seen_at'), 'assets', ['last_seen_at'], unique=False)

    # 3. events
    op.create_table(
        'events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source_type', sa.String(length=80), nullable=False),
        sa.Column('event_type', sa.String(length=120), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('asset_id', sa.UUID(), nullable=True),
        sa.Column('action', sa.String(length=120), nullable=True),
        sa.Column('outcome', sa.Enum('SUCCESS', 'FAILURE', 'UNKNOWN', name='eventoutcome'), nullable=False),
        sa.Column('severity', sa.Enum('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity'), nullable=False),
        sa.Column('raw_event', sa.JSON(), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=False),
        sa.Column('source_event_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_events_source_type'), 'events', ['source_type'], unique=False)
    op.create_index(op.f('ix_events_event_type'), 'events', ['event_type'], unique=False)
    op.create_index(op.f('ix_events_source_ip'), 'events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_events_destination_ip'), 'events', ['destination_ip'], unique=False)
    op.create_index(op.f('ix_events_hostname'), 'events', ['hostname'], unique=False)
    op.create_index(op.f('ix_events_username'), 'events', ['username'], unique=False)
    op.create_index(op.f('ix_events_asset_id'), 'events', ['asset_id'], unique=False)

    # 4. detection_rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('rule_id', sa.String(length=80), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=80), nullable=True),
        sa.Column('event_types', sa.JSON(), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('group_by', sa.String(length=80), nullable=True),
        sa.Column('threshold', sa.Integer(), nullable=True),
        sa.Column('window_seconds', sa.Integer(), nullable=True),
        sa.Column('severity', sa.Enum('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity'), nullable=False),
        sa.Column('risk_weight', sa.SmallInteger(), nullable=False, server_default='50'),
        sa.Column('mitre_metadata', sa.JSON(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('rule_id')
    )
    op.create_index(op.f('ix_detection_rules_rule_id'), 'detection_rules', ['rule_id'], unique=True)

    # 5. alerts
    op.create_table(
        'alerts',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('rule_id', sa.UUID(), nullable=False),
        sa.Column('primary_event_id', sa.UUID(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity'), nullable=False),
        sa.Column('risk_score', sa.SmallInteger(), nullable=False, server_default='50'),
        sa.Column('status', sa.Enum('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', name='alertstatus'), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='check_alert_risk_score_bounds'),
        sa.ForeignKeyConstraint(['primary_event_id'], ['events.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_rule_id'), 'alerts', ['rule_id'], unique=False)
    op.create_index(op.f('ix_alerts_primary_event_id'), 'alerts', ['primary_event_id'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)

    # 6. alert_events
    op.create_table(
        'alert_events',
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('event_id', sa.UUID(), nullable=False),
        sa.Column('evidence_role', sa.String(length=80), nullable=False, server_default='supporting'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['event_id'], ['events.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('alert_id', 'event_id')
    )

    # 7. incidents
    op.create_table(
        'incidents',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('incident_key', sa.String(length=80), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('incident_type', sa.String(length=120), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity'), nullable=False),
        sa.Column('risk_score', sa.SmallInteger(), nullable=False, server_default='50'),
        sa.Column('status', sa.Enum('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', name='incidentstatus'), nullable=False),
        sa.Column('assigned_to', sa.UUID(), nullable=True),
        sa.Column('primary_asset_id', sa.UUID(), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('correlation_rule', sa.String(length=120), nullable=True),
        sa.Column('risk_explanation', sa.JSON(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='check_incident_risk_score_bounds'),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['primary_asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_key')
    )
    op.create_index(op.f('ix_incidents_incident_key'), 'incidents', ['incident_key'], unique=True)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)

    # 8. incident_alerts
    op.create_table(
        'incident_alerts',
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=False),
        sa.Column('correlation_role', sa.String(length=80), nullable=False, server_default='contributing'),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('incident_id', 'alert_id')
    )

    # 9. incident_timeline
    op.create_table(
        'incident_timeline',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('entry_type', sa.String(length=80), nullable=False),
        sa.Column('event_id', sa.UUID(), nullable=True),
        sa.Column('alert_id', sa.UUID(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['event_id'], ['events.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incident_timeline_incident_id'), 'incident_timeline', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_timeline_timestamp'), 'incident_timeline', ['timestamp'], unique=False)

    # 10. incident_notes
    op.create_table(
        'incident_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('author_id', sa.UUID(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incident_notes_incident_id'), 'incident_notes', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_notes_author_id'), 'incident_notes', ['author_id'], unique=False)

    # 11. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actor_id', sa.UUID(), nullable=True),
        sa.Column('action', sa.String(length=120), nullable=False),
        sa.Column('target_type', sa.String(length=80), nullable=True),
        sa.Column('target_id', sa.String(length=255), nullable=True),
        sa.Column('result', sa.Enum('SUCCESS', 'FAILURE', 'DENIED', name='auditresult'), nullable=False),
        sa.Column('request_id', sa.String(length=120), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_logs_actor_id'), 'audit_logs', ['actor_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_request_id'), 'audit_logs', ['request_id'], unique=False)

def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('incident_notes')
    op.drop_table('incident_timeline')
    op.drop_table('incident_alerts')
    op.drop_table('incidents')
    op.drop_table('alert_events')
    op.drop_table('alerts')
    op.drop_table('detection_rules')
    op.drop_table('events')
    op.drop_table('assets')
    op.drop_table('users')
