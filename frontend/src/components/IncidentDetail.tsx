import React, { useState } from 'react';
import { IncidentDetail, User, IncidentStatus } from '../types';
import { SeverityBadge, StatusBadge } from './Badges';
import {
  ArrowLeft, Clock, User as UserIcon, Network,
  ChevronDown, ChevronRight, Send, RefreshCw
} from 'lucide-react';

export interface IncidentDetailProps {
  incident: IncidentDetail;
  currentUser: User;
  usersList: User[];
  onBack: () => void;
  onUpdateStatus: (status: IncidentStatus, comment?: string) => Promise<void>;
  onAssignAnalyst: (assignedTo: string | null) => Promise<void>;
  onAddNote: (body: string) => Promise<void>;
  actionLoading: boolean;
  actionError: string | null;
}

const RISK_FACTOR_COLORS: Record<string, string> = {
  base_risk: '#58a6ff',
  correlation_bonus: '#ffba42',
  compromise_indicator: '#f85149',
  privilege_escalation: '#f0883e',
  asset_criticality: '#3fb950'
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f85149',
  HIGH: '#f0883e',
  MEDIUM: '#d29922',
  LOW: '#58a6ff',
  INFO: '#3fb950'
};

export const IncidentDetailView: React.FC<IncidentDetailProps> = ({
  incident,
  currentUser,
  usersList,
  onBack,
  onUpdateStatus,
  onAssignAnalyst,
  onAddNote,
  actionLoading,
  actionError
}) => {
  const [alertsExpanded, setAlertsExpanded] = useState(false);
  const [eventsExpanded, setEventsExpanded] = useState(false);
  
  const [statusInput, setStatusInput] = useState<IncidentStatus>(incident.status);
  const [assigneeInput, setAssigneeInput] = useState<string>(incident.assigned_to || '');
  const [noteInput, setNoteInput] = useState('');

  const canAction = currentUser.role === 'ADMIN' || currentUser.role === 'ANALYST';

  const handleStatusUpdate = async () => {
    await onUpdateStatus(statusInput);
  };

  const handleAssignUpdate = async () => {
    await onAssignAnalyst(assigneeInput === '' ? null : assigneeInput);
  };

  const handleAddNoteClick = async () => {
    if (!noteInput.trim()) return;
    await onAddNote(noteInput);
    setNoteInput('');
  };

  // SVG Ring calculations
  const ringRadius = 50;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringOffset = ringCircumference - ((incident.risk_score || 0) / 100) * ringCircumference;
  const ringColor = SEVERITY_COLORS[incident.severity] || SEVERITY_COLORS.LOW;

  return (
    <div className="incident-detail-container">
      <div className="mb-md">
        <button className="btn btn-ghost" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Back to Queue</span>
        </button>
      </div>

      <div className="flex justify-between items-start mb-lg">
        <div>
          <div className="flex items-center gap-sm mb-xs">
            <span className="code-data text-muted">{incident.incident_key}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
          <h1 className="title-sm m-0 mb-sm">{incident.title}</h1>
          <div className="flex items-center gap-md text-sm text-muted">
            <div className="flex items-center gap-xs">
              <Clock size={14} />
              <span>Created: {new Date(incident.created_at).toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-xs">
              <RefreshCw size={14} />
              <span>Last seen: {new Date(incident.last_seen_at || incident.created_at).toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-xs">
              <UserIcon size={14} />
              <span>Assigned to: {incident.assignee_name || incident.assigned_to || 'Unassigned'}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid-detail">
        <div className="detail-main">
          {/* Attack Sequence */}
          <div className="card mb-md">
            <h2 className="title-sm m-0 mb-md">Attack Sequence</h2>
            <div className="attack-sequence">
              {incident.linked_alerts && incident.linked_alerts.map((alert, idx) => (
                <div key={alert.alert_id} className="attack-step">
                  <div className="attack-step-connector">
                    <div 
                      className="attack-step-dot" 
                      style={{ backgroundColor: SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.LOW }}
                    />
                    {idx < incident.linked_alerts.length - 1 && <div className="attack-step-line" />}
                  </div>
                  <div className="attack-step-content pb-md">
                    <div className="flex items-center gap-sm mb-xs">
                      <SeverityBadge severity={alert.severity} />
                      <span className="attack-step-rule code-data text-xs">{alert.rule_id}</span>
                    </div>
                    <div className="text-sm font-medium">{alert.title}</div>
                  </div>
                </div>
              ))}
              {(!incident.linked_alerts || incident.linked_alerts.length === 0) && (
                <div className="text-muted text-sm">No linked alerts available.</div>
              )}
            </div>
          </div>

          {/* Timeline */}
          <div className="card mb-md">
            <div className="flex items-center justify-between mb-md">
              <h2 className="title-sm m-0">Investigation Timeline</h2>
              <span className="badge badge-default">{incident.timeline ? incident.timeline.length : 0}</span>
            </div>
            <div className="timeline">
              {incident.timeline && incident.timeline.map((entry, idx) => (
                <div key={entry.id || idx} className={`timeline-item event-${entry.entry_type.toLowerCase()}`}>
                  <div className="timeline-time text-xs text-muted mb-xs">
                    {new Date(entry.timestamp).toLocaleString()}
                  </div>
                  <div className="timeline-title font-medium text-sm mb-xs">
                    {entry.title}
                  </div>
                  {entry.summary && (
                    <div className="timeline-body text-sm text-muted">
                      {entry.summary}
                    </div>
                  )}
                </div>
              ))}
              {(!incident.timeline || incident.timeline.length === 0) && (
                <div className="text-muted text-sm">No timeline entries available.</div>
              )}
            </div>
          </div>

          {/* Evidence Panels */}
          <div className="card mb-md p-0">
            <div className="evidence-panel">
              <div 
                className="evidence-header flex items-center gap-sm p-md cursor-pointer border-b"
                onClick={() => setAlertsExpanded(!alertsExpanded)}
              >
                {alertsExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <h3 className="text-sm font-medium m-0">
                  Linked Alerts ({incident.linked_alerts ? incident.linked_alerts.length : 0})
                </h3>
              </div>
              {alertsExpanded && (
                <div className="p-md">
                  <div className="table-responsive">
                    <table className="table w-full text-sm">
                      <thead>
                        <tr>
                          <th>RULE ID</th>
                          <th>TITLE</th>
                          <th>SEVERITY</th>
                          <th>RISK</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incident.linked_alerts && incident.linked_alerts.map(alert => (
                          <tr key={alert.alert_id}>
                            <td className="code-data text-xs">{alert.rule_id}</td>
                            <td>{alert.title}</td>
                            <td><SeverityBadge severity={alert.severity} /></td>
                            <td>{alert.risk_score}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
            <div className="evidence-panel border-t">
              <div 
                className="evidence-header flex items-center gap-sm p-md cursor-pointer border-b"
                onClick={() => setEventsExpanded(!eventsExpanded)}
              >
                {eventsExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <h3 className="text-sm font-medium m-0">
                  Event Evidence ({incident.linked_events ? incident.linked_events.length : 0})
                </h3>
              </div>
              {eventsExpanded && (
                <div className="p-md">
                  <div className="table-responsive">
                    <table className="table w-full text-sm">
                      <thead>
                        <tr>
                          <th>TIMESTAMP</th>
                          <th>TYPE</th>
                          <th>SOURCE</th>
                          <th>DESTINATION</th>
                          <th>OUTCOME</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incident.linked_events && incident.linked_events.map(evt => (
                          <tr key={evt.id}>
                            <td className="text-xs text-nowrap">{new Date(evt.timestamp).toLocaleString()}</td>
                            <td>{evt.event_type}</td>
                            <td className="code-data text-xs">{evt.source_ip || '-'}</td>
                            <td className="code-data text-xs">{evt.destination_ip || '-'}</td>
                            <td>{evt.outcome}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Investigation Notes */}
          <div className="card">
            <div className="flex items-center justify-between mb-md">
              <h2 className="title-sm m-0">Investigation Notes</h2>
              <span className="badge badge-default">{incident.notes ? incident.notes.length : 0}</span>
            </div>

            {canAction && (
              <div className="mb-lg">
                <textarea
                  className="input input-code w-full mb-sm"
                  rows={3}
                  placeholder="Add an investigation note..."
                  value={noteInput}
                  onChange={(e) => setNoteInput(e.target.value)}
                />
                <div className="flex justify-end">
                  <button 
                    className="btn btn-primary"
                    onClick={handleAddNoteClick}
                    disabled={actionLoading || !noteInput.trim()}
                  >
                    <Send size={14} />
                    <span>Add Note</span>
                  </button>
                </div>
              </div>
            )}

            <div className="notes-list flex flex-col gap-md">
              {incident.notes && incident.notes.map(note => (
                <div key={note.id} className="card bg-panel border">
                  <div className="flex items-center gap-sm mb-sm text-sm">
                    <UserIcon size={14} className="text-muted" />
                    <span className="font-medium">{note.author_name || note.author_id}</span>
                    <span className="text-muted text-xs">•</span>
                    <span className="text-muted text-xs">{new Date(note.created_at).toLocaleString()}</span>
                  </div>
                  <div className="text-sm whitespace-pre-wrap">
                    {note.body}
                  </div>
                </div>
              ))}
              {(!incident.notes || incident.notes.length === 0) && (
                <div className="text-muted text-sm text-center p-md">
                  No notes have been added yet.
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="detail-sidebar">
          {/* Risk Score Card */}
          <div className="card mb-md">
            <div className="flex flex-col items-center mb-md">
              <div className="relative" style={{ width: 120, height: 120 }}>
                <svg width="120" height="120" viewBox="0 0 120 120" className="rotate-[-90deg]">
                  <circle
                    cx="60"
                    cy="60"
                    r={ringRadius}
                    fill="none"
                    stroke="var(--border)"
                    strokeWidth="8"
                  />
                  <circle
                    cx="60"
                    cy="60"
                    r={ringRadius}
                    fill="none"
                    stroke={ringColor}
                    strokeWidth="8"
                    strokeDasharray={ringCircumference}
                    strokeDashoffset={ringOffset}
                    strokeLinecap="round"
                    className="transition-all duration-1000 ease-out"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="risk-ring-value text-2xl font-bold">{incident.risk_score}</span>
                  <span className="risk-ring-label text-xs text-muted font-medium tracking-wider">RISK</span>
                </div>
              </div>
              <div className="mt-md">
                <SeverityBadge severity={incident.severity} />
              </div>
            </div>

            {incident.risk_explanation && incident.risk_explanation.factors && (
              <div className="risk-factors flex flex-col gap-sm">
                {incident.risk_explanation.factors.map((factor, idx) => (
                  <div key={idx} className="risk-factor">
                    <div className="flex justify-between items-center mb-xs text-xs">
                      <span className="risk-factor-label font-medium">{factor.label || factor.type.replace(/_/g, ' ').toUpperCase()}</span>
                      <span className="risk-factor-points font-mono">+{factor.points}</span>
                    </div>
                    <div className="risk-factor-bar h-1.5 w-full bg-border rounded overflow-hidden">
                      <div 
                        className="risk-factor-fill h-full rounded"
                        style={{ 
                          width: `${Math.min((factor.points / 100) * 100, 100)}%`,
                          backgroundColor: RISK_FACTOR_COLORS[factor.type] || '#58a6ff'
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Entity Context */}
          <div className="card mb-md">
            <h2 className="title-sm m-0 mb-md">Entity Context</h2>
            <div className="flex flex-col gap-sm">
              {incident.source_ip && (
                <div className="entity-chip flex items-center gap-sm p-sm border rounded bg-panel">
                  <Network size={14} className="text-muted" />
                  <div>
                    <div className="text-xs text-muted mb-0.5">Source IP</div>
                    <div className="code-data text-sm">{incident.source_ip}</div>
                  </div>
                </div>
              )}
              {incident.destination_ip && (
                <div className="entity-chip flex items-center gap-sm p-sm border rounded bg-panel">
                  <Network size={14} className="text-muted" />
                  <div>
                    <div className="text-xs text-muted mb-0.5">Destination IP</div>
                    <div className="code-data text-sm">{incident.destination_ip}</div>
                  </div>
                </div>
              )}
              {incident.username && (
                <div className="entity-chip flex items-center gap-sm p-sm border rounded bg-panel">
                  <UserIcon size={14} className="text-muted" />
                  <div>
                    <div className="text-xs text-muted mb-0.5">Username</div>
                    <div className="code-data text-sm">{incident.username}</div>
                  </div>
                </div>
              )}
              {!incident.source_ip && !incident.destination_ip && !incident.username && (
                <div className="text-muted text-sm text-center">No entities extracted.</div>
              )}
            </div>
          </div>

          {/* Actions */}
          {canAction && (
            <div className="card">
              <h2 className="title-sm m-0 mb-md">Actions</h2>
              
              {actionError && (
                <div className="bg-red-500/10 text-red-500 text-sm p-sm rounded mb-md border border-red-500/20">
                  {actionError}
                </div>
              )}

              <div className="mb-md">
                <label className="block text-xs font-medium text-muted mb-xs">Update Status</label>
                <div className="flex gap-sm">
                  <select 
                    className="input w-full"
                    value={statusInput}
                    onChange={(e) => setStatusInput(e.target.value as IncidentStatus)}
                    disabled={actionLoading}
                  >
                    <option value="NEW">New</option>
                    <option value="ACKNOWLEDGED">Acknowledged</option>
                    <option value="INVESTIGATING">Investigating</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="FALSE_POSITIVE">False Positive</option>
                  </select>
                  <button 
                    className="btn btn-secondary whitespace-nowrap"
                    onClick={handleStatusUpdate}
                    disabled={actionLoading || statusInput === incident.status}
                  >
                    Update
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-muted mb-xs">Assign Analyst</label>
                <div className="flex gap-sm">
                  <select 
                    className="input w-full"
                    value={assigneeInput}
                    onChange={(e) => setAssigneeInput(e.target.value)}
                    disabled={actionLoading}
                  >
                    <option value="">Unassigned</option>
                    {usersList.map(u => (
                      <option key={u.id || u.username} value={u.username}>{u.display_name || u.username}</option>
                    ))}
                  </select>
                  <button 
                    className="btn btn-secondary whitespace-nowrap"
                    onClick={handleAssignUpdate}
                    disabled={actionLoading || assigneeInput === (incident.assigned_to || '')}
                  >
                    Assign
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
