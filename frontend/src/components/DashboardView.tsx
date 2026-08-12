import React from 'react';
import { Activity, RefreshCw, TrendingUp, ShieldAlert, Layers, ArrowRight } from 'lucide-react';
import { DashboardSummary } from '../types';
import { SeverityBadge, StatusBadge } from './Badges';

interface DashboardViewProps {
  summary: DashboardSummary | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onSelectIncident: (id: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  summary,
  loading,
  error,
  onRefresh,
  onSelectIncident
}) => {
  if (loading && !summary) {
    return (
      <div className="state-container">
        <RefreshCw className="animate-spin text-muted" size={32} />
        <div className="state-title">Loading Dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="state-container state-error">
        <ShieldAlert size={32} className="text-error" />
        <div className="state-title">Failed to Load Dashboard</div>
        <div className="state-message">{error}</div>
        <button className="btn btn-primary" onClick={onRefresh}>
          Retry
        </button>
      </div>
    );
  }

  // Fallback defaults
  const totalEvents24h = summary?.total_events_24h || 0;
  const openIncidents = summary?.open_incidents || 0;
  
  const activeAlerts = (summary?.active_alerts_by_severity || []).reduce((acc, item) => acc + item.count, 0);
  const criticalAlertsItem = (summary?.active_alerts_by_severity || []).find(i => i.severity === 'CRITICAL');
  const criticalAlerts = criticalAlertsItem ? criticalAlertsItem.count : 0;

  const eventTrend = summary?.event_trend || [];
  const maxTrendCount = eventTrend.reduce((max, item) => Math.max(max, item.count), 0);
  
  const activeAlertsBySeverity = summary?.active_alerts_by_severity || [];
  const maxSeverityCount = activeAlertsBySeverity.reduce((max, item) => Math.max(max, item.count), 0);

  const topDetectionRules = summary?.top_detection_rules || [];
  const recentIncidents = summary?.recent_incidents || [];

  return (
    <div className="page-container">
      <div className="page-header">
        <div className="page-title-group">
          <Activity className="text-primary" size={24} />
          <div>
            <h1 className="page-title">SOC Command Center</h1>
            <div className="page-subtitle">Overview of security alerts and incidents</div>
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-secondary" onClick={onRefresh} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid-metrics">
        <div className="metric-card">
          <div className="metric-label">Total Events 24h</div>
          <div className="metric-value text-primary">{totalEvents24h.toLocaleString()}</div>
          <div className="metric-sub">Events processed in the last 24 hours</div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Open Incidents</div>
          <div className={`metric-value ${openIncidents > 0 ? 'text-error' : 'text-success'}`}>
            {openIncidents.toLocaleString()}
          </div>
          <div className="metric-sub">Incidents requiring attention</div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Active Alerts</div>
          <div className="metric-value text-warning">{activeAlerts.toLocaleString()}</div>
          <div className="metric-sub">Unresolved alerts across all severities</div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Critical Alerts</div>
          <div className={`metric-value ${criticalAlerts > 0 ? 'text-error' : ''}`}>
            {criticalAlerts.toLocaleString()}
          </div>
          <div className="metric-sub">Highest priority alerts</div>
        </div>
      </div>

      <div className="grid-2col">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <TrendingUp size={18} className="text-muted" />
              Event Trend (24h)
            </h2>
          </div>
          <div className="card-body">
            <div className="chart-container">
              {eventTrend.length > 0 ? (
                eventTrend.map((item, idx) => {
                  const heightPct = maxTrendCount > 0 ? (item.count / maxTrendCount) * 100 : 0;
                  return (
                    <div 
                      key={idx}
                      className={`chart-bar ${item.count > 0 ? 'bg-primary' : 'bg-empty'}`}
                      style={{ height: `${Math.max(heightPct, 1)}%` }}
                      title={`${item.hour}: ${item.count}`}
                    />
                  );
                })
              ) : (
                <div className="chart-empty text-muted">
                  No event data
                </div>
              )}
              {eventTrend.length > 0 && (
                <>
                  <div className="chart-label-left">-24h</div>
                  <div className="chart-label-center">-12h</div>
                  <div className="chart-label-right">Now</div>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Layers size={18} className="text-muted" />
              Severity Breakdown
            </h2>
          </div>
          <div className="card-body">
            <div className="severity-chart-container">
              {activeAlertsBySeverity.length > 0 ? (
                activeAlertsBySeverity.map((item) => {
                  const widthPct = maxSeverityCount > 0 ? (item.count / maxSeverityCount) * 100 : 0;
                  let colorClass = 'info';
                  if (item.severity === 'CRITICAL') colorClass = 'critical';
                  else if (item.severity === 'HIGH') colorClass = 'high';
                  else if (item.severity === 'MEDIUM') colorClass = 'medium';
                  else if (item.severity === 'LOW') colorClass = 'low';
                  
                  return (
                    <div key={item.severity} className="severity-row">
                      <div className="severity-label">
                        {item.severity}
                      </div>
                      <div className="severity-bar-track">
                        <div className={`severity-bar-fill ${colorClass}`} style={{ width: `${widthPct}%` }} />
                      </div>
                      <div className="severity-value">
                        {item.count}
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-muted text-center">No active alerts</div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <ShieldAlert size={18} className="text-muted" />
            Top Detection Rules
          </h2>
        </div>
        <div className="card-body p-0">
          <table className="data-table">
            <thead>
              <tr>
                <th>RULE ID</th>
                <th>NAME</th>
                <th className="text-right">TRIGGERS</th>
              </tr>
            </thead>
            <tbody>
              {topDetectionRules.length > 0 ? (
                topDetectionRules.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td className="code-data">{rule.rule_id}</td>
                    <td>{rule.name || 'Unknown Rule'}</td>
                    <td className="text-right">{rule.count.toLocaleString()}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="text-center text-muted py-4">No detection rules triggered</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <Activity size={18} className="text-muted" />
            Recent Incidents
          </h2>
        </div>
        <div className="card-body p-0">
          <table className="data-table">
            <thead>
              <tr>
                <th>KEY</th>
                <th>TITLE</th>
                <th>SEVERITY</th>
                <th>RISK</th>
                <th>STATUS</th>
                <th>CREATED</th>
                <th className="w-8"></th>
              </tr>
            </thead>
            <tbody>
              {recentIncidents.length > 0 ? (
                recentIncidents.map((incident) => (
                  <tr 
                    key={incident.id} 
                    className={`cursor-pointer hover-row ${incident.severity === 'CRITICAL' ? 'row-critical' : ''}`}
                    onClick={() => onSelectIncident(incident.id)}
                  >
                    <td className="code-data text-muted">{incident.incident_key}</td>
                    <td className="font-medium">{incident.title}</td>
                    <td><SeverityBadge severity={incident.severity} /></td>
                    <td>
                      <span className={`badge ${incident.risk_score >= 80 ? 'badge-error' : incident.risk_score >= 50 ? 'badge-warning' : 'badge-neutral'}`}>
                        {incident.risk_score}
                      </span>
                    </td>
                    <td><StatusBadge status={incident.status} /></td>
                    <td className="text-muted text-sm">{new Date(incident.created_at).toLocaleString()}</td>
                    <td className="text-right">
                      <ArrowRight size={16} className="text-muted" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center text-muted py-4">No recent incidents</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
