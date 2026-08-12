import React from 'react';
import { ShieldCheck, RefreshCw, AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { IncidentSummary, IncidentStatus, Severity } from '../types';
import { SeverityBadge, StatusBadge } from './Badges';

interface IncidentQueueProps {
  incidents: IncidentSummary[];
  total: number;
  page: number;
  pages: number;
  loading: boolean;
  error: string | null;
  statusFilter: IncidentStatus | '';
  severityFilter: Severity | '';
  minRiskFilter: string;
  searchFilter: string;
  setStatusFilter: (s: IncidentStatus | '') => void;
  setSeverityFilter: (s: Severity | '') => void;
  setMinRiskFilter: (s: string) => void;
  setSearchFilter: (s: string) => void;
  onPageChange: (page: number) => void;
  onRefresh: () => void;
  onSelectIncident: (id: string) => void;
}

export const IncidentQueue: React.FC<IncidentQueueProps> = ({
  incidents,
  total,
  page,
  pages,
  loading,
  error,
  statusFilter,
  severityFilter,
  minRiskFilter,
  searchFilter,
  setStatusFilter,
  setSeverityFilter,
  setMinRiskFilter,
  setSearchFilter,
  onPageChange,
  onRefresh,
  onSelectIncident,
}) => {
  const getRiskClass = (score: number) => {
    if (score > 80) return 'text-critical text-error text-red-500'; // Fallbacks based on common classes
    if (score > 50) return 'text-high text-warning text-orange-500';
    return '';
  };

  const getRowClass = (severity: Severity) => {
    let base = 'row-clickable';
    if (severity === 'CRITICAL') return `${base} row-critical`;
    if (severity === 'HIGH') return `${base} row-high`;
    return base;
  };

  return (
    <div className="incident-queue">
      <header className="page-header">
        <div className="page-header-content">
          <div className="title-group">
            <ShieldCheck className="icon-header" size={28} />
            <div>
              <h1>
                Incident Queue
                {total > 0 && <span className="badge badge-subtle">{total}</span>}
              </h1>
              <p className="subtitle">Active security incidents requiring analyst attention</p>
            </div>
          </div>
          <div className="actions">
            <button className="btn btn-primary" onClick={onRefresh} disabled={loading}>
              <RefreshCw className={loading ? 'animate-spin' : ''} size={18} />
              <span>Refresh</span>
            </button>
          </div>
        </div>
      </header>

      <div className="filter-bar">
        <div className="input-group">
          <label className="input-label">Status</label>
          <select
            className="input"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as IncidentStatus | '')}
          >
            <option value="">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
        </div>

        <div className="input-group">
          <label className="input-label">Severity</label>
          <select
            className="input"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>
        </div>

        <div className="input-group">
          <label className="input-label">Min Risk Score</label>
          <input
            type="number"
            className="input"
            min="0"
            max="100"
            value={minRiskFilter}
            onChange={(e) => setMinRiskFilter(e.target.value)}
            placeholder="e.g. 50"
          />
        </div>

        <div className="input-group">
          <label className="input-label">Search Source IP</label>
          <input
            type="text"
            className="input"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="e.g. 192.168.1.1"
          />
        </div>
      </div>

      <div className="card card-flush">
        {loading && incidents.length === 0 ? (
          <div className="state-container">
            <RefreshCw className="animate-spin" size={32} />
            <p>Loading incidents...</p>
          </div>
        ) : error ? (
          <div className="state-error">
            <AlertCircle size={32} />
            <p>Error loading incidents: {error}</p>
            <button className="btn btn-secondary mt-4" onClick={onRefresh}>
              Retry
            </button>
          </div>
        ) : incidents.length === 0 ? (
          <div className="state-container">
            <ShieldCheck size={48} className="text-muted" />
            <p>No incidents match your criteria.</p>
          </div>
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>KEY</th>
                  <th>TITLE</th>
                  <th>SEVERITY</th>
                  <th>RISK</th>
                  <th>STATUS</th>
                  <th>ASSIGNED</th>
                  <th>LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className={getRowClass(incident.severity)}
                    onClick={() => onSelectIncident(incident.id)}
                  >
                    <td className="code-data">{incident.incident_key}</td>
                    <td className="font-medium">{incident.title}</td>
                    <td>
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className={`font-semibold ${getRiskClass(incident.risk_score)}`}>
                      {incident.risk_score}
                    </td>
                    <td>
                      <StatusBadge status={incident.status} />
                    </td>
                    <td>{incident.assignee_name || '—'}</td>
                    <td className="text-muted">
                      {new Date(incident.updated_at || incident.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <div className="pagination-info">
                Page {page} of {pages > 0 ? pages : 1}
              </div>
              <div className="pagination-actions">
                <button
                  className="btn btn-secondary btn-sm"
                  disabled={page <= 1}
                  onClick={() => onPageChange(page - 1)}
                >
                  <ChevronLeft size={16} />
                  Prev
                </button>
                <button
                  className="btn btn-secondary btn-sm"
                  disabled={page >= pages}
                  onClick={() => onPageChange(page + 1)}
                >
                  Next
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default IncidentQueue;
