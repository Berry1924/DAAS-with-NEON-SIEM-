import React, { useState } from 'react';
import { AuditLog, User } from '../types';
import { ShieldAlert, RefreshCw, ChevronDown, ChevronRight, Activity } from 'lucide-react';

interface AuditViewProps {
  auditLogs: AuditLog[];
  total: number;
  page: number;
  pages: number;
  loading: boolean;
  error: string | null;
  currentUser: User;
  actionFilter: string;
  requestIdFilter: string;
  actorFilter: string;
  setActionFilter: (action: string) => void;
  setRequestIdFilter: (reqId: string) => void;
  setActorFilter: (actor: string) => void;
  onPageChange: (page: number) => void;
  onRefresh: () => void;
}

export const AuditView: React.FC<AuditViewProps> = ({
  auditLogs,
  total,
  page,
  pages,
  loading,
  error,
  currentUser,
  actionFilter,
  requestIdFilter,
  actorFilter,
  setActionFilter,
  setRequestIdFilter,
  setActorFilter,
  onPageChange,
  onRefresh,
}) => {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  if (currentUser?.role !== 'ADMIN') {
    return (
      <div className="state-container state-error">
        <ShieldAlert className="state-icon" size={48} />
        <h3 className="state-title">Access Denied</h3>
        <p className="state-desc">You do not have permission to view the audit logs.</p>
      </div>
    );
  }

  const toggleRow = (id: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  return (
    <div>
      <div className="page-header">
        <div className="page-header-title">
          <h2>Audit Logs</h2>
          <span className="page-header-sub">System activity and access records ({total})</span>
        </div>
        <div className="page-header-actions">
          <button className="btn btn-secondary" onClick={onRefresh} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      <div className="filter-bar card">
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div>
            <label className="input-label">Action</label>
            <input
              type="text"
              className="input"
              placeholder="Filter by action..."
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
            />
          </div>
          <div>
            <label className="input-label">Actor</label>
            <input
              type="text"
              className="input"
              placeholder="Filter by actor..."
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
            />
          </div>
          <div>
            <label className="input-label">Request ID</label>
            <input
              type="text"
              className="input"
              placeholder="Filter by request ID..."
              value={requestIdFilter}
              onChange={(e) => setRequestIdFilter(e.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="card card-flush">
        {error ? (
          <div className="state-container state-error">
            <ShieldAlert className="state-icon" size={32} />
            <h3 className="state-title">Error</h3>
            <p className="state-desc">{error}</p>
          </div>
        ) : loading && auditLogs.length === 0 ? (
          <div className="state-container">
            <RefreshCw className="state-icon animate-spin" size={32} />
            <h3 className="state-title">Loading Logs</h3>
            <p className="state-desc">Fetching audit records...</p>
          </div>
        ) : auditLogs.length === 0 ? (
          <div className="state-container">
            <Activity className="state-icon" size={32} />
            <h3 className="state-title">No Logs Found</h3>
            <p className="state-desc">Adjust filters to see more results.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '40px' }}></th>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Resource</th>
                  <th>Status</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <React.Fragment key={log.id}>
                    <tr onClick={() => toggleRow(log.id)} style={{ cursor: 'pointer' }}>
                      <td>
                        {expandedRows.has(log.id) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      </td>
                      <td className="code-data font-mono">{new Date(log.timestamp).toLocaleString()}</td>
                      <td>
                        <span className="badge badge-info">{log.action}</span>
                      </td>
                      <td className="code-data font-mono">{log.actor_name || 'System'}</td>
                      <td className="code-data font-mono">{log.target_type} {log.target_id ? `(${log.target_id})` : ''}</td>
                      <td>
                        <span className={`badge ${log.result === 'SUCCESS' ? 'badge-resolved' : 'badge-critical'}`}>
                          {log.result}
                        </span>
                      </td>
                      <td className="code-data font-mono">{log.source_ip}</td>
                    </tr>
                    {expandedRows.has(log.id) && (
                      <tr className="expanded-row">
                        <td colSpan={7} style={{ padding: '1rem', backgroundColor: 'var(--surface-color)' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                            <div>
                              <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.875rem' }}>Details</h4>
                              <table className="data-table">
                                <tbody>
                                  <tr>
                                    <td style={{ width: '120px', fontWeight: 500 }}>ID</td>
                                    <td className="code-data font-mono">{log.id}</td>
                                  </tr>
                                  <tr>
                                    <td style={{ fontWeight: 500 }}>Request ID</td>
                                    <td className="code-data font-mono">{log.request_id}</td>
                                  </tr>
                                </tbody>
                              </table>
                            </div>
                            <div>
                              <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.875rem' }}>Metadata</h4>
                              <pre className="evidence-code">
                                {JSON.stringify(log.audit_metadata, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!error && total > 0 && (
        <div className="pagination">
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Showing page {page} of {pages} ({total} total records)
          </div>
          <div className="pagination-buttons">
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1 || loading}
            >
              Previous
            </button>
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => onPageChange(page + 1)}
              disabled={page >= pages || loading}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
