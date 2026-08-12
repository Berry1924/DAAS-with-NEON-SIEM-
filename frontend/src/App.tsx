import { useState, useEffect, useCallback } from 'react';
import {
  User,
  Health,
  IncidentDetail,
  IncidentPage,
  IncidentStatus,
  Severity,
  AuditPage,
  DashboardSummary
} from './types';
import { request } from './api/client';
import { TopBar } from './components/Header';
import { Sidebar, NavTab } from './components/Sidebar';
import { LoginView } from './components/LoginView';
import { IncidentQueue } from './components/IncidentQueue';
import { IncidentDetailView } from './components/IncidentDetail';
import { AuditView } from './components/AuditView';
import { DashboardView } from './components/DashboardView';
import { Search, Activity } from 'lucide-react';

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');

  // Dashboard State
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState<string | null>(null);

  // Incidents State
  const [incidentPage, setIncidentPage] = useState<IncidentPage | null>(null);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | ''>('');
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [minRiskFilter, setMinRiskFilter] = useState<string>('');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [incPageNum, setIncPageNum] = useState(1);

  // Selected Incident Detail State
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // System Users List for Assignment Dropdown
  const [usersList, setUsersList] = useState<User[]>([]);

  // Audit Logs State
  const [auditPage, setAuditPage] = useState<AuditPage | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [auditReqIdFilter, setAuditReqIdFilter] = useState('');
  const [auditActorFilter, setAuditActorFilter] = useState('');
  const [auditPageNum, setAuditPageNum] = useState(1);

  // M00-M05 Prototype State
  const [sourceType, setSourceType] = useState<'linux_auth' | 'json'>('linux_auth');
  const [payload, setPayload] = useState('{"message":"Accepted password for demo from 192.0.2.10 port 22 ssh2"}');
  const [protoMessage, setProtoMessage] = useState<string | null>(null);

  const handleUnauthorized = useCallback(() => {
    setToken(null);
    setUser(null);
    setAuthError('Session expired. Please sign in again.');
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      const h = await request<Health>('/api/v1/health');
      setHealth(h);
      setHealthError(null);
    } catch (err) {
      setHealth(null);
      setHealthError(err instanceof Error ? err.message : 'Unable to connect to backend.');
    }
  }, []);

  useEffect(() => {
    void loadHealth();
  }, [loadHealth]);

  // Load Incident Queue
  const loadIncidents = useCallback(async (accessToken = token) => {
    if (!accessToken) return;
    setIncidentsLoading(true);
    setIncidentsError(null);

    const query = new URLSearchParams();
    query.set('page', String(incPageNum));
    query.set('page_size', '20');
    if (statusFilter) query.set('status', statusFilter);
    if (severityFilter) query.set('severity', severityFilter);
    if (minRiskFilter) query.set('min_risk', minRiskFilter);
    if (searchFilter) query.set('source_ip', searchFilter);

    try {
      const res = await request<IncidentPage>(`/api/v1/incidents?${query.toString()}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }, handleUnauthorized);
      setIncidentPage(res);
    } catch (err) {
      setIncidentsError(err instanceof Error ? err.message : 'Could not load incident queue.');
    } finally {
      setIncidentsLoading(false);
    }
  }, [token, incPageNum, statusFilter, severityFilter, minRiskFilter, searchFilter, handleUnauthorized]);

  // Load Incident Detail
  const loadIncidentDetail = useCallback(async (id: string, accessToken = token) => {
    if (!accessToken || !id) return;
    setDetailLoading(true);
    setDetailError(null);

    try {
      const detail = await request<IncidentDetail>(`/api/v1/incidents/${id}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }, handleUnauthorized);
      setIncidentDetail(detail);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Could not load incident detail.');
    } finally {
      setDetailLoading(false);
    }
  }, [token, handleUnauthorized]);

  // Load Audit Trail
  const loadAuditLogs = useCallback(async (accessToken = token) => {
    if (!accessToken) return;
    setAuditLoading(true);
    setAuditError(null);

    const query = new URLSearchParams();
    query.set('page', String(auditPageNum));
    query.set('page_size', '20');
    if (auditActionFilter) query.set('action', auditActionFilter);
    if (auditReqIdFilter) query.set('request_id', auditReqIdFilter);
    if (auditActorFilter) query.set('actor_name', auditActorFilter);

    try {
      const res = await request<AuditPage>(`/api/v1/audit?${query.toString()}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }, handleUnauthorized);
      setAuditPage(res);
    } catch (err) {
      setAuditError(err instanceof Error ? err.message : 'Could not load audit logs.');
    } finally {
      setAuditLoading(false);
    }
  }, [token, auditPageNum, auditActionFilter, auditReqIdFilter, auditActorFilter, handleUnauthorized]);

  // Load Users List for assignment dropdown
  const loadUsersList = useCallback(async (accessToken = token) => {
    if (!accessToken) return;
    try {
      const res = await request<User[]>('/api/v1/users', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      setUsersList(res);
    } catch {
      // Fallback
    }
  }, [token]);

  // Load Dashboard Summary
  const loadDashboardSummary = useCallback(async (accessToken = token) => {
    if (!accessToken) return;
    setDashboardLoading(true);
    setDashboardError(null);

    try {
      const summary = await request<DashboardSummary>('/api/v1/dashboard/summary', {
        headers: { Authorization: `Bearer ${accessToken}` },
      }, handleUnauthorized);
      setDashboardSummary(summary);
    } catch (err) {
      setDashboardError(err instanceof Error ? err.message : 'Could not load dashboard summary.');
    } finally {
      setDashboardLoading(false);
    }
  }, [token, handleUnauthorized]);

  useEffect(() => {
    if (token) {
      if (activeTab === 'dashboard') {
        void loadDashboardSummary();
      } else if (activeTab === 'incidents') {
        if (selectedIncidentId) {
          void loadIncidentDetail(selectedIncidentId);
        } else {
          void loadIncidents();
        }
      } else if (activeTab === 'audit' && user?.role === 'ADMIN') {
        void loadAuditLogs();
      }
      void loadUsersList();
    }
  }, [token, activeTab, selectedIncidentId, loadDashboardSummary, loadIncidents, loadIncidentDetail, loadAuditLogs, loadUsersList, user?.role]);

  // Login Handler
  const handleLogin = async (usr: string, pass: string) => {
    setAuthLoading(true);
    setAuthError(null);
    try {
      const res = await request<{ access_token: string; user: User }>('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usr, password: pass }),
      });
      setToken(res.access_token);
      setUser(res.user);
      setActiveTab('incidents');
      void loadIncidents(res.access_token);
      void loadUsersList(res.access_token);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Authentication failed.');
    } finally {
      setAuthLoading(false);
    }
  };

  // Logout Handler
  const handleLogout = () => {
    setToken(null);
    setUser(null);
    setSelectedIncidentId(null);
    setIncidentDetail(null);
    setIncidentPage(null);
    setAuditPage(null);
  };

  // Incident Actions
  const handleUpdateStatus = async (newStatus: IncidentStatus, comment?: string) => {
    if (!token || !selectedIncidentId) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await request(`/api/v1/incidents/${selectedIncidentId}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, comment }),
      }, handleUnauthorized);
      await loadIncidentDetail(selectedIncidentId);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Status update failed.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAssignAnalyst = async (assignedTo: string | null) => {
    if (!token || !selectedIncidentId) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await request(`/api/v1/incidents/${selectedIncidentId}/assign`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: assignedTo }),
      }, handleUnauthorized);
      await loadIncidentDetail(selectedIncidentId);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Assignment failed.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddNote = async (body: string) => {
    if (!token || !selectedIncidentId) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await request(`/api/v1/incidents/${selectedIncidentId}/notes`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ body }),
      }, handleUnauthorized);
      await loadIncidentDetail(selectedIncidentId);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Adding note failed.');
    } finally {
      setActionLoading(false);
    }
  };

  // Prototype Actions
  const submitTelemetry = async (batch = false) => {
    if (!token) return;
    let parsedPayload: Record<string, unknown>;
    try {
      parsedPayload = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      setProtoMessage('Payload must be valid JSON.');
      return;
    }
    const eventObj = { source_type: sourceType, source_event_id: `ui-${Date.now()}`, payload: parsedPayload };
    const body = batch
      ? [eventObj, { source_type: 'json', source_event_id: `ui-batch-${Date.now()}`, payload: { event: 'ui_batch_demo', user: user?.username } }]
      : eventObj;
    try {
      const res = await request<{ accepted: number; duplicates?: number }>('/api/v1/events' + (batch ? '/batch' : ''), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      setProtoMessage(`Telemetry accepted: ${res.accepted} event(s)${res.duplicates ? `, ${res.duplicates} duplicate(s)` : ''}.`);
    } catch (err) {
      setProtoMessage(err instanceof Error ? err.message : 'Telemetry submission failed.');
    }
  };

  // ── Render: Login ──
  if (!user) {
    return <LoginView onLogin={handleLogin} loading={authLoading} error={authError} />;
  }

  // ── Render: Authenticated App Shell ──
  return (
    <div className="app-shell">
      <Sidebar
        user={user}
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setSelectedIncidentId(null);
          setIncidentDetail(null);
          setActiveTab(tab);
        }}
        onLogout={handleLogout}
        openIncidents={dashboardSummary?.open_incidents}
      />

      <div className="app-main">
        <TopBar
          health={health}
          healthError={healthError}
          onRefreshHealth={() => void loadHealth()}
        />

        <div className="app-content animate-fadeIn">
          {activeTab === 'dashboard' && (
            <DashboardView
              summary={dashboardSummary}
              loading={dashboardLoading}
              error={dashboardError}
              onRefresh={() => void loadDashboardSummary()}
              onSelectIncident={(id) => {
                setSelectedIncidentId(id);
                setActiveTab('incidents');
                void loadIncidentDetail(id);
              }}
            />
          )}

          {activeTab === 'incidents' && (
            selectedIncidentId ? (
              detailLoading ? (
                <div className="state-container">
                  <div className="state-icon animate-spin">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                    </svg>
                  </div>
                  <div className="state-title">Loading incident details…</div>
                </div>
              ) : detailError ? (
                <div className="state-error" style={{ maxWidth: 600, margin: '2rem auto' }}>
                  <div className="font-bold mb-sm">Failed to load incident detail:</div>
                  <div className="mb-md">{detailError}</div>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      setSelectedIncidentId(null);
                      setIncidentDetail(null);
                    }}
                  >
                    Back to Queue
                  </button>
                </div>
              ) : incidentDetail ? (
                <IncidentDetailView
                  incident={incidentDetail}
                  currentUser={user}
                  usersList={usersList}
                  onBack={() => {
                    setSelectedIncidentId(null);
                    setIncidentDetail(null);
                    void loadIncidents();
                  }}
                  onUpdateStatus={handleUpdateStatus}
                  onAssignAnalyst={handleAssignAnalyst}
                  onAddNote={handleAddNote}
                  actionLoading={actionLoading}
                  actionError={actionError}
                />
              ) : null
            ) : (
              <IncidentQueue
                incidents={incidentPage?.items || []}
                total={incidentPage?.total || 0}
                page={incPageNum}
                pages={incidentPage?.pages || 1}
                loading={incidentsLoading}
                error={incidentsError}
                statusFilter={statusFilter}
                severityFilter={severityFilter}
                minRiskFilter={minRiskFilter}
                searchFilter={searchFilter}
                setStatusFilter={setStatusFilter}
                setSeverityFilter={setSeverityFilter}
                setMinRiskFilter={setMinRiskFilter}
                setSearchFilter={setSearchFilter}
                onPageChange={(p) => setIncPageNum(p)}
                onRefresh={() => void loadIncidents()}
                onSelectIncident={(id) => {
                  setSelectedIncidentId(id);
                  void loadIncidentDetail(id);
                }}
              />
            )
          )}

          {activeTab === 'audit' && (
            <AuditView
              auditLogs={auditPage?.items || []}
              total={auditPage?.total || 0}
              page={auditPageNum}
              pages={auditPage?.pages || 1}
              loading={auditLoading}
              error={auditError}
              currentUser={user}
              actionFilter={auditActionFilter}
              requestIdFilter={auditReqIdFilter}
              actorFilter={auditActorFilter}
              setActionFilter={setAuditActionFilter}
              setRequestIdFilter={setAuditReqIdFilter}
              setActorFilter={setAuditActorFilter}
              onPageChange={(p) => setAuditPageNum(p)}
              onRefresh={() => void loadAuditLogs()}
            />
          )}

          {activeTab === 'telemetry' && (
            <div style={{ maxWidth: 1000 }}>
              <div className="page-header">
                <div>
                  <h2 className="page-header-title">
                    <Activity size={22} className="text-primary" />
                    <span>Submit Telemetry</span>
                  </h2>
                  <div className="page-header-sub">Inject synthetic security events into the pipeline</div>
                </div>
              </div>

              <div className="card">
                <div className="mb-md">
                  <label className="input-label">Source Type</label>
                  <select
                    className="input"
                    value={sourceType}
                    onChange={(e) => setSourceType(e.target.value as 'linux_auth' | 'json')}
                  >
                    <option value="linux_auth">Linux Authentication Log</option>
                    <option value="json">Raw JSON</option>
                  </select>
                </div>

                <div className="mb-md">
                  <label className="input-label">JSON Payload</label>
                  <textarea
                    className="input input-code"
                    value={payload}
                    onChange={(e) => setPayload(e.target.value)}
                    rows={5}
                  />
                </div>

                <div className="flex gap-sm">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => void submitTelemetry(false)}
                  >
                    Submit Event
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => void submitTelemetry(true)}
                  >
                    Submit Demo Batch
                  </button>
                </div>
              </div>

              {protoMessage && (
                <p role="status" className="text-warning font-bold mt-md">
                  {protoMessage}
                </p>
              )}
            </div>
          )}

          {activeTab === 'events' && (
            <div className="state-container">
              <Search size={48} className="state-icon" />
              <div className="state-title">Event Search</div>
              <div className="state-desc">
                Event search and investigation tools. Use the Ingest tab to submit telemetry, then view events via the Incident evidence panel.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
