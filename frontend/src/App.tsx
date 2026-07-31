import { FormEvent, useCallback, useEffect, useState } from 'react';

type Health = { status: string; app: string; version: string; environment?: string };
type User = { username: string; display_name: string; role: string };
type EventItem = {
  id: string; timestamp: string; source_type: string; event_type: string;
  source_ip?: string; destination_ip?: string; hostname?: string; username?: string;
  action?: string; outcome: string; severity: string; source_event_id?: string;
  raw_event: Record<string, unknown>; event_metadata: Record<string, unknown>;
};
type EventPage = { items: EventItem[]; page: number; page_size: number; total: number; pages: number };

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: { Accept: 'application/json', ...options.headers },
  });
  const rawBody = await response.text();
  let body: unknown = null;
  if (rawBody) {
    try { body = JSON.parse(rawBody); } catch { /* rendered below as a safe response error */ }
  }
  if (!response.ok) {
    const detail = typeof body === 'object' && body && 'detail' in body
      ? String((body as { detail: unknown }).detail)
      : rawBody || `${response.status} ${response.statusText}`;
    throw new Error(`Request failed (${response.status}): ${detail}`);
  }
  if (body === null) throw new Error('Backend returned an empty or non-JSON response.');
  return body as T;
}

const panel: React.CSSProperties = { background: '#111827', border: '1px solid #1f2937', borderRadius: 8, padding: '1.25rem', marginBottom: '1rem' };
const input: React.CSSProperties = { width: '100%', boxSizing: 'border-box', background: '#0b1220', color: '#f3f4f6', border: '1px solid #334155', borderRadius: 4, padding: '0.55rem', marginTop: '0.25rem' };
const button: React.CSSProperties = { background: '#0284c7', color: 'white', border: 0, borderRadius: 4, padding: '0.55rem 0.8rem', cursor: 'pointer', marginRight: '0.5rem', marginTop: '0.5rem' };

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [events, setEvents] = useState<EventPage | null>(null);
  const [selected, setSelected] = useState<EventItem | null>(null);
  const [sourceType, setSourceType] = useState<'linux_auth' | 'json'>('linux_auth');
  const [payload, setPayload] = useState('{"message":"Accepted password for demo from 192.0.2.10 port 22 ssh2"}');

  const loadHealth = useCallback(async () => {
    try { setHealth(await api<Health>('/api/v1/health')); setHealthError(null); }
    catch (error) { setHealth(null); setHealthError(error instanceof Error ? error.message : 'Unable to contact backend.'); }
  }, []);

  const loadEvents = useCallback(async (accessToken = token) => {
    if (!accessToken) return;
    try { setEvents(await api<EventPage>('/api/v1/events?page_size=25', { headers: { Authorization: `Bearer ${accessToken}` } })); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Could not load events.'); }
  }, [token]);

  useEffect(() => { void loadHealth(); }, [loadHealth]);

  async function login(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api<{ access_token: string; user: User }>('/api/v1/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }),
      });
      setToken(result.access_token); setUser(result.user); setPassword(''); setMessage(`Signed in as ${result.user.username}.`);
      await loadEvents(result.access_token);
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Login failed.'); }
  }

  async function submitTelemetry(batch = false) {
    if (!token) { setMessage('Sign in as an ADMIN or ANALYST to submit telemetry.'); return; }
    let parsedPayload: Record<string, unknown>;
    try { parsedPayload = JSON.parse(payload) as Record<string, unknown>; }
    catch { setMessage('Payload must be valid JSON.'); return; }
    const event = { source_type: sourceType, source_event_id: `ui-${Date.now()}`, payload: parsedPayload };
    const body = batch ? [event, { source_type: 'json', source_event_id: `ui-batch-${Date.now()}`, payload: { event: 'ui_batch_demo', user: user?.username } }] : event;
    try {
      const result = await api<{ accepted: number; duplicates?: number }>('/api/v1/events' + (batch ? '/batch' : ''), {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      setMessage(`Telemetry accepted: ${result.accepted} event(s)${result.duplicates ? `, ${result.duplicates} duplicate(s)` : ''}.`);
      await loadEvents();
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Telemetry submission failed.'); }
  }

  async function openEvent(eventId: string) {
    if (!token) return;
    try { setSelected(await api<EventItem>(`/api/v1/events/${eventId}`, { headers: { Authorization: `Bearer ${token}` } })); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Could not load event detail.'); }
  }

  return <div style={{ padding: '2rem', maxWidth: 1100, margin: '0 auto' }}>
    <header style={{ borderBottom: '1px solid #1f2937', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
      <h1 style={{ color: '#38bdf8', margin: 0, fontSize: '1.8rem' }}>CYBERWOLF SIEM</h1>
      <p style={{ color: '#9ca3af', margin: '0.3rem 0 0' }}>M00–M05 local security telemetry prototype</p>
    </header>

    <section style={panel}><h2 style={{ marginTop: 0 }}>Backend connection</h2>
      {health ? <span style={{ color: '#4ade80' }}>● Connected — {health.app} {health.version} ({health.status})</span> : <span style={{ color: '#f87171' }}>● {healthError || 'Connecting…'}</span>}
      <button type="button" style={button} onClick={() => void loadHealth()}>Refresh health</button>
    </section>

    {!user ? <section style={panel}><h2 style={{ marginTop: 0 }}>Sign in</h2><form onSubmit={login}>
      <label>Username<input style={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
      <label>Password<input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
      <button style={button} type="submit">Login</button>
    </form><p style={{ color: '#9ca3af', marginBottom: 0 }}>Create a local administrator with the documented bootstrap command; this UI never stores credentials or tokens in browser storage.</p></section>
    : <section style={panel}><strong>Authenticated:</strong> {user.display_name} ({user.role}) <button type="button" style={button} onClick={() => { setToken(null); setUser(null); setEvents(null); setSelected(null); setMessage('Signed out locally.'); }}>Logout</button></section>}

    {user && <><section style={panel}><h2 style={{ marginTop: 0 }}>Submit synthetic telemetry</h2>
      <label>Source type<select style={input} value={sourceType} onChange={(e) => setSourceType(e.target.value as 'linux_auth' | 'json')}><option value="linux_auth">Linux authentication</option><option value="json">JSON</option></select></label>
      <label>Payload (JSON)<textarea style={{ ...input, minHeight: 110 }} value={payload} onChange={(e) => setPayload(e.target.value)} /></label>
      <button type="button" style={button} onClick={() => void submitTelemetry(false)}>Submit event</button>
      <button type="button" style={button} onClick={() => void submitTelemetry(true)}>Submit demo batch</button>
    </section>
    <section style={panel}><h2 style={{ marginTop: 0 }}>Event explorer</h2><button type="button" style={button} onClick={() => void loadEvents()}>Refresh events</button>
      {events && <><p>{events.total} event(s), page {events.page} of {events.pages || 1}</p><div style={{ overflowX: 'auto' }}><table style={{ width: '100%', borderCollapse: 'collapse' }}><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>User</th><th>Outcome</th><th>Severity</th><th /></tr></thead><tbody>{events.items.map((item) => <tr key={item.id}><td>{new Date(item.timestamp).toLocaleString()}</td><td>{item.source_type}</td><td>{item.event_type}</td><td>{item.username || '—'}</td><td>{item.outcome}</td><td>{item.severity}</td><td><button type="button" style={button} onClick={() => void openEvent(item.id)}>Detail</button></td></tr>)}</tbody></table></div></>}
    </section>
    {selected && <section style={panel}><h2 style={{ marginTop: 0 }}>Event detail</h2><p><strong>{selected.id}</strong></p><p>{selected.source_type} / {selected.event_type} / {selected.outcome} / {selected.severity}</p><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', background: '#0b1220', padding: '0.75rem' }}>{JSON.stringify({ raw_event: selected.raw_event, metadata: selected.event_metadata }, null, 2)}</pre></section>}</>}
    {message && <p role="status" style={{ color: '#fbbf24' }}>{message}</p>}
  </div>;
}
