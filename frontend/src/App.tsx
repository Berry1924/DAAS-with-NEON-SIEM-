import { useEffect, useState } from 'react';

export default function App() {
  const [health, setHealth] = useState<{ status: string; app: string; version: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/v1/health')
      .then((res) => res.json())
      .then((data) => setHealth(data))
      .catch((err) => setError('Backend API disconnected: ' + err.message));
  }, []);

  return (
    <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <header style={{ borderBottom: '1px solid #1f2937', paddingBottom: '1rem', marginBottom: '2rem' }}>
        <h1 style={{ color: '#38bdf8', margin: 0, fontSize: '1.8rem' }}>CYBERWOLF SIEM</h1>
        <p style={{ color: '#9ca3af', marginTop: '0.25rem' }}>Security Operations Center Baseline</p>
      </header>
      
      <main>
        <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.2rem', marginTop: 0 }}>System Health Status</h2>
          {health ? (
            <div style={{ color: '#4ade80' }}>
              <p>🟢 <strong>Status:</strong> {health.status.toUpperCase()}</p>
              <p><strong>System:</strong> {health.app} (v{health.version})</p>
            </div>
          ) : error ? (
            <div style={{ color: '#f87171' }}>🔴 {error}</div>
          ) : (
            <div style={{ color: '#9ca3af' }}>Connecting to backend...</div>
          )}
        </div>
      </main>
    </div>
  );
}
