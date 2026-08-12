import React, { useState } from 'react';
import { Shield, KeyRound, User, AlertCircle } from 'lucide-react';

interface LoginViewProps {
  onLogin: (username: string, password: string) => Promise<void>;
  loading: boolean;
  error: string | null;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLogin, loading, error }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLogin(username, password);
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="login-icon">
            <Shield size={32} />
          </div>
          <h1 className="login-title">NEON SIEM</h1>
          <p className="login-subtitle">Authenticate to access operations center</p>
        </div>

        {error && (
          <div className="login-error">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="login-input-group">
            <label className="input-label" htmlFor="username">Username</label>
            <div className="login-input-wrapper">
              <span className="login-input-icon">
                <User size={16} />
              </span>
              <input
                id="username"
                type="text"
                className="login-input"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div className="login-input-group">
            <label className="input-label" htmlFor="password">Password</label>
            <div className="login-input-wrapper">
              <span className="login-input-icon">
                <KeyRound size={16} />
              </span>
              <input
                id="password"
                type="password"
                className="login-input"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <button
            type="submit"
            className="login-btn"
            disabled={loading || !username || !password}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
        
        <div className="login-footer">
          Authorized personnel only. All access is logged and monitored.
        </div>
      </div>
    </div>
  );
};
