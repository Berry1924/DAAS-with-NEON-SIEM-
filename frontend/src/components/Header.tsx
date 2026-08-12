import React from 'react';
import { Health } from '../types';
import { RefreshCw } from 'lucide-react';

interface TopBarProps {
  health: Health | null;
  healthError: string | null;
  onRefreshHealth: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  health,
  healthError,
  onRefreshHealth,
}) => {
  return (
    <div className="topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="health-pill"
          onClick={onRefreshHealth}
          title="Click to refresh connection status"
        >
          <span
            className={`health-dot ${
              health ? 'connected' : healthError ? 'error' : 'loading'
            }`}
          />
          {health ? (
            <span>Connected · {health.version}</span>
          ) : (
            <span>{healthError || 'Connecting…'}</span>
          )}
        </button>
      </div>

      <div className="topbar-right">
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={onRefreshHealth}
          title="Refresh"
        >
          <RefreshCw size={14} />
        </button>
      </div>
    </div>
  );
};

// Keep the old Header export name for backward compatibility during transition
export const Header = TopBar;
