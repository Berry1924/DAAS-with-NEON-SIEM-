import React from 'react';
import { Severity, IncidentStatus } from '../types';
import { AlertTriangle, ShieldAlert, AlertCircle, Info, CheckCircle2, Eye, Search } from 'lucide-react';

const severityConfig: Record<Severity, { className: string; icon: React.ReactNode }> = {
  CRITICAL: { className: 'badge-critical', icon: <ShieldAlert size={12} /> },
  HIGH: { className: 'badge-high', icon: <AlertTriangle size={12} /> },
  MEDIUM: { className: 'badge-medium', icon: <AlertCircle size={12} /> },
  LOW: { className: 'badge-low', icon: <Info size={12} /> },
  INFO: { className: 'badge-info', icon: <Info size={12} /> },
};

const statusConfig: Record<IncidentStatus, { className: string; icon: React.ReactNode }> = {
  NEW: { className: 'badge-new', icon: <AlertCircle size={12} /> },
  ACKNOWLEDGED: { className: 'badge-acknowledged', icon: <Eye size={12} /> },
  INVESTIGATING: { className: 'badge-investigating', icon: <Search size={12} /> },
  RESOLVED: { className: 'badge-resolved', icon: <CheckCircle2 size={12} /> },
  FALSE_POSITIVE: { className: 'badge-false-positive', icon: <CheckCircle2 size={12} /> },
};

export const SeverityBadge: React.FC<{ severity: Severity; showScore?: number }> = ({ severity, showScore }) => {
  const config = severityConfig[severity];
  return (
    <span className={`badge ${config.className}`}>
      {config.icon}
      <span>{severity}</span>
      {showScore !== undefined && <span style={{ opacity: 0.9 }}>({showScore})</span>}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: IncidentStatus }> = ({ status }) => {
  const config = statusConfig[status];
  return (
    <span className={`badge ${config.className}`}>
      {config.icon}
      <span>{status.replace('_', ' ')}</span>
    </span>
  );
};
