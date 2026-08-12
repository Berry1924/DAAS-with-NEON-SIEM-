import React from 'react';
import { User } from '../types';
import {
  LayoutDashboard,
  ShieldCheck,
  Search,
  Activity,
  FileText,
  LogOut,
  Zap,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'incidents' | 'events' | 'telemetry' | 'audit';

interface SidebarProps {
  user: User;
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  onLogout: () => void;
  openIncidents?: number;
}

interface NavItem {
  id: NavTab;
  label: string;
  icon: React.ReactNode;
  section: 'operations' | 'investigate' | 'system';
  adminOnly?: boolean;
  badge?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  user,
  activeTab,
  setActiveTab,
  onLogout,
  openIncidents,
}) => {
  const navItems: NavItem[] = [
    { id: 'dashboard', label: 'Command Center', icon: <LayoutDashboard size={20} />, section: 'operations' },
    { id: 'incidents', label: 'Incidents', icon: <ShieldCheck size={20} />, section: 'operations', badge: openIncidents },
    { id: 'events', label: 'Event Search', icon: <Search size={20} />, section: 'investigate' },
    { id: 'telemetry', label: 'Ingest', icon: <Activity size={20} />, section: 'investigate' },
    { id: 'audit', label: 'Audit Trail', icon: <FileText size={20} />, section: 'system', adminOnly: true },
  ];

  const sections: { key: string; label: string }[] = [
    { key: 'operations', label: 'Operations' },
    { key: 'investigate', label: 'Investigate' },
    { key: 'system', label: 'System' },
  ];

  const initial = user.display_name
    ? user.display_name.charAt(0).toUpperCase()
    : user.username.charAt(0).toUpperCase();

  const roleClass = `role-${user.role.toLowerCase()}`;

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Zap size={18} />
        </div>
        <div className="sidebar-brand-text">
          <div className="sidebar-brand-name">NEON</div>
          <div className="sidebar-brand-sub">SIEM Console</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {sections.map((section) => {
          const items = navItems.filter(
            (item) => item.section === section.key && (!item.adminOnly || user.role === 'ADMIN')
          );
          if (items.length === 0) return null;

          return (
            <React.Fragment key={section.key}>
              <div className="sidebar-section-label">{section.label}</div>
              {items.map((item) => (
                <button
                  key={item.id}
                  className={`sidebar-item${activeTab === item.id ? ' active' : ''}`}
                  onClick={() => setActiveTab(item.id)}
                  type="button"
                >
                  <span className="sidebar-item-icon">{item.icon}</span>
                  <span className="sidebar-item-label">{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="sidebar-item-badge">{item.badge}</span>
                  )}
                </button>
              ))}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Footer — User Profile */}
      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="sidebar-avatar">{initial}</div>
          <div className="sidebar-user-info">
            <div className="sidebar-user-name">{user.display_name || user.username}</div>
            <div className={`sidebar-user-role ${roleClass}`}>{user.role}</div>
          </div>
        </div>
        <button
          className="btn btn-ghost"
          onClick={onLogout}
          type="button"
          style={{ width: '100%', marginTop: '8px', justifyContent: 'center' }}
        >
          <LogOut size={14} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
};
