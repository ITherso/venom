import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import './App.css';

type View = 'dashboard' | 'scans' | 'backups' | 'deployments' | 'rbac' | 'audit' | 'sla' | 'dr';

const App: React.FC = () => {
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="app-container">
      <nav className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-header">
          <h2>VENOM</h2>
          <button className="sidebar-toggle" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? '✕' : '☰'}
          </button>
        </div>

        <ul className="nav-menu">
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'dashboard' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('dashboard');
              }}
            >
              📊 Dashboard
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'scans' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('scans');
              }}
            >
              🔍 Security Scans
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'backups' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('backups');
              }}
            >
              💾 Backup Management
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'deployments' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('deployments');
              }}
            >
              🚀 Deployments
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'rbac' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('rbac');
              }}
            >
              👥 Access Control
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'sla' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('sla');
              }}
            >
              📈 SLA Monitoring
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'audit' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('audit');
              }}
            >
              📋 Audit Logs
            </a>
          </li>
          <li>
            <a
              href="#"
              className={`nav-link ${activeView === 'dr' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveView('dr');
              }}
            >
              🔁 Disaster Recovery
            </a>
          </li>
        </ul>

        <div className="sidebar-footer">
          <div className="user-section">
            <div className="user-avatar">👤</div>
            <div className="user-info">
              <p className="user-name">Admin</p>
              <p className="user-role">Administrator</p>
            </div>
          </div>
        </div>
      </nav>

      <main className="main-content">
        {activeView === 'dashboard' && <Dashboard refreshInterval={5000} />}
        {activeView === 'scans' && (
          <div className="view-container">
            <h1>Security Scans</h1>
            <p>Scan management interface coming soon...</p>
          </div>
        )}
        {activeView === 'backups' && (
          <div className="view-container">
            <h1>Backup Management</h1>
            <p>Backup management interface coming soon...</p>
          </div>
        )}
        {activeView === 'deployments' && (
          <div className="view-container">
            <h1>Deployments</h1>
            <p>Deployment management interface coming soon...</p>
          </div>
        )}
        {activeView === 'rbac' && (
          <div className="view-container">
            <h1>Access Control (RBAC)</h1>
            <p>RBAC management interface coming soon...</p>
          </div>
        )}
        {activeView === 'sla' && (
          <div className="view-container">
            <h1>SLA Monitoring</h1>
            <p>SLA monitoring dashboard coming soon...</p>
          </div>
        )}
        {activeView === 'audit' && (
          <div className="view-container">
            <h1>Audit Logs</h1>
            <p>Audit log viewer coming soon...</p>
          </div>
        )}
        {activeView === 'dr' && (
          <div className="view-container">
            <h1>Disaster Recovery</h1>
            <p>Disaster recovery management coming soon...</p>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
