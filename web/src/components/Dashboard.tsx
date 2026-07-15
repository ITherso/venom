import React, { useEffect, useState } from 'react';
import { DashboardData, SystemStatus, HealthCheck } from '../types';
import StatusCard from './StatusCard';
import MetricsChart from './MetricsChart';
import AuditLog from './AuditLog';
import SLAStatus from './SLAStatus';
import ScansPanel from './ScansPanel';
import BackupsPanel from './BackupsPanel';

interface DashboardProps {
  refreshInterval?: number;
}

const Dashboard: React.FC<DashboardProps> = ({ refreshInterval = 5000 }) => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        const response = await fetch('/api/dashboard');
        if (!response.ok) throw new Error('Failed to fetch dashboard data');
        const dashboardData = await response.json();
        setData(dashboardData);
        setLastUpdate(new Date());
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  if (error) {
    return (
      <div className="dashboard-error">
        <h2>Error Loading Dashboard</h2>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="dashboard-loading">
        <div className="spinner">Loading...</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>VENOM Dashboard</h1>
        <div className="header-info">
          <span className="version">v0.5.0</span>
          <span className="last-update">Updated: {lastUpdate.toLocaleTimeString()}</span>
        </div>
      </header>

      <div className="dashboard-grid">
        {/* Status Overview */}
        <section className="status-overview">
          <h2>System Overview</h2>
          <div className="status-cards">
            <StatusCard
              title="System Status"
              status={data.systemStatus.status}
              value={data.systemStatus.healthy ? 'Healthy' : 'Unhealthy'}
              details={`Uptime: ${formatUptime(data.systemStatus.uptime)}`}
            />
            <StatusCard
              title="CPU Usage"
              status={data.healthCheck.cpu > 80 ? 'critical' : data.healthCheck.cpu > 60 ? 'warning' : 'healthy'}
              value={`${data.healthCheck.cpu.toFixed(1)}%`}
              details="Current usage"
            />
            <StatusCard
              title="Memory Usage"
              status={data.healthCheck.memory > 80 ? 'critical' : data.healthCheck.memory > 60 ? 'warning' : 'healthy'}
              value={`${data.healthCheck.memory.toFixed(1)}%`}
              details="Current usage"
            />
            <StatusCard
              title="Disk Usage"
              status={data.healthCheck.disk > 85 ? 'critical' : data.healthCheck.disk > 70 ? 'warning' : 'healthy'}
              value={`${data.healthCheck.disk.toFixed(1)}%`}
              details="Current usage"
            />
          </div>
        </section>

        {/* SLA Status */}
        <section className="sla-section">
          <h2>SLA Monitoring</h2>
          <SLAStatus metrics={data.slaMetrics} violations={data.slaViolations} />
        </section>

        {/* Metrics Chart */}
        <section className="metrics-section">
          <h2>Performance Metrics</h2>
          <MetricsChart data={data.healthCheck} />
        </section>

        {/* Active Scans */}
        <section className="scans-section">
          <h2>Security Scans</h2>
          <ScansPanel scans={data.activeScans} />
        </section>

        {/* Recent Backups */}
        <section className="backups-section">
          <h2>Backup Management</h2>
          <BackupsPanel backups={data.recentBackups} />
        </section>

        {/* Audit Log */}
        <section className="audit-section">
          <h2>Recent Audit Events</h2>
          <AuditLog events={data.recentAuditEvents} />
        </section>
      </div>

      <footer className="dashboard-footer">
        <p>VENOM v0.5.0 - Enterprise Pentesting Framework</p>
        <p>© 2024 Security Operations Team</p>
      </footer>
    </div>
  );
};

const formatUptime = (uptime: number): string => {
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  return `${days}d ${hours}h`;
};

export default Dashboard;
