import React from 'react';
import './StatusCard.css';

interface StatusCardProps {
  title: string;
  status: 'healthy' | 'warning' | 'critical' | 'running' | 'stopped' | 'degraded';
  value: string | number;
  details?: string;
  icon?: React.ReactNode;
  onClick?: () => void;
}

const StatusCard: React.FC<StatusCardProps> = ({ title, status, value, details, icon, onClick }) => {
  return (
    <div className={`status-card status-${status}`} onClick={onClick}>
      <div className="card-header">
        {icon && <div className="card-icon">{icon}</div>}
        <h3>{title}</h3>
        <div className={`status-badge ${status}`}>{status}</div>
      </div>
      <div className="card-value">{value}</div>
      {details && <div className="card-details">{details}</div>}
    </div>
  );
};

export default StatusCard;
