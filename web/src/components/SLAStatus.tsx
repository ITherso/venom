import React from 'react';
import { SLAMetric, SLAViolation } from '../types';
import './SLAStatus.css';

interface SLAStatusProps {
  metrics: SLAMetric[];
  violations: SLAViolation[];
}

const SLAStatus: React.FC<SLAStatusProps> = ({ metrics, violations }) => {
  return (
    <div className="sla-status">
      <div className="sla-metrics">
        {metrics.map((metric) => (
          <div key={metric.id} className={`sla-metric ${metric.withinSLA ? 'compliant' : 'violated'}`}>
            <div className="metric-header">
              <h4>{metric.name}</h4>
              <span className={`sla-badge ${metric.slaLevel.toLowerCase()}`}>{metric.slaLevel}</span>
            </div>
            <div className="metric-value">
              <span className="current">{metric.currentValue.toFixed(2)}%</span>
              <span className="target">Target: {metric.targetValue.toFixed(2)}%</span>
            </div>
            <div className="metric-progress">
              <div
                className="progress-bar"
                style={{ width: `${Math.min((metric.currentValue / metric.targetValue) * 100, 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {violations.length > 0 && (
        <div className="sla-violations">
          <h3>Active Violations</h3>
          {violations.slice(0, 5).map((violation) => (
            <div key={violation.id} className={`violation violation-${violation.severity.toLowerCase()}`}>
              <div className="violation-header">
                <span className="severity">{violation.severity}</span>
                <span className="time">{new Date(violation.startTime).toLocaleString()}</span>
              </div>
              <p className="description">{violation.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SLAStatus;
