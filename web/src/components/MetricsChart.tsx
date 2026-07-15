import React from 'react';
import { HealthCheck } from '../types';
import './MetricsChart.css';

interface MetricsChartProps {
  data: HealthCheck;
}

const MetricsChart: React.FC<MetricsChartProps> = ({ data }) => {
  const metrics = [
    { label: 'CPU', value: data.cpu, unit: '%', threshold: 80 },
    { label: 'Memory', value: data.memory, unit: '%', threshold: 80 },
    { label: 'Disk', value: data.disk, unit: '%', threshold: 85 },
    { label: 'Network', value: data.network, unit: '%', threshold: 90 },
  ];

  const getStatusClass = (value: number, threshold: number) => {
    if (value > threshold) return 'critical';
    if (value > threshold - 10) return 'warning';
    return 'healthy';
  };

  return (
    <div className="metrics-chart">
      <div className="metrics-grid">
        {metrics.map((metric) => (
          <div key={metric.label} className={`metric-item ${getStatusClass(metric.value, metric.threshold)}`}>
            <div className="metric-label">{metric.label}</div>
            <div className="metric-gauge">
              <div className="gauge-background">
                <div className="gauge-fill" style={{ width: `${metric.value}%` }} />
              </div>
              <div className="gauge-value">
                {metric.value.toFixed(1)}{metric.unit}
              </div>
            </div>
            <div className="metric-threshold">
              Threshold: {metric.threshold}{metric.unit}
            </div>
          </div>
        ))}
      </div>
      <div className="metrics-timestamp">
        Last updated: {new Date(data.timestamp).toLocaleTimeString()}
      </div>
    </div>
  );
};

export default MetricsChart;
