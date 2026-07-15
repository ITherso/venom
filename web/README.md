# VENOM Dashboard

Enterprise-grade web dashboard for VENOM v0.5.0 pentesting framework.

## Features

### 🎯 Main Dashboard
- **System Overview** - Real-time system status, CPU, memory, disk, network metrics
- **SLA Monitoring** - SLA level tracking, metric compliance, violation alerts
- **Performance Metrics** - CPU, memory, disk, network gauges with real-time updates
- **Security Scans** - Active scan tracking, vulnerability distribution
- **Backup Management** - Backup job status, compression ratios, restore capabilities
- **Audit Logs** - Comprehensive event logging with filtering and details

### 🔒 Access Control
- User and role management
- Permission assignment
- Subject lifecycle management

### 📊 SLA Management
- Multi-level SLA tiers (Platinum/Gold/Silver/Bronze)
- Real-time metric tracking
- Automatic violation detection
- SLA agreement management

### 🔍 Security Scanning
- Scan job management
- Vulnerability tracking (Critical/High/Medium/Low)
- Scan result analysis
- Target management

### 💾 Backup & Restore
- Backup job lifecycle
- Compression ratio monitoring
- Restore scheduling
- Retention management

### 🚀 Deployment Monitoring
- Environment status (dev/staging/production)
- Replica tracking
- Health checks
- Performance metrics

### 📋 Audit Logging
- Event categorization
- Severity levels
- Actor tracking
- Resource monitoring

### 🔁 Disaster Recovery
- DR plan management
- Drill execution
- Failover simulation
- Recovery point tracking

## Architecture

### Components
- **Dashboard** - Main view with all widgets
- **StatusCard** - System status display
- **MetricsChart** - Performance metrics visualization
- **SLAStatus** - SLA compliance tracking
- **AuditLog** - Event log viewer
- **ScansPanel** - Security scan management
- **BackupsPanel** - Backup management

### Styling
- Dark theme (GitHub-inspired)
- Responsive grid layouts
- Real-time status indicators
- Color-coded severity levels

### Data Types
- System Status & Health Checks
- SLA Metrics & Violations
- Audit Events
- Scan Results
- Backup Jobs
- Deployments
- Users & Roles
- DR Plans & Drills

## Getting Started

### Prerequisites
- Node.js 16+
- npm or yarn

### Installation
```bash
cd web
npm install
```

### Development
```bash
npm start
```
Dashboard will be available at `http://localhost:3000`

### Build
```bash
npm run build
```
Optimized build in `build/` directory

### Testing
```bash
npm test
```

## API Integration

The dashboard expects the following endpoints:

```
GET /api/dashboard              - Main dashboard data
GET /api/scans                 - Active scans
GET /api/scans/:id             - Scan details
GET /api/backups               - Backup jobs
GET /api/deployments           - Deployment status
GET /api/rbac/users            - User management
GET /api/rbac/roles            - Role management
GET /api/sla/metrics           - SLA metrics
GET /api/sla/violations        - SLA violations
GET /api/audit/logs            - Audit events
GET /api/dr/plans              - DR plans
GET /api/dr/drills             - DR drills
```

## Deployment

### Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: venom-dashboard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: venom-dashboard
  template:
    metadata:
      labels:
        app: venom-dashboard
    spec:
      containers:
      - name: dashboard
        image: ghcr.io/itherso/venom-dashboard:0.5.0
        ports:
        - containerPort: 3000
        env:
        - name: REACT_APP_API_URL
          value: "http://api.venom.svc.cluster.local"
```

## Features Roadmap

- [ ] Real-time WebSocket updates
- [ ] Advanced charting (Charts.js, D3.js)
- [ ] Report generation (PDF, CSV)
- [ ] Custom dashboards
- [ ] Alert notifications
- [ ] User preferences & theming
- [ ] Multi-language support
- [ ] Mobile responsive optimization

## Performance Metrics

- **Bundle Size**: ~150KB (gzipped)
- **Initial Load**: < 2s on 4G
- **Updates**: 5s intervals (configurable)
- **Support**: Chrome, Firefox, Safari, Edge

## Security

- HTTPS only
- CSP headers
- XSS protection
- CSRF tokens
- Secure session cookies
- Rate limiting on API calls

## Contributing

Submit issues and pull requests on GitHub.

## License

Enterprise License - All Rights Reserved
