# VENOM v0.5.0 - Complete Deployment Guide

## 📋 Deployment Overview

VENOM v0.5.0 includes comprehensive deployment infrastructure for development, staging, and production environments using Docker, Kubernetes, Terraform, and GitHub Actions CI/CD.

---

## 🐳 WEEK 1: Docker Setup

### Building Docker Image

```bash
# Build locally
docker build -t venom:latest .

# Build and tag for registry
docker build -t ghcr.io/itherso/venom:v0.5.0 .

# Push to container registry
docker push ghcr.io/itherso/venom:v0.5.0
```

### Docker Compose (Development)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f venom

# Stop services
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v
```

**Services Available:**
- VENOM Proxy: http://localhost:8080
- REST API: http://localhost:3000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001
- Kibana: http://localhost:5601
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### Docker Image Details

- **Base Image**: Alpine 3.18 (4.5 MB)
- **Compiled Binary**: ~9-10 MB
- **Final Image Size**: ~15 MB (compressed)
- **Build Time**: ~38 seconds
- **Runtime Memory**: 15-25 MB (idle)

---

## ☸️ WEEK 2: Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm (optional, for package management)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Test minikube (development)
minikube start --cpus=4 --memory=8192
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f k8s/deployment.yaml

# Verify deployment
kubectl get all -n venom
kubectl get pods -n venom

# Check service status
kubectl get svc -n venom

# Port forward for local access
kubectl port-forward -n venom svc/venom 8080:8080 3000:3000
```

### Scaling Deployment

```bash
# Manual scaling
kubectl scale deployment venom-proxy -n venom --replicas=5

# Check HPA status
kubectl get hpa -n venom
kubectl describe hpa venom-hpa -n venom

# Monitor autoscaling
watch kubectl get hpa -n venom
```

### Viewing Logs

```bash
# View pod logs
kubectl logs -n venom deployment/venom-proxy -f

# View all recent events
kubectl get events -n venom --sort-by='.lastTimestamp'

# Exec into pod for debugging
kubectl exec -it -n venom deployment/venom-proxy -- /bin/sh
```

### Health Checks

```bash
# Check pod health
kubectl get pods -n venom -o wide

# Describe pod for detailed status
kubectl describe pod -n venom <pod-name>

# Check readiness/liveness probes
kubectl get pod -n venom <pod-name> -o yaml | grep -A10 "probes"
```

---

## 🏗️ WEEK 3: Infrastructure as Code (Terraform)

### Prerequisites

```bash
# Install Terraform
curl https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Verify installation
terraform version
```

### AWS Setup

```bash
# Configure AWS credentials
aws configure

# Verify access
aws ec2 describe-regions
```

### Deploy Infrastructure

```bash
# Initialize Terraform
cd terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan -var-file=prod.tfvars -out=tfplan

# Apply configuration
terraform apply tfplan

# View outputs
terraform output
```

### Environment-Specific Deployments

```bash
# Development environment
terraform apply -var-file=dev.tfvars

# Staging environment
terraform apply -var-file=staging.tfvars

# Production environment
terraform apply -var-file=prod.tfvars
```

### Managing Infrastructure

```bash
# Get cluster credentials
aws eks update-kubeconfig --region us-east-1 --name venom-prod

# Destroy infrastructure (WARNING: destructive)
terraform destroy -var-file=prod.tfvars

# Get specific resource state
terraform state show aws_eks_cluster.venom
terraform state list
```

### Remote State Management

```bash
# Create S3 bucket for state
aws s3 mb s3://venom-terraform-state

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket venom-terraform-state \
  --versioning-configuration Status=Enabled

# Create DynamoDB table for locks
aws dynamodb create-table \
  --table-name terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### Terraform Outputs

After deployment, get important connection strings:

```bash
# Database endpoint
terraform output rds_endpoint

# Redis endpoint
terraform output redis_endpoint

# EKS cluster name
terraform output eks_cluster_name

# EKS cluster endpoint
terraform output eks_cluster_endpoint
```

---

## 🔄 WEEK 4: CI/CD Pipeline (GitHub Actions)

### GitHub Actions Workflow

The pipeline automatically:
1. Runs tests on every push
2. Builds Docker image
3. Deploys to development (on develop branch)
4. Deploys to production (on version tags)
5. Runs smoke tests
6. Performs automatic rollback on failure

### Manual Deployment

```bash
# Tag release
git tag v0.5.1 -m "Release v0.5.1"
git push origin v0.5.1

# This triggers the prod deployment pipeline automatically
```

### Monitoring Deployments

```bash
# View workflow runs
gh run list --repo ITherso/venom

# View specific run
gh run view <run-id> --repo ITherso/venom

# Stream live logs
gh run view <run-id> --repo ITherso/venom --log
```

### Secrets Configuration

Add required secrets to GitHub repository settings:

```
DEV_DEPLOY_WEBHOOK       - Webhook URL for dev deployment
DEV_DEPLOY_TOKEN         - Auth token for dev deployment
PROD_DEPLOY_WEBHOOK      - Webhook URL for prod deployment
PROD_DEPLOY_TOKEN        - Auth token for prod deployment
DEV_KUBECONFIG          - Base64 encoded kubeconfig for dev
PROD_KUBECONFIG         - Base64 encoded kubeconfig for prod
SLACK_WEBHOOK           - Slack notification webhook
```

### Manual Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/venom-proxy -n venom

# Rollout history
kubectl rollout history deployment/venom-proxy -n venom

# Rollback to specific revision
kubectl rollout undo deployment/venom-proxy --to-revision=3 -n venom
```

---

## 📊 Monitoring & Observability

### Prometheus Metrics

Metrics are automatically exported to Prometheus at:
- `http://localhost:9090` (development)
- `https://prometheus.venom.example.com` (production)

**Key Metrics:**
- `venom_proxy_requests_total` - Total proxy requests
- `venom_proxy_request_duration_ms` - Request latency
- `venom_scanner_vulnerabilities_total` - Vulnerabilities found
- `venom_memory_usage_mb` - Memory consumption

### Grafana Dashboards

Access Grafana at:
- `http://localhost:3001` (development)
- `https://grafana.venom.example.com` (production)

Default login: `admin:admin` (change in production)

### Elasticsearch & Kibana

View logs in Kibana:
- `http://localhost:5601` (development)
- `https://kibana.venom.example.com` (production)

---

## 🔐 Security

### Network Security

- Network policies enforce egress/ingress rules
- Database access restricted to application pods
- All traffic encrypted with TLS
- No public database access

### Secrets Management

Store sensitive data in Kubernetes Secrets:

```bash
# Create secret
kubectl create secret generic venom-secrets \
  --from-literal=db-password=yourpassword \
  -n venom

# View secret (base64 encoded)
kubectl get secret venom-secrets -n venom -o yaml

# Update secret
kubectl patch secret venom-secrets -n venom \
  --type merge -p '{"data": {"db-password": "'$(echo -n newpassword | base64)'"}}'
```

### SSL/TLS

Install cert-manager for automatic certificate management:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

---

## 🚨 Backup & Disaster Recovery

### Database Backups

```bash
# Manual RDS snapshot
aws rds create-db-snapshot \
  --db-instance-identifier venom-prod \
  --db-snapshot-identifier venom-backup-$(date +%Y%m%d)

# List snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier venom-prod

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier venom-restored \
  --db-snapshot-identifier venom-backup-20240101
```

### Kubernetes Backup (Velero)

```bash
# Install Velero
wget https://github.com/vmware-tanzu/velero/releases/download/v1.12.0/velero-v1.12.0-linux-amd64.tar.gz
tar -xvf velero-v1.12.0-linux-amd64.tar.gz
sudo mv velero-v1.12.0-linux-amd64/velero /usr/local/bin/

# Install Velero in cluster
velero install \
  --provider aws \
  --bucket velero-backups \
  --secret-file ./credentials-velero

# Create backup
velero backup create venom-backup-20240101

# List backups
velero backup get

# Restore from backup
velero restore create --from-backup venom-backup-20240101
```

---

## 📈 Performance Tuning

### Pod Resource Allocation

Current defaults:
- **Requests**: 500m CPU, 512Mi memory
- **Limits**: 2000m CPU, 2Gi memory

Adjust based on load testing:

```yaml
resources:
  requests:
    cpu: 1000m      # Increase if CPU-bound
    memory: 1Gi     # Increase if memory-intensive
  limits:
    cpu: 4000m
    memory: 4Gi
```

### Database Connection Pooling

PostgreSQL connection limits:
- Pool size: 20 (adjust based on concurrent requests)
- Timeout: 30 seconds
- Idle timeout: 5 minutes

### Redis Configuration

Redis maxmemory policies:
- Policy: `allkeys-lru` (evict least recently used)
- Maxmemory: 1GB (adjust based on usage)

---

## 🆘 Troubleshooting

### Pod Crash Issues

```bash
# Check pod status
kubectl describe pod -n venom <pod-name>

# View logs
kubectl logs -n venom <pod-name> --previous

# Get events
kubectl get events -n venom --sort-by='.lastTimestamp'
```

### Database Connection Issues

```bash
# Test connectivity
kubectl run -it --rm debug --image=alpine --restart=Never -- \
  sh -c 'apk add postgresql-client && psql -h postgres -U venom'

# Check RDS security groups
aws ec2 describe-security-groups --region us-east-1
```

### High CPU/Memory Usage

```bash
# Get resource metrics
kubectl top pods -n venom

# Top nodes
kubectl top nodes

# Increase limits or add more replicas
kubectl scale deployment venom-proxy -n venom --replicas=5
```

---

## 📝 Deployment Checklist

- [ ] Docker image built and tested
- [ ] Docker Compose verified (dev stack)
- [ ] Kubernetes manifests validated
- [ ] Terraform infrastructure planned
- [ ] AWS credentials configured
- [ ] EKS cluster deployed
- [ ] RDS database initialized
- [ ] Redis cache running
- [ ] Ingress configured with TLS
- [ ] Monitoring stack operational
- [ ] Backups configured
- [ ] CI/CD pipeline active
- [ ] SSL certificates valid
- [ ] Health checks passing
- [ ] Smoke tests successful
- [ ] Documentation updated
- [ ] SLA monitoring enabled

---

## 🚀 Production Deployment Checklist

- [ ] Load testing completed
- [ ] Performance baseline established
- [ ] Security audit passed
- [ ] Backup strategy tested
- [ ] Disaster recovery plan documented
- [ ] On-call playbooks created
- [ ] Monitoring alerts configured
- [ ] Logging retention policies set
- [ ] Database backups automated
- [ ] Certificate renewal automated
- [ ] Network policies validated
- [ ] Rate limiting configured
- [ ] CDN integration (if applicable)
- [ ] DDoS protection enabled

---

## 📞 Support & Documentation

For issues or questions:
- GitHub Issues: https://github.com/ITherso/venom/issues
- Documentation: https://github.com/ITherso/venom/wiki
- Email: e268792@metu.edu.tr

---

**VENOM v0.5.0 - Production Ready! 🚀**
