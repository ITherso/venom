# Production environment configuration
environment = "prod"
aws_region  = "us-east-1"

# VPC
vpc_cidr_block       = "10.0.0.0/16"
public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
private_subnet_cidrs = ["10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24"]

# EKS - Production cluster with high availability
eks_desired_size = 5
eks_min_size     = 3
eks_max_size     = 20
eks_instance_types = ["t3.large", "t3.xlarge"]

# RDS - Production database with backups and multi-AZ
db_allocated_storage    = 500
db_backup_retention_days = 90

# Redis - Production cluster with failover
redis_node_type = "cache.r6g.xlarge"
redis_num_nodes = 3

# Logging
log_retention_days = 90

tags = {
  CostCenter = "production"
  Team       = "platform"
  Compliance = "required"
}
