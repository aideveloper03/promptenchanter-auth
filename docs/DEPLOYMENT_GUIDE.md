# Deployment Guide - User Management API

Complete guide for deploying the User Management API to various environments including cloud platforms, VPS, and containerized deployments.

## 📋 Table of Contents

1. [Pre-deployment Checklist](#pre-deployment-checklist)
2. [Docker Deployment](#docker-deployment)
3. [AWS Deployment](#aws-deployment)
4. [Google Cloud Platform](#google-cloud-platform)
5. [DigitalOcean Deployment](#digitalocean-deployment)
6. [Heroku Deployment](#heroku-deployment)
7. [VPS Deployment](#vps-deployment)
8. [Kubernetes Deployment](#kubernetes-deployment)
9. [Load Balancing & Scaling](#load-balancing--scaling)
10. [Monitoring & Logging](#monitoring--logging)
11. [Backup & Recovery](#backup--recovery)
12. [Security Hardening](#security-hardening)

## ✅ Pre-deployment Checklist

### Security Requirements
- [ ] Change `SECRET_KEY` to a secure random value (32+ characters)
- [ ] Change `ENCRYPTION_KEY` to a secure random value (32 bytes)
- [ ] Set strong admin password
- [ ] Enable IP whitelisting (`ENABLE_IP_WHITELIST=true`)
- [ ] Configure SSL/TLS certificates
- [ ] Review and set appropriate rate limits
- [ ] Configure firewall rules

### Configuration Requirements
- [ ] Set production database path
- [ ] Configure SMTP settings for email (if using)
- [ ] Set appropriate log levels
- [ ] Configure backup strategy
- [ ] Set monitoring endpoints
- [ ] Configure environment-specific settings

### Performance Requirements
- [ ] Optimize database settings
- [ ] Configure connection pooling
- [ ] Set appropriate worker count
- [ ] Configure caching if needed
- [ ] Optimize memory settings

## 🐳 Docker Deployment

### Single Container Deployment

**Dockerfile:**
```dockerfile
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV WORKERS=4

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create non-root user
RUN useradd -m -u 1000 apiuser && chown -R apiuser:apiuser /app
USER apiuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD uvicorn main:app --host 0.0.0.0 --port 8000 --workers $WORKERS
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - ENABLE_IP_WHITELIST=${ENABLE_IP_WHITELIST:-false}
      - WHITELISTED_IPS=${WHITELISTED_IPS:-127.0.0.1,localhost}
      - DATABASE_URL=sqlite:///./data/user_management.db
    volumes:
      - api_data:/app/data
      - api_logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - api
    restart: unless-stopped

volumes:
  api_data:
  api_logs:
```

**nginx.conf:**
```nginx
events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        server api:8000;
    }

    server {
        listen 80;
        server_name your-domain.com;
        
        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        location / {
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

**Deploy with Docker:**
```bash
# Create environment file
cp .env.example .env
# Edit .env with production values

# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f

# Scale the API service
docker-compose up -d --scale api=3
```

## ☁️ AWS Deployment

### AWS ECS Deployment

**1. Create ECS Task Definition (task-definition.json):**
```json
{
  "family": "user-management-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "api",
      "image": "your-account.dkr.ecr.region.amazonaws.com/user-management-api:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "SECRET_KEY",
          "value": "your-secret-key"
        },
        {
          "name": "ENABLE_IP_WHITELIST",
          "value": "true"
        }
      ],
      "secrets": [
        {
          "name": "ADMIN_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:user-mgmt-admin-pass"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/user-management-api",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

**2. Deployment Script (deploy-aws.sh):**
```bash
#!/bin/bash

# Configuration
ECR_REPOSITORY="your-account.dkr.ecr.us-east-1.amazonaws.com/user-management-api"
ECS_CLUSTER="user-management-cluster"
ECS_SERVICE="user-management-service"
REGION="us-east-1"

# Build and push to ECR
echo "Building Docker image..."
docker build -t user-management-api .

echo "Tagging image..."
docker tag user-management-api:latest $ECR_REPOSITORY:latest

echo "Pushing to ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_REPOSITORY
docker push $ECR_REPOSITORY:latest

echo "Updating ECS service..."
aws ecs update-service \
    --cluster $ECS_CLUSTER \
    --service $ECS_SERVICE \
    --force-new-deployment \
    --region $REGION

echo "Deployment initiated. Check ECS console for status."
```

**3. CloudFormation Template (infrastructure.yaml):**
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'User Management API Infrastructure'

Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  DomainName:
    Type: String
    Default: api.example.com

Resources:
  # ECS Cluster
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: user-management-cluster

  # Application Load Balancer
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: user-management-alb
      Subnets: !Ref SubnetIds
      SecurityGroups: [!Ref LoadBalancerSecurityGroup]
      Tags:
        - Key: Name
          Value: user-management-alb

  # Security Groups
  LoadBalancerSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for load balancer
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0

  ECSSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for ECS tasks
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 8000
          ToPort: 8000
          SourceSecurityGroupId: !Ref LoadBalancerSecurityGroup

  # Target Group
  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Name: user-management-tg
      Port: 8000
      Protocol: HTTP
      TargetType: ip
      VpcId: !Ref VpcId
      HealthCheckPath: /health
      HealthCheckIntervalSeconds: 30
      HealthCheckTimeoutSeconds: 5
      HealthyThresholdCount: 2

  # Listener
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref TargetGroup
      LoadBalancerArn: !Ref LoadBalancer
      Port: 80
      Protocol: HTTP

Outputs:
  LoadBalancerDNS:
    Description: DNS name of the load balancer
    Value: !GetAtt LoadBalancer.DNSName
```

### AWS Lambda Deployment (Serverless)

**serverless.yml:**
```yaml
service: user-management-api

provider:
  name: aws
  runtime: python3.9
  region: us-east-1
  environment:
    SECRET_KEY: ${env:SECRET_KEY}
    ENCRYPTION_KEY: ${env:ENCRYPTION_KEY}
    ADMIN_PASSWORD: ${env:ADMIN_PASSWORD}

functions:
  api:
    handler: lambda_handler.handler
    timeout: 30
    events:
      - http:
          path: /{proxy+}
          method: ANY
          cors: true
      - http:
          path: /
          method: ANY
          cors: true

plugins:
  - serverless-python-requirements
  - serverless-domain-manager

custom:
  pythonRequirements:
    dockerizePip: true
  customDomain:
    domainName: api.example.com
    stage: ${self:provider.stage}
    createRoute53Record: true
```

**lambda_handler.py:**
```python
from mangum import Mangum
from main import app

handler = Mangum(app, lifespan="off")
```

## 🔵 Google Cloud Platform

### Cloud Run Deployment

**cloudbuild.yaml:**
```yaml
steps:
  # Build the container image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/user-management-api', '.']
  
  # Push the container image to Container Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/user-management-api']
  
  # Deploy container image to Cloud Run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - 'user-management-api'
      - '--image'
      - 'gcr.io/$PROJECT_ID/user-management-api'
      - '--region'
      - 'us-central1'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'

options:
  logging: CLOUD_LOGGING_ONLY
```

**Deploy Script:**
```bash
#!/bin/bash

PROJECT_ID="your-project-id"
REGION="us-central1"

# Set project
gcloud config set project $PROJECT_ID

# Enable APIs
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com

# Build and deploy
gcloud builds submit --config cloudbuild.yaml

# Set environment variables
gcloud run services update user-management-api \
  --region=$REGION \
  --set-env-vars="SECRET_KEY=your-secret-key" \
  --set-env-vars="ENCRYPTION_KEY=your-encryption-key" \
  --set-env-vars="ENABLE_IP_WHITELIST=true"

# Get service URL
gcloud run services describe user-management-api \
  --region=$REGION \
  --format="value(status.url)"
```

## 🌊 DigitalOcean Deployment

### App Platform Deployment

**.do/app.yaml:**
```yaml
name: user-management-api
services:
- name: api
  source_dir: /
  github:
    repo: your-username/user-management-api
    branch: main
  run_command: uvicorn main:app --host 0.0.0.0 --port 8080
  environment_slug: python
  instance_count: 2
  instance_size_slug: basic-xxs
  http_port: 8080
  health_check:
    http_path: /health
  envs:
  - key: SECRET_KEY
    value: your-secret-key
    type: SECRET
  - key: ENCRYPTION_KEY
    value: your-encryption-key
    type: SECRET
  - key: ADMIN_PASSWORD
    value: your-admin-password
    type: SECRET
  - key: ENABLE_IP_WHITELIST
    value: "true"
```

**Deploy:**
```bash
# Install doctl
snap install doctl

# Authenticate
doctl auth init

# Deploy
doctl apps create --spec .do/app.yaml

# Get app info
doctl apps list
```

### Droplet Deployment

**setup-droplet.sh:**
```bash
#!/bin/bash

# Update system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/download/v2.0.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Setup firewall
ufw allow 22
ufw allow 80
ufw allow 443
ufw --force enable

# Create app directory
mkdir -p /opt/user-management-api
cd /opt/user-management-api

# Clone or copy your application files here
# Then run:
docker-compose up -d
```

## 🔮 Heroku Deployment

### Standard Heroku Deployment

**Procfile:**
```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

**runtime.txt:**
```
python-3.9.16
```

**Deploy Script:**
```bash
#!/bin/bash

# Install Heroku CLI and login
# heroku login

# Create Heroku app
heroku create user-management-api-prod

# Set config variables
heroku config:set SECRET_KEY="your-secret-key"
heroku config:set ENCRYPTION_KEY="your-encryption-key"
heroku config:set ADMIN_PASSWORD="your-admin-password"
heroku config:set ENABLE_IP_WHITELIST="true"

# Deploy
git add .
git commit -m "Deploy to Heroku"
git push heroku main

# Scale workers
heroku ps:scale web=2

# View logs
heroku logs --tail
```

## 🖥️ VPS Deployment

### Ubuntu/Debian VPS Setup

**deploy-vps.sh:**
```bash
#!/bin/bash

# Configuration
APP_USER="apiuser"
APP_DIR="/opt/user-management-api"
DOMAIN="api.example.com"

# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# Create application user
useradd -m -s /bin/bash $APP_USER
usermod -aG sudo $APP_USER

# Create application directory
mkdir -p $APP_DIR
chown $APP_USER:$APP_USER $APP_DIR

# Switch to app user
sudo -u $APP_USER bash << EOF
cd $APP_DIR

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with production values

# Test application
python main.py &
sleep 5
curl http://localhost:8000/health
pkill -f "python main.py"
EOF

# Create systemd service
cat > /etc/systemd/system/user-management-api.service << EOF
[Unit]
Description=User Management API
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
ExecStart=$APP_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable user-management-api
systemctl start user-management-api

# Configure Nginx
cat > /etc/nginx/sites-available/user-management-api << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/user-management-api /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# Get SSL certificate
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

echo "Deployment complete! API is running at https://$DOMAIN"
```

## ⚙️ Kubernetes Deployment

### Kubernetes Manifests

**namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: user-management
```

**configmap.yaml:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
  namespace: user-management
data:
  ENABLE_IP_WHITELIST: "true"
  RATE_LIMIT_PER_MINUTE: "100"
  DEBUG: "false"
```

**secret.yaml:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
  namespace: user-management
type: Opaque
data:
  SECRET_KEY: base64-encoded-secret-key
  ENCRYPTION_KEY: base64-encoded-encryption-key
  ADMIN_PASSWORD: base64-encoded-admin-password
```

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-management-api
  namespace: user-management
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-management-api
  template:
    metadata:
      labels:
        app: user-management-api
    spec:
      containers:
      - name: api
        image: your-registry/user-management-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: SECRET_KEY
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: ENCRYPTION_KEY
        - name: ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: ADMIN_PASSWORD
        envFrom:
        - configMapRef:
            name: api-config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

**service.yaml:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: user-management-api-service
  namespace: user-management
spec:
  selector:
    app: user-management-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: ClusterIP
```

**ingress.yaml:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: user-management-api-ingress
  namespace: user-management
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: user-management-api-service
            port:
              number: 80
```

**Deploy to Kubernetes:**
```bash
# Apply manifests
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml

# Check deployment status
kubectl get pods -n user-management
kubectl get services -n user-management
kubectl get ingress -n user-management

# View logs
kubectl logs -f deployment/user-management-api -n user-management
```

## ⚖️ Load Balancing & Scaling

### Horizontal Pod Autoscaler (Kubernetes)

**hpa.yaml:**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: user-management-api-hpa
  namespace: user-management
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: user-management-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### HAProxy Load Balancer

**haproxy.cfg:**
```
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend api_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/api.pem
    redirect scheme https if !{ ssl_fc }
    default_backend api_backend

backend api_backend
    balance roundrobin
    option httpchk GET /health
    server api1 10.0.1.10:8000 check
    server api2 10.0.1.11:8000 check
    server api3 10.0.1.12:8000 check
```

## 📊 Monitoring & Logging

### Prometheus + Grafana

**docker-compose.monitoring.yml:**
```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  grafana_data:
```

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'user-management-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

### ELK Stack for Logging

**docker-compose.elk.yml:**
```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"

  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
```

## 💾 Backup & Recovery

### Automated Backup Script

**backup.sh:**
```bash
#!/bin/bash

BACKUP_DIR="/backups/user-management"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
cp /opt/user-management-api/user_management.db $BACKUP_DIR/db_$DATE.db

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz -C /opt/user-management-api .env app/

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/db_$DATE.db s3://your-backup-bucket/database/
aws s3 cp $BACKUP_DIR/config_$DATE.tar.gz s3://your-backup-bucket/config/

# Clean old backups
find $BACKUP_DIR -name "*.db" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

**Cron job:**
```bash
# Add to crontab
0 2 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1
```

## 🔒 Security Hardening

### Security Checklist

- [ ] Use HTTPS everywhere
- [ ] Implement proper firewall rules
- [ ] Regular security updates
- [ ] Strong passwords and keys
- [ ] IP whitelisting enabled
- [ ] Rate limiting configured
- [ ] Logging and monitoring
- [ ] Regular backups
- [ ] Vulnerability scanning
- [ ] Access control reviews

### Security Headers (Nginx)

```nginx
# Security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";

# Hide server information
server_tokens off;
```

### Fail2Ban Configuration

**/etc/fail2ban/jail.local:**
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/nginx/error.log
maxretry = 10

[api-auth]
enabled = true
filter = api-auth
action = iptables-multiport[name=ApiAuth, port="http,https", protocol=tcp]
logpath = /var/log/user-management-api/access.log
maxretry = 5
```

This deployment guide provides comprehensive coverage for deploying the User Management API across various platforms and environments. Choose the deployment method that best fits your infrastructure requirements and scaling needs.