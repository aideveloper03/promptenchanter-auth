# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the User Management API in production environments with enhanced security, performance, and monitoring.

## Pre-deployment Checklist

### 1. Security Configuration ✅

```bash
# Generate secure configuration values
python -c "
from app.security.secrets_manager import EnvironmentValidator, SecretsManager
import json

# Validate current configuration
validation = EnvironmentValidator.validate_production_config()
print('Security Validation:')
print(json.dumps(validation, indent=2))

# Generate secure values if needed
if not validation['is_production_ready']:
    print('\nGenerated secure values:')
    secure_config = EnvironmentValidator.generate_secure_config()
    for key, value in secure_config.items():
        print(f'{key}={value}')
"
```

### 2. Environment Variables

Create a production `.env` file with secure values:

```bash
# Security - REQUIRED: Change these values!
SECRET_KEY=your-64-character-secret-key-here-minimum-32-characters-required
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database - Use PostgreSQL for production
DATABASE_URL=postgresql://username:password@localhost:5432/user_management

# Security Settings
BCRYPT_ROUNDS=12
ENCRYPTION_KEY=your-32-byte-base64-encoded-encryption-key-here

# Admin Credentials - CHANGE THESE!
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-very-secure-admin-password-with-special-chars

# IP Whitelisting - ENABLE in production
ENABLE_IP_WHITELIST=true
WHITELISTED_IPS=your.server.ip,load.balancer.ip,office.network.ip/24

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# Application Settings
APP_NAME=User Management API
APP_VERSION=1.0.0
DEBUG=false

# Redis - For caching and session storage
REDIS_URL=redis://redis-server:6379/0

# Email Settings (if needed)
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USERNAME=noreply@yourdomain.com
SMTP_PASSWORD=your-smtp-password

# Monitoring
LOG_LEVEL=info
```

### 3. SSL/TLS Certificates

```bash
# Place your SSL certificates in the ssl/ directory
mkdir -p ssl/
# Copy your certificates:
# ssl/cert.pem - SSL certificate
# ssl/key.pem  - Private key
# ssl/chain.pem - Certificate chain (if applicable)

# For Let's Encrypt certificates:
certbot certonly --standalone -d yourdomain.com
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ssl/key.pem
```

## Deployment Methods

### Method 1: Docker Compose (Recommended)

1. **Prepare the environment:**
```bash
# Clone the repository
git clone <repository-url>
cd user-management-api

# Create production environment file
cp .env.example .env
# Edit .env with your production values
```

2. **Deploy with the deployment script:**
```bash
./scripts/deploy.sh
```

3. **Manual deployment:**
```bash
# Build and start services
docker-compose -f docker-compose.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Method 2: Manual Installation

1. **System Requirements:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    python3.9+ \
    python3-pip \
    python3-venv \
    nginx \
    redis-server \
    postgresql-client \
    supervisor

# CentOS/RHEL
sudo yum install -y \
    python39 \
    python39-pip \
    nginx \
    redis \
    postgresql-client \
    supervisor
```

2. **Application Setup:**
```bash
# Create application user
sudo useradd -m -s /bin/bash userapi
sudo su - userapi

# Setup application
git clone <repository-url> /home/userapi/app
cd /home/userapi/app

# Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with production values
```

3. **Database Setup (PostgreSQL):**
```bash
# Create database and user
sudo -u postgres psql
CREATE DATABASE user_management;
CREATE USER userapi_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE user_management TO userapi_user;
\q

# Update DATABASE_URL in .env
DATABASE_URL=postgresql://userapi_user:secure_password@localhost:5432/user_management
```

4. **Systemd Service:**
```bash
# Create service file
sudo tee /etc/systemd/system/userapi.service > /dev/null <<EOF
[Unit]
Description=User Management API
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=userapi
Group=userapi
WorkingDirectory=/home/userapi/app
Environment=PATH=/home/userapi/app/venv/bin
ExecStart=/home/userapi/app/venv/bin/gunicorn main:app --worker-class uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000 --workers 4
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable userapi
sudo systemctl start userapi
sudo systemctl status userapi
```

5. **Nginx Configuration:**
```bash
# Create nginx configuration
sudo tee /etc/nginx/sites-available/userapi > /dev/null <<EOF
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_private_key /path/to/ssl/key.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=2r/s;

    location ~ ^/(api/v1/(auth/login|admin/login|staff/login)) {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

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
sudo ln -s /etc/nginx/sites-available/userapi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Database Migration to PostgreSQL

For production, migrate from SQLite to PostgreSQL:

1. **Install PostgreSQL adapter:**
```bash
pip install asyncpg
```

2. **Create migration script:**
```python
# migrate_to_postgres.py
import asyncio
import aiosqlite
import asyncpg
import json

async def migrate_data():
    # Connect to SQLite
    sqlite_conn = await aiosqlite.connect('user_management.db')
    
    # Connect to PostgreSQL
    pg_conn = await asyncpg.connect('postgresql://user:pass@localhost/db')
    
    # Migrate users table
    async with sqlite_conn.execute("SELECT * FROM users") as cursor:
        async for row in cursor:
            await pg_conn.execute("""
                INSERT INTO users (id, username, name, email, password_hash, ...)
                VALUES ($1, $2, $3, $4, $5, ...)
            """, *row)
    
    await sqlite_conn.close()
    await pg_conn.close()

# Run migration
asyncio.run(migrate_data())
```

## Monitoring and Maintenance

### 1. Health Monitoring

```bash
# Check application health
curl -s https://yourdomain.com/health | jq

# Monitor logs
tail -f logs/app.log
tail -f logs/error.log
tail -f logs/security.log

# System metrics
docker stats  # For Docker deployment
systemctl status userapi  # For systemd deployment
```

### 2. Log Rotation

```bash
# Configure logrotate
sudo tee /etc/logrotate.d/userapi > /dev/null <<EOF
/home/userapi/app/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### 3. Backup Strategy

```bash
# Database backup script
#!/bin/bash
# backup_db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/userapi"
mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump -h localhost -U userapi_user user_management | gzip > \
    $BACKUP_DIR/db_backup_$DATE.sql.gz

# Application data backup
tar -czf $BACKUP_DIR/app_data_$DATE.tar.gz \
    /home/userapi/app/data \
    /home/userapi/app/.env \
    /home/userapi/app/ssl

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### 4. Performance Tuning

```bash
# Nginx tuning
worker_processes auto;
worker_connections 1024;
sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
gzip on;

# PostgreSQL tuning
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
```

## Security Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw --force enable

# Fail2ban for SSH protection
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

### 2. SSL Security

```bash
# Test SSL configuration
curl -s https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com

# Automated certificate renewal
echo "0 3 * * * certbot renew --quiet" | sudo crontab -
```

### 3. Application Security

- Enable IP whitelisting in production
- Use strong passwords for all accounts
- Regularly rotate API keys and secrets
- Monitor security logs for suspicious activity
- Keep dependencies updated

## Troubleshooting

### Common Issues

1. **Permission Denied Errors:**
```bash
# Fix file permissions
sudo chown -R userapi:userapi /home/userapi/app
sudo chmod +x /home/userapi/app/scripts/*.sh
```

2. **Database Connection Issues:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql
# Check connection
psql -h localhost -U userapi_user user_management
```

3. **Redis Connection Issues:**
```bash
# Check Redis status
sudo systemctl status redis
# Test connection
redis-cli ping
```

4. **Memory Issues:**
```bash
# Monitor memory usage
free -h
# Check application memory
ps aux | grep python
```

### Performance Issues

1. **Slow Response Times:**
   - Check database query performance
   - Verify Redis is working
   - Monitor CPU and memory usage
   - Review nginx access logs

2. **High Error Rates:**
   - Check application logs
   - Verify database connectivity
   - Monitor rate limiting

## Scaling Considerations

### Horizontal Scaling

1. **Load Balancer Setup:**
```nginx
upstream userapi_backend {
    server app1.internal:8000;
    server app2.internal:8000;
    server app3.internal:8000;
}

server {
    location / {
        proxy_pass http://userapi_backend;
    }
}
```

2. **Database Clustering:**
   - PostgreSQL streaming replication
   - Read replicas for improved performance
   - Connection pooling with PgBouncer

3. **Redis Clustering:**
   - Redis Sentinel for high availability
   - Redis Cluster for horizontal scaling

### Vertical Scaling

- Increase server resources (CPU, RAM)
- Optimize database configuration
- Tune application worker processes
- Use SSD storage for better I/O performance

## Compliance and Auditing

### Data Protection

- Implement data retention policies
- Ensure GDPR compliance for EU users
- Regular security audits
- Data encryption at rest and in transit

### Logging and Auditing

- Comprehensive audit logs
- Security event monitoring
- Regular log analysis
- Compliance reporting

## Support and Maintenance

### Regular Tasks

- [ ] Weekly security updates
- [ ] Monthly backup verification
- [ ] Quarterly security review
- [ ] Annual dependency audit

### Emergency Procedures

1. **Security Incident Response**
2. **Data Recovery Procedures**
3. **Service Restoration Steps**
4. **Communication Protocols**

---

For additional support, refer to the API documentation at `/docs` or contact the development team.