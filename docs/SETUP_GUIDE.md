# User Management API - Complete Setup Guide

This guide provides step-by-step instructions for setting up the User Management API in different environments.

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git (optional, for cloning)
- 4GB+ RAM recommended
- 10GB+ disk space

## 🚀 Quick Start (Development)

### 1. Download and Setup

```bash
# Create project directory
mkdir user-management-api
cd user-management-api

# Copy all the project files to this directory
# (You should have all the files from the previous setup)

# Verify you have these key files:
ls -la
# Should show: main.py, requirements.txt, .env.example, app/, docs/, etc.
```

### 2. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit the .env file with your preferred editor
nano .env  # or vim .env, or code .env
```

**Critical settings to change:**
```bash
# SECURITY - MUST CHANGE IN PRODUCTION
SECRET_KEY=your-super-secret-key-here-at-least-32-characters-long
ENCRYPTION_KEY=your-32-byte-encryption-key-change-this-too

# ADMIN CREDENTIALS
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-admin-password-123!

# IP WHITELISTING (disable for development)
ENABLE_IP_WHITELIST=false
```

### 4. Run the Application

```bash
# Run in development mode
python main.py
```

The API will start on `http://localhost:8000`

### 5. Verify Installation

```bash
# Check health endpoint
curl http://localhost:8000/health

# Check API info
curl http://localhost:8000/api/v1/info

# Access documentation
# Open browser to: http://localhost:8000/docs
```

## 🏢 Production Setup

### 1. Server Requirements

**Minimum Requirements:**
- 2 CPU cores
- 4GB RAM
- 20GB disk space
- Ubuntu 20.04+ / CentOS 8+ / RHEL 8+

**Recommended:**
- 4+ CPU cores
- 8GB+ RAM
- 50GB+ SSD storage
- Load balancer (nginx/Apache)

### 2. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.8+
sudo apt install python3 python3-pip python3-venv -y

# Install system dependencies
sudo apt install build-essential libssl-dev libffi-dev -y

# Create application user
sudo useradd -m -s /bin/bash apiuser
sudo usermod -aG sudo apiuser
```

### 3. Application Setup

```bash
# Switch to application user
sudo su - apiuser

# Create application directory
mkdir -p /home/apiuser/user-management-api
cd /home/apiuser/user-management-api

# Copy application files here
# ... (copy all your files)

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Production Configuration

```bash
# Create production environment file
cp .env.example .env

# Edit with production settings
nano .env
```

**Production .env example:**
```bash
# SECURITY - GENERATED SECURE VALUES
SECRET_KEY=prod-secret-key-32-chars-minimum-very-secure-random-string-here
ENCRYPTION_KEY=another-32-byte-encryption-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# DATABASE
DATABASE_URL=sqlite:///./user_management.db

# SECURITY SETTINGS
BCRYPT_ROUNDS=12

# ADMIN (use strong password)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Super-Secure-Admin-Password-2024!

# IP WHITELISTING (ENABLE IN PRODUCTION)
ENABLE_IP_WHITELIST=true
WHITELISTED_IPS=192.168.1.100,10.0.0.5,your.server.public.ip

# RATE LIMITING
RATE_LIMIT_PER_MINUTE=100

# BATCH PROCESSING
BATCH_LOG_INTERVAL_MINUTES=5
MEMORY_THRESHOLD_MB=200

# APPLICATION
APP_NAME=User Management API
APP_VERSION=1.0.0
DEBUG=false
```

### 5. Systemd Service Setup

Create systemd service file:

```bash
sudo nano /etc/systemd/system/user-management-api.service
```

```ini
[Unit]
Description=User Management API
After=network.target

[Service]
Type=simple
User=apiuser
Group=apiuser
WorkingDirectory=/home/apiuser/user-management-api
Environment=PATH=/home/apiuser/user-management-api/venv/bin
ExecStart=/home/apiuser/user-management-api/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/apiuser/user-management-api

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable user-management-api

# Start service
sudo systemctl start user-management-api

# Check status
sudo systemctl status user-management-api

# View logs
sudo journalctl -u user-management-api -f
```

### 6. Nginx Reverse Proxy

Install nginx:
```bash
sudo apt install nginx -y
```

Create nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/user-management-api
```

```nginx
server {
    listen 80;
    server_name your-domain.com;  # Change this to your domain

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 8k;
        proxy_buffers 8 8k;
    }

    # Health check endpoint (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # No rate limiting for health checks
        limit_req off;
    }

    # Block common attack paths
    location ~ /\. {
        deny all;
        return 404;
    }
    
    location ~ ^/(admin|staff)/ {
        # Additional security for admin/staff endpoints
        allow 192.168.1.0/24;  # Adjust to your admin network
        deny all;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable the site:
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/user-management-api /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

### 7. SSL Certificate (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx -y

# Get certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal (already configured by certbot)
sudo systemctl status certbot.timer
```

### 8. Firewall Configuration

```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow application port (if needed for direct access)
sudo ufw allow 8000

# Check status
sudo ufw status
```

## 🐳 Docker Setup (Alternative)

### 1. Create Dockerfile

```dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 apiuser && chown -R apiuser:apiuser /app
USER apiuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2. Create docker-compose.yml

```yaml
version: '3.8'

services:
  user-management-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - ADMIN_USERNAME=${ADMIN_USERNAME}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - ENABLE_IP_WHITELIST=${ENABLE_IP_WHITELIST}
      - WHITELISTED_IPS=${WHITELISTED_IPS}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
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
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - user-management-api
    restart: unless-stopped
```

### 3. Run with Docker

```bash
# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop
docker-compose down
```

## 🔧 Environment Configurations

### Development Environment

```bash
# .env for development
SECRET_KEY=dev-secret-key-not-for-production
ENCRYPTION_KEY=dev-encryption-key-32-characters
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ENABLE_IP_WHITELIST=false
DEBUG=true
RATE_LIMIT_PER_MINUTE=60
```

### Staging Environment

```bash
# .env for staging
SECRET_KEY=staging-secret-key-secure-32-chars
ENCRYPTION_KEY=staging-encryption-key-32-chars
ADMIN_USERNAME=staging_admin
ADMIN_PASSWORD=StagingPassword123!
ENABLE_IP_WHITELIST=true
WHITELISTED_IPS=staging.internal.ip,dev.team.ips
DEBUG=false
RATE_LIMIT_PER_MINUTE=100
```

### Production Environment

```bash
# .env for production
SECRET_KEY=${PROD_SECRET_KEY}  # From secure vault
ENCRYPTION_KEY=${PROD_ENCRYPTION_KEY}  # From secure vault
ADMIN_USERNAME=prod_admin
ADMIN_PASSWORD=${PROD_ADMIN_PASSWORD}  # From secure vault
ENABLE_IP_WHITELIST=true
WHITELISTED_IPS=prod.server.ip,admin.office.ip
DEBUG=false
RATE_LIMIT_PER_MINUTE=200
BATCH_LOG_INTERVAL_MINUTES=5
MEMORY_THRESHOLD_MB=500
```

## 🔍 Monitoring Setup

### 1. Application Monitoring

Create monitoring script:
```bash
nano /home/apiuser/monitor.sh
```

```bash
#!/bin/bash

# Monitor script for User Management API
LOG_FILE="/var/log/user-management-api-monitor.log"
API_URL="http://localhost:8000/health"

# Function to log with timestamp
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

# Check API health
check_health() {
    response=$(curl -s -w "%{http_code}" $API_URL)
    http_code="${response: -3}"
    
    if [ "$http_code" == "200" ]; then
        log_message "API health check: OK"
        return 0
    else
        log_message "API health check: FAILED (HTTP $http_code)"
        return 1
    fi
}

# Check disk space
check_disk() {
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
    if [ $disk_usage -gt 90 ]; then
        log_message "ALERT: Disk usage high: ${disk_usage}%"
    fi
}

# Check memory
check_memory() {
    memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    if (( $(echo "$memory_usage > 90" | bc -l) )); then
        log_message "ALERT: Memory usage high: ${memory_usage}%"
    fi
}

# Main monitoring
log_message "Starting health check"
check_health
check_disk
check_memory
log_message "Health check complete"
```

Make executable and add to cron:
```bash
chmod +x /home/apiuser/monitor.sh

# Add to crontab (run every 5 minutes)
crontab -e
# Add line: */5 * * * * /home/apiuser/monitor.sh
```

### 2. Log Rotation

Create logrotate configuration:
```bash
sudo nano /etc/logrotate.d/user-management-api
```

```
/var/log/user-management-api-monitor.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 644 apiuser apiuser
}

/home/apiuser/user-management-api/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 apiuser apiuser
    postrotate
        systemctl reload user-management-api
    endscript
}
```

## 🔐 Security Hardening

### 1. System Security

```bash
# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Change SSH port (optional)
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh

# Install fail2ban
sudo apt install fail2ban -y

# Configure fail2ban for nginx
sudo nano /etc/fail2ban/jail.local
```

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

[sshd]
enabled = true
port = 2222
maxretry = 3
```

### 2. Application Security

```bash
# Set secure file permissions
chmod 600 .env
chmod 600 user_management.db
chmod -R 755 app/
chown -R apiuser:apiuser /home/apiuser/user-management-api/
```

## 🧪 Testing the Setup

### 1. Basic Functionality Test

```bash
# Test script
cat > test_setup.sh << 'EOF'
#!/bin/bash

API_BASE="http://localhost:8000/api/v1"

echo "Testing User Management API Setup..."

# Test 1: Health check
echo "1. Testing health endpoint..."
health_response=$(curl -s $API_BASE/../health)
if echo $health_response | grep -q "healthy"; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi

# Test 2: Register user
echo "2. Testing user registration..."
register_response=$(curl -s -X POST "$API_BASE/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "testuser",
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123",
        "type": "Personal"
    }')

if echo $register_response | grep -q "User registered successfully"; then
    echo "✓ User registration passed"
else
    echo "✗ User registration failed"
    echo "Response: $register_response"
    exit 1
fi

# Test 3: Login
echo "3. Testing user login..."
login_response=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "test@example.com",
        "password": "password123"
    }')

token=$(echo $login_response | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ ! -z "$token" ]; then
    echo "✓ User login passed"
else
    echo "✗ User login failed"
    exit 1
fi

# Test 4: Get profile
echo "4. Testing profile access..."
profile_response=$(curl -s -X GET "$API_BASE/auth/profile" \
    -H "Authorization: Bearer $token")

if echo $profile_response | grep -q "testuser"; then
    echo "✓ Profile access passed"
else
    echo "✗ Profile access failed"
    exit 1
fi

echo "All tests passed! ✓"
EOF

chmod +x test_setup.sh
./test_setup.sh
```

### 2. Performance Test

```bash
# Install Apache Bench
sudo apt install apache2-utils -y

# Test concurrent requests
ab -n 1000 -c 10 http://localhost:8000/health

# Test authentication endpoint
ab -n 100 -c 5 -p register_payload.json -T application/json http://localhost:8000/api/v1/auth/register
```

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. Port Already in Use
```bash
# Check what's using port 8000
sudo lsof -i :8000

# Kill process if needed
sudo kill -9 <PID>

# Or use different port
uvicorn main:app --port 8001
```

#### 2. Permission Denied on Database
```bash
# Fix database permissions
sudo chown apiuser:apiuser user_management.db
chmod 664 user_management.db
```

#### 3. Module Not Found Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

#### 4. SSL Certificate Issues
```bash
# Check certificate status
sudo certbot certificates

# Renew certificate
sudo certbot renew --dry-run
```

#### 5. High Memory Usage
```bash
# Check memory usage
free -h

# Adjust batch processing settings in .env
BATCH_LOG_INTERVAL_MINUTES=2
MEMORY_THRESHOLD_MB=100
```

### Log Locations

- **Application logs**: `journalctl -u user-management-api`
- **Nginx logs**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **System logs**: `/var/log/syslog`
- **Monitor logs**: `/var/log/user-management-api-monitor.log`

### Backup and Recovery

```bash
# Backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/apiuser/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
cp user_management.db $BACKUP_DIR/user_management_$DATE.db

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz .env main.py app/

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.db" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x backup.sh

# Add to crontab for daily backups
echo "0 2 * * * /home/apiuser/user-management-api/backup.sh" | crontab -
```

This completes the comprehensive setup guide for the User Management API. The system is now ready for development, staging, or production use with proper security, monitoring, and backup procedures.