# User Management Backend API

A comprehensive, secure user management backend system built with FastAPI, featuring user registration, authentication, API key management, conversation limits, admin controls, and robust security measures.

## 🚀 Features

### Core Features
- **User Registration & Authentication**: Secure user registration with JWT-based authentication
- **API Key Management**: Generate and manage API keys with conversation limits
- **Conversation Limits**: Per-user limits that reset every 24 hours
- **Admin Panel**: Full administrative control over users and system
- **Support Staff**: Multi-level staff system with different permission levels
- **Message Logging**: Batch processing of message logs with memory management
- **Rate Limiting**: IP-based rate limiting to prevent abuse

### Security Features
- **Password Security**: bcrypt hashing with configurable rounds
- **Data Encryption**: Sensitive data encryption using Fernet
- **IP Whitelisting**: Configurable IP whitelisting for enhanced security
- **Input Sanitization**: XSS protection and input validation
- **SQL Injection Protection**: Parameterized queries and ORM usage
- **Session Management**: Secure JWT token handling

### Advanced Features
- **Background Tasks**: Scheduled tasks for cleanup and maintenance
- **Health Monitoring**: System health checks and memory monitoring
- **Batch Processing**: Efficient message logging with batch operations
- **High Concurrency**: Async/await support for high-performance operations
- **Database Backup**: Soft delete with backup storage

## 📋 Requirements

- Python 3.8+
- SQLite (included)
- See `requirements.txt` for Python dependencies

## 🛠️ Installation

### Quick Setup

1. **Clone or create the project directory**:
```bash
mkdir user-management-api
cd user-management-api
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Create environment configuration**:
```bash
cp .env.example .env
```

4. **Edit the `.env` file with your configuration**:
```bash
# Security - IMPORTANT: Change these in production!
SECRET_KEY=your-super-secret-key-here-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=sqlite:///./user_management.db

# Security Settings
BCRYPT_ROUNDS=12
ENCRYPTION_KEY=your-encryption-key-here-32-bytes

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123!

# IP Whitelisting (set to true in production)
ENABLE_IP_WHITELIST=false
WHITELISTED_IPS=127.0.0.1,localhost

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

5. **Run the application**:
```bash
python main.py
```

The API will be available at `http://localhost:8000`

### Production Setup

For production deployment:

1. **Set secure environment variables**:
```bash
export SECRET_KEY="your-very-secure-secret-key-at-least-32-characters"
export ENCRYPTION_KEY="your-32-byte-encryption-key-here"
export ADMIN_PASSWORD="secure-admin-password"
export ENABLE_IP_WHITELIST=true
export WHITELISTED_IPS="your.server.ip,another.allowed.ip"
```

2. **Use a production WSGI server**:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

3. **Set up reverse proxy** (nginx recommended):
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 📖 API Documentation

### Interactive Documentation
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Authentication Methods

#### 1. JWT Authentication (Users/Admin/Staff)
```bash
# Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Use token in requests
curl -X GET "http://localhost:8000/api/v1/auth/profile" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

#### 2. API Key Authentication
```bash
# Get API key (after login)
curl -X GET "http://localhost:8000/api/v1/auth/api-key" \
  -H "Authorization: Bearer your-jwt-token"

# Use API key for requests
curl -X POST "http://localhost:8000/api/v1/auth/verify-key" \
  -H "Authorization: Bearer pe-your-api-key-here"
```

### Core Endpoints

#### User Management
```bash
# Register new user
POST /api/v1/auth/register
{
  "username": "johndoe",
  "name": "John Doe", 
  "email": "john@example.com",
  "password": "password123",
  "confirm_password": "password123",
  "type": "Personal"
}

# Login
POST /api/v1/auth/login
{
  "email": "john@example.com",
  "password": "password123"
}

# Get profile
GET /api/v1/auth/profile
Headers: Authorization: Bearer <jwt-token>

# Update profile
PUT /api/v1/auth/profile
Headers: Authorization: Bearer <jwt-token>
{
  "name": "John Smith",
  "about_me": "Updated about me"
}
```

#### API Key Management
```bash
# Get encrypted API key
GET /api/v1/auth/api-key
Headers: Authorization: Bearer <jwt-token>

# Regenerate API key  
POST /api/v1/auth/regenerate-key
Headers: Authorization: Bearer <jwt-token>

# Verify API key and deduct limit
POST /api/v1/auth/verify-key
Headers: Authorization: Bearer <api-key>
```

#### Admin Operations
```bash
# Admin login
POST /api/v1/admin/login
{
  "username": "admin",
  "password": "admin123!"
}

# Get all users
GET /api/v1/admin/users?limit=100&offset=0
Headers: Authorization: Bearer <admin-jwt-token>

# Update user
PUT /api/v1/admin/users/johndoe
Headers: Authorization: Bearer <admin-jwt-token>
{
  "subscription_plan": "premium",
  "limits": {"conversation_limit": 100, "reset": 100}
}

# Create staff member
POST /api/v1/admin/staff
Headers: Authorization: Bearer <admin-jwt-token>
{
  "name": "Support User",
  "username": "support1",
  "email": "support@example.com", 
  "password": "support123",
  "staff_level": "support"
}
```

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    about_me TEXT DEFAULT '',
    hobbies TEXT DEFAULT '',
    type TEXT NOT NULL DEFAULT 'Personal',
    time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    subscription_plan TEXT DEFAULT 'free',
    credits TEXT DEFAULT '{"main":5, "reset":5}',
    limits TEXT DEFAULT '{"conversation_limit":10, "reset":10}',
    access_rtype TEXT DEFAULT '["bpe","tot"]',
    level TEXT DEFAULT 'basic',
    additional_notes TEXT DEFAULT '',
    key TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    last_limit_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Message Logs Table
```sql
CREATE TABLE message_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    model TEXT NOT NULL,
    messages TEXT NOT NULL,
    research_model BOOLEAN DEFAULT 0,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 Integration Guide

### Using as Middleware

The system provides middleware functions for external APIs:

```python
from app.middleware.auth_middleware import UserManagerClient

# Initialize client
user_manager = UserManagerClient()

@app.on_event("startup")
async def startup():
    await user_manager.initialize()

@app.post("/api/chat")
async def chat_endpoint(request: Request, data: dict):
    # Get API key from headers
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing API key")
    
    api_key = auth_header.split(" ")[1]
    client_ip = request.client.host
    
    # Verify user and deduct usage
    try:
        user_info = await user_manager.verify_user(api_key, client_ip)
        
        # Process the chat request
        response = process_chat(data)
        
        # Log the conversation
        await user_manager.log_conversation(
            api_key, 
            data.get("model", "gpt-3.5-turbo"),
            data.get("messages", [])
        )
        
        return response
        
    except HTTPException:
        raise
```

### Decorator Usage

```python
from app.middleware.auth_middleware import require_api_key

@require_api_key
async def protected_route(request: Request):
    user = request.state.user
    remaining = request.state.remaining_conversations
    return {"user": user["username"], "remaining": remaining}
```

## 🔒 Security Configuration

### IP Whitelisting

Enable IP whitelisting in production:

```bash
# .env
ENABLE_IP_WHITELIST=true
WHITELISTED_IPS=192.168.1.100,10.0.0.5,your.server.ip
```

### Password Requirements

- Minimum 8 characters
- At least 1 number
- At least 1 uppercase letter (recommended)
- At least 1 lowercase letter (recommended)

### API Key Format

- Prefix: `pe-`
- Length: 35 characters total (pe- + 32 random characters)
- Characters: alphanumeric (a-z, A-Z, 0-9)

## 🎯 Usage Examples

### Complete User Workflow

```bash
# 1. Register user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "name": "Test User",
    "email": "test@example.com", 
    "password": "password123",
    "confirm_password": "password123",
    "type": "Personal"
  }'

# 2. Login to get JWT token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# 3. Get API key
curl -X GET "http://localhost:8000/api/v1/auth/api-key" \
  -H "Authorization: Bearer eyJ..."

# Response: {"key": "encrypted-key", "created_at": "2024-..."}

# 4. Use API key for requests
curl -X POST "http://localhost:8000/api/v1/auth/verify-key" \
  -H "Authorization: Bearer pe-your-actual-api-key-here"

# Response: {"valid": true, "username": "testuser", "remaining_conversations": 9}
```

### Message Logging

```bash
curl -X POST "http://localhost:8000/api/v1/auth/log-message" \
  -H "Authorization: Bearer pe-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "Hello"},
      {"role": "assistant", "content": "Hi there!"}
    ],
    "research_model": false
  }'
```

## 🏥 Health Monitoring

### Health Check Endpoint

```bash
curl -X GET "http://localhost:8000/health"
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00",
  "database": "healthy",
  "memory": {
    "used_percent": 45.2,
    "used_mb": 512.3,
    "available_mb": 1024.7
  },
  "disk": {
    "used_percent": 67.8,
    "free_gb": 15.2
  },
  "message_buffer_size": 25,
  "scheduler_running": true
}
```

### Background Tasks

The system runs several background tasks:
- **Daily Limit Reset**: Midnight (00:00) - Resets all user conversation limits
- **Message Batch Processing**: Every 10 minutes (configurable)
- **Memory Check**: Every 2 minutes - Forces batch processing if memory threshold exceeded
- **Log Cleanup**: Weekly (Sunday 02:00) - Removes logs older than 90 days
- **Usage Statistics**: Daily (01:00) - Generates usage reports

## 🐛 Troubleshooting

### Common Issues

#### 1. Database Connection Error
```bash
# Check if database file exists and is writable
ls -la user_management.db
chmod 664 user_management.db
```

#### 2. Permission Denied on API Key
```bash
# Check if IP whitelisting is enabled
curl -X GET "http://localhost:8000/health"
# If enabled, add your IP to WHITELISTED_IPS
```

#### 3. Rate Limit Exceeded
```bash
# Wait or increase rate limit in .env
RATE_LIMIT_PER_MINUTE=100
```

#### 4. Conversation Limit Exceeded
```bash
# Wait for daily reset or admin can reset manually
curl -X POST "http://localhost:8000/api/v1/admin/reset-limits" \
  -H "Authorization: Bearer admin-jwt-token"
```

### Logs and Debugging

Enable debug mode:
```bash
# .env
DEBUG=true
```

Check application logs:
```bash
python main.py 2>&1 | tee app.log
```

## 🧪 Testing

### Run Tests
```bash
pytest tests/ -v
```

### Manual Testing

Use the provided test script:
```bash
python tests/test_api.py
```

## 📈 Performance Tuning

### Database Optimization
- Indexes are automatically created for frequently queried fields
- Use pagination for large result sets
- Consider connection pooling for high load

### Memory Management
- Adjust `MEMORY_THRESHOLD_MB` in .env
- Adjust `BATCH_LOG_INTERVAL_MINUTES` for more frequent processing
- Monitor health endpoint for memory usage

### Rate Limiting
- Adjust `RATE_LIMIT_PER_MINUTE` based on your needs
- Implement Redis for distributed rate limiting if needed

## 🔄 Backup and Recovery

### Database Backup
```bash
# Create backup
cp user_management.db user_management_backup_$(date +%Y%m%d).db

# Restore backup
cp user_management_backup_20240101.db user_management.db
```

### Configuration Backup
```bash
# Backup environment and config
tar -czf config_backup_$(date +%Y%m%d).tar.gz .env main.py app/
```

## 🎉 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation at `/docs`
3. Check the health endpoint for system status
4. Create an issue with detailed error information

## 🔮 Roadmap

Future enhancements:
- [ ] Redis integration for session storage
- [ ] Email verification system
- [ ] Two-factor authentication
- [ ] Advanced analytics dashboard
- [ ] Webhook support for external integrations
- [ ] Docker containerization
- [ ] Kubernetes deployment configs