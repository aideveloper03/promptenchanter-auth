# API Reference - User Management Backend

Complete reference for all API endpoints, request/response formats, and authentication methods.

## 📚 Table of Contents

1. [Authentication](#authentication)
2. [User Management Endpoints](#user-management-endpoints)
3. [Admin Endpoints](#admin-endpoints)
4. [Staff Endpoints](#staff-endpoints)
5. [Utility Endpoints](#utility-endpoints)
6. [Error Responses](#error-responses)
7. [Rate Limiting](#rate-limiting)
8. [Webhooks](#webhooks)

## 🔐 Authentication

### Authentication Methods

#### 1. JWT Token Authentication
Used for user, admin, and staff access to protected endpoints.

```http
Authorization: Bearer <jwt-token>
```

#### 2. API Key Authentication
Used for external API access with conversation limits.

```http
Authorization: Bearer <api-key>
```

### Token Expiration
- JWT tokens expire after 30 minutes (configurable)
- API keys do not expire but can be regenerated
- Refresh tokens are not implemented (re-login required)

## 👤 User Management Endpoints

### Register User

Register a new user account.

```http
POST /api/v1/auth/register
```

**Request Body:**
```json
{
  "username": "johndoe",
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123",
  "confirm_password": "SecurePass123",
  "about_me": "Software developer",
  "hobbies": "Coding, Reading",
  "type": "Personal"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully",
  "user_id": "1",
  "username": "johndoe"
}
```

**Password Requirements:**
- Minimum 8 characters
- At least 1 number
- At least 1 uppercase letter (recommended)
- At least 1 lowercase letter (recommended)

### Login User

Authenticate user and receive JWT token.

```http
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": "1800"
}
```

### Get User Profile

Get current user's profile information.

```http
GET /api/v1/auth/profile
Authorization: Bearer <jwt-token>
```

**Response (200):**
```json
{
  "username": "johndoe",
  "name": "John Doe",
  "email": "john@example.com",
  "about_me": "Software developer",
  "hobbies": "Coding, Reading",
  "type": "Personal",
  "time_created": "2024-01-01T12:00:00Z",
  "subscription_plan": "free",
  "credits": {
    "main": 5,
    "reset": 5
  },
  "limits": {
    "conversation_limit": 10,
    "reset": 10
  },
  "access_rtype": ["bpe", "tot"],
  "level": "basic",
  "additional_notes": ""
}
```

### Update User Profile

Update user profile information.

```http
PUT /api/v1/auth/profile
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "name": "John Smith",
  "about_me": "Senior Software Developer",
  "hobbies": "Coding, Reading, Gaming"
}
```

**Response (200):**
```json
{
  "message": "Profile updated successfully"
}
```

### Get API Key

Get encrypted API key for external usage.

```http
GET /api/v1/auth/api-key
Authorization: Bearer <jwt-token>
```

**Response (200):**
```json
{
  "key": "gAAAAABh...[encrypted-key]",
  "created_at": "2024-01-01T12:00:00Z"
}
```

### Regenerate API Key

Generate a new API key (invalidates the old one).

```http
POST /api/v1/auth/regenerate-key
Authorization: Bearer <jwt-token>
```

**Response (200):**
```json
{
  "key": "gAAAAABh...[new-encrypted-key]",
  "created_at": "2024-01-01T12:30:00Z"
}
```

### Reset Password

Change user password.

```http
PUT /api/v1/auth/password
Authorization: Bearer <jwt-token>
```

**Request Body:**
```json
{
  "current_password": "SecurePass123",
  "new_password": "NewSecurePass123",
  "confirm_new_password": "NewSecurePass123"
}
```

**Response (200):**
```json
{
  "message": "Password updated successfully"
}
```

### Delete Account

Delete user account (soft delete with backup).

```http
DELETE /api/v1/auth/account
Authorization: Bearer <jwt-token>
```

**Response (200):**
```json
{
  "message": "Account deleted successfully"
}
```

### Verify API Key

Verify API key and deduct conversation limit (for middleware use).

```http
POST /api/v1/auth/verify-key
Authorization: Bearer <api-key>
```

**Response (200):**
```json
{
  "valid": true,
  "username": "johndoe",
  "email": "john@example.com",
  "remaining_conversations": 9
}
```

### Log Message

Log a conversation message (for external APIs).

```http
POST /api/v1/auth/log-message
Authorization: Bearer <api-key>
```

**Request Body:**
```json
{
  "model": "gpt-3.5-turbo",
  "messages": [
    {"role": "user", "content": "Hello"},
    {"role": "assistant", "content": "Hi there!"}
  ],
  "research_model": false
}
```

**Response (200):**
```json
{
  "message": "Message logged successfully",
  "log_id": "123"
}
```

## 👑 Admin Endpoints

### Admin Login

Authenticate admin user.

```http
POST /api/v1/admin/login
```

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin_password"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": "1800"
}
```

### Get All Users

Get paginated list of all users.

```http
GET /api/v1/admin/users?limit=100&offset=0
Authorization: Bearer <admin-jwt-token>
```

**Query Parameters:**
- `limit` (integer, optional): Number of users per page (max 1000, default 100)
- `offset` (integer, optional): Number of users to skip (default 0)

**Response (200):**
```json
[
  {
    "username": "johndoe",
    "name": "John Doe",
    "email": "john@example.com",
    "about_me": "Software developer",
    "hobbies": "Coding, Reading",
    "type": "Personal",
    "time_created": "2024-01-01T12:00:00Z",
    "subscription_plan": "free",
    "credits": {"main": 5, "reset": 5},
    "limits": {"conversation_limit": 10, "reset": 10},
    "access_rtype": ["bpe", "tot"],
    "level": "basic",
    "additional_notes": ""
  }
]
```

### Get User by Username

Get specific user details.

```http
GET /api/v1/admin/users/{username}
Authorization: Bearer <admin-jwt-token>
```

**Response (200):**
```json
{
  "username": "johndoe",
  "name": "John Doe",
  "email": "john@example.com",
  "about_me": "Software developer",
  "hobbies": "Coding, Reading",
  "type": "Personal",
  "time_created": "2024-01-01T12:00:00Z",
  "subscription_plan": "free",
  "credits": {"main": 5, "reset": 5},
  "limits": {"conversation_limit": 10, "reset": 10},
  "access_rtype": ["bpe", "tot"],
  "level": "basic",
  "additional_notes": ""
}
```

### Update User (Admin)

Update any user's information.

```http
PUT /api/v1/admin/users/{username}
Authorization: Bearer <admin-jwt-token>
```

**Request Body:**
```json
{
  "name": "Updated Name",
  "email": "newemail@example.com",
  "subscription_plan": "premium",
  "limits": {
    "conversation_limit": 100,
    "reset": 100
  },
  "credits": {
    "main": 50,
    "reset": 50
  },
  "level": "advanced",
  "is_active": true
}
```

**Response (200):**
```json
{
  "message": "User updated successfully"
}
```

### Delete User (Admin)

Delete a user account.

```http
DELETE /api/v1/admin/users/{username}
Authorization: Bearer <admin-jwt-token>
```

**Response (200):**
```json
{
  "message": "User deleted successfully"
}
```

### Regenerate User API Key (Admin)

Regenerate API key for any user.

```http
POST /api/v1/admin/users/{username}/regenerate-key
Authorization: Bearer <admin-jwt-token>
```

**Response (200):**
```json
{
  "message": "API key regenerated successfully",
  "new_key": "pe-new-api-key-here"
}
```

### Create Staff Member

Create a new support staff member.

```http
POST /api/v1/admin/staff
Authorization: Bearer <admin-jwt-token>
```

**Request Body:**
```json
{
  "name": "Support Staff",
  "username": "support1",
  "email": "support@example.com",
  "password": "StaffPass123",
  "staff_level": "support"
}
```

**Staff Levels:**
- `new`: Read-only access to user information
- `support`: Can update email, password, conversation limits, and plans
- `advanced`: Same as support + can delete user accounts

**Response (201):**
```json
{
  "message": "Staff member created successfully",
  "staff_id": "1",
  "username": "support1"
}
```

### Reset All User Limits

Reset conversation limits for all users.

```http
POST /api/v1/admin/reset-limits
Authorization: Bearer <admin-jwt-token>
```

**Response (200):**
```json
{
  "message": "All user limits reset successfully"
}
```

## 👥 Staff Endpoints

### Staff Login

Authenticate support staff member.

```http
POST /api/v1/staff/login
```

**Request Body:**
```json
{
  "username": "support1",
  "password": "StaffPass123"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": "1800",
  "staff_level": "support"
}
```

### Get Users (Staff)

Get users list with permissions based on staff level.

```http
GET /api/v1/staff/users?limit=100&offset=0
Authorization: Bearer <staff-jwt-token>
```

**Response (200):**
```json
[
  {
    "username": "johndoe",
    "name": "John Doe",
    "email": "john@example.com",
    "about_me": "Software developer",
    "hobbies": "Coding, Reading",
    "type": "Personal",
    "time_created": "2024-01-01T12:00:00Z",
    "subscription_plan": "free",
    "credits": {"main": 5, "reset": 5},
    "limits": {"conversation_limit": 10, "reset": 10},
    "access_rtype": ["bpe", "tot"],
    "level": "basic",
    "additional_notes": ""
  }
]
```

*Note: `new` level staff won't see `additional_notes`*

### Update User (Staff)

Update user information based on staff permissions.

```http
PUT /api/v1/staff/users/{username}
Authorization: Bearer <staff-jwt-token>
```

**Request Body (support/advanced level):**
```json
{
  "email": "newemail@example.com",
  "limits": {
    "conversation_limit": 50,
    "reset": 50
  },
  "subscription_plan": "premium"
}
```

**Response (200):**
```json
{
  "message": "User updated successfully"
}
```

### Delete User (Staff)

Delete user account (advanced staff only).

```http
DELETE /api/v1/staff/users/{username}
Authorization: Bearer <staff-jwt-token>
```

**Response (200):**
```json
{
  "message": "User deleted successfully"
}
```

### Get Staff Profile

Get current staff member's profile.

```http
GET /api/v1/staff/profile
Authorization: Bearer <staff-jwt-token>
```

**Response (200):**
```json
{
  "id": 1,
  "name": "Support Staff",
  "username": "support1",
  "email": "support@example.com",
  "staff_level": "support",
  "time_created": "2024-01-01T12:00:00Z",
  "is_active": true
}
```

## 🛠️ Utility Endpoints

### Health Check

Get system health status.

```http
GET /health
```

**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
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

### API Information

Get API details and endpoints.

```http
GET /api/v1/info
```

**Response (200):**
```json
{
  "api_name": "User Management API",
  "version": "1.0.0",
  "endpoints": {
    "authentication": {
      "register": "POST /api/v1/auth/register",
      "login": "POST /api/v1/auth/login",
      "profile": "GET /api/v1/auth/profile"
    },
    "admin": {
      "login": "POST /api/v1/admin/login",
      "get_users": "GET /api/v1/admin/users"
    }
  },
  "authentication_methods": {
    "jwt_token": "Bearer token for user/admin/staff authentication",
    "api_key": "Bearer pe-xxx for API access with conversation limits"
  },
  "rate_limits": {
    "default": "60 requests per minute",
    "conversation_limits": "Per-user limits that reset daily"
  }
}
```

### Root Endpoint

Get basic API information.

```http
GET /
```

**Response (200):**
```json
{
  "message": "User Management API",
  "version": "1.0.0",
  "status": "running",
  "docs": "/docs",
  "health": "/health",
  "features": [
    "User registration and authentication",
    "API key management",
    "Conversation limits",
    "Admin controls",
    "Support staff management",
    "Message logging",
    "Rate limiting",
    "IP whitelisting",
    "Security encryption"
  ]
}
```

## ❌ Error Responses

### Standard Error Format

All errors follow a consistent format:

```json
{
  "error": true,
  "detail": "Error description",
  "status_code": 400,
  "timestamp": "1640995200.123"
}
```

### Common HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 400 | Bad Request | Invalid request data or parameters |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Access denied (IP not whitelisted, insufficient permissions) |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists (e.g., email/username taken) |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit or conversation limit exceeded |
| 500 | Internal Server Error | Server-side error |

### Validation Errors

```json
{
  "detail": [
    {
      "loc": ["body", "password"],
      "msg": "Password must be at least 8 characters long",
      "type": "value_error"
    }
  ]
}
```

### Authentication Errors

```json
{
  "detail": "Invalid API key",
  "error": true,
  "status_code": 401
}
```

### Rate Limiting Errors

```json
{
  "detail": "Rate limit exceeded. Please try again later.",
  "limit": 60,
  "window": "60 seconds"
}
```

```json
{
  "detail": "Conversation limit exceeded. Limit resets every 24 hours."
}
```

## 🚦 Rate Limiting

### Global Rate Limiting

- **Default**: 60 requests per minute per IP
- **Configurable** via `RATE_LIMIT_PER_MINUTE` environment variable
- **Window**: 1 minute (60 seconds)

### Conversation Limits

- **Per-user limits** based on subscription plan
- **Default**: 10 conversations per day for free users
- **Reset**: Every 24 hours at midnight
- **Admin override**: Admins can manually reset limits

### Rate Limit Headers

Rate limit information is included in response headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1640995260
```

## 📞 Webhooks

### Message Log Webhook

When enabled, the system can send webhooks for logged messages:

**Webhook URL Configuration:**
```bash
WEBHOOK_URL=https://your-app.com/webhooks/message-logged
WEBHOOK_SECRET=your-webhook-secret
```

**Webhook Payload:**
```json
{
  "event": "message_logged",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "username": "johndoe",
    "email": "john@example.com",
    "model": "gpt-3.5-turbo",
    "message_count": 2,
    "research_model": false
  },
  "signature": "sha256=..."
}
```

**Signature Verification:**
```python
import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, f"sha256={expected_signature}")
```

## 📊 Usage Examples

### Complete User Flow

```bash
# 1. Register user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","name":"Test User","email":"test@example.com","password":"Password123","confirm_password":"Password123","type":"Personal"}'

# 2. Login
TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123"}' | jq -r .access_token)

# 3. Get profile
curl -X GET "http://localhost:8000/api/v1/auth/profile" \
  -H "Authorization: Bearer $TOKEN"

# 4. Get API key
API_KEY=$(curl -s -X GET "http://localhost:8000/api/v1/auth/api-key" \
  -H "Authorization: Bearer $TOKEN" | jq -r .key)

# 5. Use API key (this would be your actual API key, not the encrypted one)
curl -X POST "http://localhost:8000/api/v1/auth/verify-key" \
  -H "Authorization: Bearer pe-your-actual-api-key"
```

### Admin Operations

```bash
# Admin login
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123!"}' | jq -r .access_token)

# Get all users
curl -X GET "http://localhost:8000/api/v1/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Update user limits
curl -X PUT "http://localhost:8000/api/v1/admin/users/testuser" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"limits":{"conversation_limit":100,"reset":100},"subscription_plan":"premium"}'
```

This completes the comprehensive API reference for the User Management Backend. All endpoints are documented with examples, error responses, and usage patterns.