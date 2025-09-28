# Integration Guide - User Management API

This guide explains how to integrate the User Management API with external applications and services as a middleware for authentication and user management.

## 📋 Table of Contents

1. [Integration Overview](#integration-overview)
2. [FastAPI Integration](#fastapi-integration)
3. [Flask Integration](#flask-integration)
4. [Express.js Integration](#expressjs-integration)
5. [Django Integration](#django-integration)
6. [Standalone Client Usage](#standalone-client-usage)
7. [Middleware Functions](#middleware-functions)
8. [Best Practices](#best-practices)
9. [Error Handling](#error-handling)
10. [Performance Optimization](#performance-optimization)

## 🔄 Integration Overview

The User Management API can be integrated as a middleware service to handle:
- User authentication via API keys
- Conversation limit management
- Request logging and monitoring
- Rate limiting and security
- User information retrieval

### Architecture Pattern

```
[Client] → [Your API] → [User Management Middleware] → [Your Business Logic]
                    ↓
            [User Management Database]
```

## 🚀 FastAPI Integration

### Method 1: Using the Provided Middleware Class

```python
# main.py
from fastapi import FastAPI, Request, HTTPException
from app.middleware.auth_middleware import UserManagerClient
import os

app = FastAPI()

# Initialize user manager client
user_manager = UserManagerClient(
    db_path=os.getenv("USER_MANAGEMENT_DB", "user_management.db")
)

@app.on_event("startup")
async def startup():
    await user_manager.initialize()

@app.on_event("shutdown")
async def shutdown():
    await user_manager.close()

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Global authentication middleware"""
    
    # Skip auth for public endpoints
    public_paths = ["/health", "/docs", "/openapi.json"]
    if request.url.path in public_paths:
        response = await call_next(request)
        return response
    
    # Extract API key
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid authorization header")
    
    api_key = auth_header.split(" ")[1]
    client_ip = request.client.host
    
    try:
        # Verify user and get info
        user_info = await user_manager.verify_user(api_key, client_ip)
        
        # Add user info to request state
        request.state.user = user_info["user"]
        request.state.remaining_conversations = user_info["remaining_conversations"]
        
        # Process request
        response = await call_next(request)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Authentication failed: {str(e)}")

@app.post("/api/chat")
async def chat_endpoint(request: Request, data: dict):
    """Protected chat endpoint"""
    user = request.state.user
    remaining = request.state.remaining_conversations
    
    # Your chat logic here
    chat_response = process_chat(data)
    
    # Log the conversation
    await user_manager.log_conversation(
        user["key"],
        data.get("model", "gpt-3.5-turbo"),
        data.get("messages", []),
        data.get("research_model", False)
    )
    
    return {
        "response": chat_response,
        "user": user["username"],
        "remaining_conversations": remaining - 1
    }

def process_chat(data):
    # Your actual chat processing logic
    return {"message": "Hello from your API!"}
```

### Method 2: Using Decorator Pattern

```python
from fastapi import FastAPI, Request, Depends
from app.middleware.auth_middleware import require_api_key, UserManagerClient

app = FastAPI()
user_manager = UserManagerClient()

@app.on_event("startup")
async def startup():
    await user_manager.initialize()

@require_api_key
@app.post("/api/protected")
async def protected_endpoint(request: Request, data: dict):
    """Protected endpoint using decorator"""
    user = request.state.user
    
    # Your business logic here
    result = your_business_logic(data)
    
    # Optionally log the action
    await user_manager.log_conversation(
        user["key"],
        "custom-action",
        [{"action": "api_call", "data": data}]
    )
    
    return {"result": result, "user": user["username"]}

def your_business_logic(data):
    return {"processed": True, "data": data}
```

### Method 3: Manual Verification

```python
from fastapi import FastAPI, Request, HTTPException, Header
from app.middleware.auth_middleware import UserManagerClient

app = FastAPI()
user_manager = UserManagerClient()

async def verify_api_key(authorization: str = Header(None)):
    """Dependency for manual API key verification"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing authorization header")
    
    api_key = authorization.split(" ")[1]
    
    try:
        user_info = await user_manager.verify_user(api_key)
        return user_info
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Authentication failed: {str(e)}")

@app.post("/api/manual")
async def manual_auth_endpoint(
    data: dict,
    user_info: dict = Depends(verify_api_key)
):
    """Manually verify API key using dependency"""
    user = user_info["user"]
    
    # Your logic here
    return {"message": f"Hello {user['username']}", "data": data}
```

## 🌶️ Flask Integration

### Basic Flask Integration

```python
# app.py
from flask import Flask, request, jsonify, g
from functools import wraps
import asyncio
import sys
import os

# Add the user management path
sys.path.append(os.path.join(os.path.dirname(__file__), 'user-management-api'))
from app.middleware.auth_middleware import UserManagerClient

app = Flask(__name__)

# Initialize user manager
user_manager = UserManagerClient()

# Initialize on startup
@app.before_first_request
def initialize():
    asyncio.run(user_manager.initialize())

# Cleanup on shutdown
import atexit
atexit.register(lambda: asyncio.run(user_manager.close()))

def require_auth(f):
    """Flask decorator for API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        api_key = auth_header.split(' ')[1]
        client_ip = request.remote_addr
        
        try:
            # Verify user (run async in sync context)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            user_info = loop.run_until_complete(
                user_manager.verify_user(api_key, client_ip)
            )
            loop.close()
            
            # Store user info in Flask's g object
            g.user = user_info["user"]
            g.remaining_conversations = user_info["remaining_conversations"]
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    
    return decorated_function

@app.route('/api/chat', methods=['POST'])
@require_auth
def chat():
    """Protected chat endpoint"""
    data = request.get_json()
    
    # Your chat logic
    chat_response = process_chat(data)
    
    # Log conversation (async in sync context)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(
        user_manager.log_conversation(
            g.user["key"],
            data.get("model", "gpt-3.5-turbo"),
            data.get("messages", [])
        )
    )
    loop.close()
    
    return jsonify({
        'response': chat_response,
        'user': g.user["username"],
        'remaining_conversations': g.remaining_conversations - 1
    })

def process_chat(data):
    # Your chat processing logic
    return {"message": "Hello from Flask!"}

if __name__ == '__main__':
    app.run(debug=True)
```

### Flask with AsyncIO Support

```python
# app.py (using Flask with asyncio)
from quart import Quart, request, jsonify, g
from functools import wraps
from app.middleware.auth_middleware import UserManagerClient

app = Quart(__name__)
user_manager = UserManagerClient()

@app.before_serving
async def initialize():
    await user_manager.initialize()

@app.after_serving
async def cleanup():
    await user_manager.close()

def require_auth(f):
    """Quart decorator for API key authentication"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        api_key = auth_header.split(' ')[1]
        client_ip = request.remote_addr
        
        try:
            user_info = await user_manager.verify_user(api_key, client_ip)
            g.user = user_info["user"]
            g.remaining_conversations = user_info["remaining_conversations"]
            
            return await f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    
    return decorated_function

@app.route('/api/chat', methods=['POST'])
@require_auth
async def chat():
    data = await request.get_json()
    
    chat_response = await process_chat(data)
    
    await user_manager.log_conversation(
        g.user["key"],
        data.get("model", "gpt-3.5-turbo"),
        data.get("messages", [])
    )
    
    return jsonify({
        'response': chat_response,
        'user': g.user["username"],
        'remaining_conversations': g.remaining_conversations - 1
    })

async def process_chat(data):
    # Your async chat processing logic
    return {"message": "Hello from Quart!"}
```

## 🟢 Express.js Integration

### Using HTTP Requests

```javascript
// middleware/auth.js
const axios = require('axios');

const USER_MANAGEMENT_URL = process.env.USER_MANAGEMENT_URL || 'http://localhost:8000';

async function verifyApiKey(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing authorization header' });
        }
        
        const apiKey = authHeader.split(' ')[1];
        
        // Verify API key with user management service
        const response = await axios.post(
            `${USER_MANAGEMENT_URL}/api/v1/auth/verify-key`,
            {},
            {
                headers: {
                    'Authorization': authHeader,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        // Store user info in request
        req.user = {
            username: response.data.username,
            email: response.data.email,
            remainingConversations: response.data.remaining_conversations
        };
        
        next();
        
    } catch (error) {
        if (error.response) {
            return res.status(error.response.status).json({
                error: error.response.data.detail || 'Authentication failed'
            });
        }
        
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function logMessage(apiKey, model, messages, researchModel = false) {
    try {
        await axios.post(
            `${USER_MANAGEMENT_URL}/api/v1/auth/log-message`,
            {
                model,
                messages,
                research_model: researchModel
            },
            {
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                }
            }
        );
    } catch (error) {
        console.error('Failed to log message:', error.message);
    }
}

module.exports = { verifyApiKey, logMessage };
```

```javascript
// app.js
const express = require('express');
const { verifyApiKey, logMessage } = require('./middleware/auth');

const app = express();
app.use(express.json());

// Protected route
app.post('/api/chat', verifyApiKey, async (req, res) => {
    try {
        const { model, messages } = req.body;
        
        // Your chat processing logic
        const chatResponse = await processChatRequest(messages, model);
        
        // Log the conversation
        const apiKey = req.headers.authorization.split(' ')[1];
        await logMessage(apiKey, model, [
            ...messages,
            { role: 'assistant', content: chatResponse.content }
        ]);
        
        res.json({
            response: chatResponse,
            user: req.user.username,
            remainingConversations: req.user.remainingConversations - 1
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

async function processChatRequest(messages, model) {
    // Your chat processing logic here
    return { content: "Hello from Express!" };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

### Using Direct Database Connection (Node.js)

```javascript
// db/userManager.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

class UserManager {
    constructor(dbPath = 'user_management.db') {
        this.db = new sqlite3.Database(dbPath);
    }
    
    async verifyApiKey(apiKey, clientIp = null) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE key = ? AND is_active = 1',
                [apiKey],
                (err, row) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    
                    if (!row) {
                        reject(new Error('Invalid API key'));
                        return;
                    }
                    
                    const limits = JSON.parse(row.limits);
                    if (limits.conversation_limit <= 0) {
                        reject(new Error('Conversation limit exceeded'));
                        return;
                    }
                    
                    // Deduct conversation limit
                    limits.conversation_limit -= 1;
                    
                    this.db.run(
                        'UPDATE users SET limits = ? WHERE key = ?',
                        [JSON.stringify(limits), apiKey],
                        (updateErr) => {
                            if (updateErr) {
                                reject(updateErr);
                                return;
                            }
                            
                            resolve({
                                user: row,
                                remainingConversations: limits.conversation_limit
                            });
                        }
                    );
                }
            );
        });
    }
    
    async logMessage(username, email, model, messages, researchModel = false) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO message_logs (username, email, model, messages, research_model)
                 VALUES (?, ?, ?, ?, ?)`,
                [username, email, model, JSON.stringify(messages), researchModel],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(this.lastID);
                    }
                }
            );
        });
    }
    
    close() {
        this.db.close();
    }
}

module.exports = UserManager;
```

## 🐍 Django Integration

### Django Middleware

```python
# middleware/auth_middleware.py
import asyncio
import json
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from asgiref.sync import sync_to_async
import sys
import os

# Add user management path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'user-management-api'))
from app.middleware.auth_middleware import UserManagerClient

class UserAuthMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        self.user_manager = UserManagerClient()
        # Initialize user manager
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.user_manager.initialize())
        loop.close()
        super().__init__(get_response)
    
    def process_request(self, request):
        # Skip authentication for admin and public paths
        skip_paths = ['/admin/', '/health/', '/static/', '/media/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Check for API authentication
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Missing authorization header'}, status=401)
        
        api_key = auth_header.split(' ')[1]
        client_ip = self.get_client_ip(request)
        
        try:
            # Verify user (run async in sync context)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            user_info = loop.run_until_complete(
                self.user_manager.verify_user(api_key, client_ip)
            )
            loop.close()
            
            # Add user info to request
            request.user_info = user_info["user"]
            request.remaining_conversations = user_info["remaining_conversations"]
            
            return None
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=401)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

### Django Views

```python
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import asyncio

@csrf_exempt
@require_http_methods(["POST"])
def chat_view(request):
    """Protected chat view"""
    try:
        data = json.loads(request.body)
        
        # User info is available from middleware
        user = request.user_info
        remaining = request.remaining_conversations
        
        # Your chat processing logic
        chat_response = process_chat(data)
        
        # Log conversation
        from middleware.auth_middleware import UserManagerClient
        user_manager = UserManagerClient()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            user_manager.log_conversation(
                user["key"],
                data.get("model", "gpt-3.5-turbo"),
                data.get("messages", [])
            )
        )
        loop.close()
        
        return JsonResponse({
            'response': chat_response,
            'user': user["username"],
            'remaining_conversations': remaining - 1
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def process_chat(data):
    # Your chat processing logic
    return {"message": "Hello from Django!"}
```

### Django Settings

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'middleware.auth_middleware.UserAuthMiddleware',  # Add your middleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ... other middleware
]

# Add user management configuration
USER_MANAGEMENT_DB = os.path.join(BASE_DIR, 'user_management.db')
```

## 🔧 Standalone Client Usage

### Python Client

```python
# user_management_client.py
import aiosqlite
import json
import asyncio
from typing import Optional, Dict, Any

class UserManagementClient:
    def __init__(self, db_path: str = "user_management.db"):
        self.db_path = db_path
        self.connection = None
    
    async def connect(self):
        """Connect to the user management database"""
        self.connection = await aiosqlite.connect(self.db_path)
    
    async def disconnect(self):
        """Disconnect from the database"""
        if self.connection:
            await self.connection.close()
    
    async def verify_api_key(self, api_key: str) -> Dict[str, Any]:
        """Verify API key and return user info"""
        if not self.connection:
            await self.connect()
        
        cursor = await self.connection.execute(
            "SELECT * FROM users WHERE key = ? AND is_active = 1",
            (api_key,)
        )
        row = await cursor.fetchone()
        
        if not row:
            raise ValueError("Invalid API key")
        
        columns = [description[0] for description in cursor.description]
        user = dict(zip(columns, row))
        
        # Check conversation limits
        limits = json.loads(user['limits'])
        if limits.get('conversation_limit', 0) <= 0:
            raise ValueError("Conversation limit exceeded")
        
        return user
    
    async def deduct_conversation(self, api_key: str) -> bool:
        """Deduct one conversation from user's limit"""
        user = await self.verify_api_key(api_key)
        limits = json.loads(user['limits'])
        
        if limits.get('conversation_limit', 0) <= 0:
            return False
        
        limits['conversation_limit'] -= 1
        
        await self.connection.execute(
            "UPDATE users SET limits = ? WHERE key = ?",
            (json.dumps(limits), api_key)
        )
        await self.connection.commit()
        
        return True
    
    async def log_message(self, user: Dict[str, Any], model: str, 
                         messages: list, research_model: bool = False) -> int:
        """Log a conversation message"""
        cursor = await self.connection.execute(
            """INSERT INTO message_logs (username, email, model, messages, research_model)
               VALUES (?, ?, ?, ?, ?)""",
            (user['username'], user['email'], model, 
             json.dumps(messages), research_model)
        )
        await self.connection.commit()
        return cursor.lastrowid

# Usage example
async def main():
    client = UserManagementClient()
    
    try:
        # Verify API key
        user = await client.verify_api_key("pe-your-api-key-here")
        print(f"User: {user['username']}")
        
        # Deduct conversation
        success = await client.deduct_conversation("pe-your-api-key-here")
        print(f"Deduction successful: {success}")
        
        # Log message
        await client.log_message(
            user,
            "gpt-3.5-turbo",
            [{"role": "user", "content": "Hello"}]
        )
        
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### HTTP Client (Any Language)

```bash
# Example using curl

# 1. Verify API key
curl -X POST "http://localhost:8000/api/v1/auth/verify-key" \
  -H "Authorization: Bearer pe-your-api-key-here" \
  -H "Content-Type: application/json"

# Response: {"valid": true, "username": "user", "remaining_conversations": 9}

# 2. Log a message
curl -X POST "http://localhost:8000/api/v1/auth/log-message" \
  -H "Authorization: Bearer pe-your-api-key-here" \
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

## ⚡ Performance Optimization

### Connection Pooling

```python
# For high-performance applications
import asyncio
import aiosqlite
from contextlib import asynccontextmanager

class PooledUserManager:
    def __init__(self, db_path: str, pool_size: int = 10):
        self.db_path = db_path
        self.pool_size = pool_size
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.initialized = False
    
    async def initialize(self):
        """Initialize connection pool"""
        for _ in range(self.pool_size):
            conn = await aiosqlite.connect(self.db_path)
            await self.pool.put(conn)
        self.initialized = True
    
    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool"""
        if not self.initialized:
            await self.initialize()
        
        conn = await self.pool.get()
        try:
            yield conn
        finally:
            await self.pool.put(conn)
    
    async def verify_api_key(self, api_key: str):
        """Verify API key using pooled connection"""
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM users WHERE key = ? AND is_active = 1",
                (api_key,)
            )
            # ... rest of verification logic
```

### Caching

```python
# Add caching for frequently accessed data
import asyncio
from datetime import datetime, timedelta

class CachedUserManager:
    def __init__(self, db_path: str, cache_ttl: int = 300):  # 5 minutes
        self.db_path = db_path
        self.cache_ttl = cache_ttl
        self.user_cache = {}
        self.cache_timestamps = {}
    
    async def verify_api_key_cached(self, api_key: str):
        """Verify API key with caching"""
        now = datetime.now()
        
        # Check cache
        if (api_key in self.user_cache and 
            api_key in self.cache_timestamps and
            now - self.cache_timestamps[api_key] < timedelta(seconds=self.cache_ttl)):
            return self.user_cache[api_key]
        
        # Fetch from database
        user = await self.verify_api_key(api_key)
        
        # Cache the result
        self.user_cache[api_key] = user
        self.cache_timestamps[api_key] = now
        
        return user
    
    def clear_cache(self):
        """Clear expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, timestamp in self.cache_timestamps.items()
            if now - timestamp >= timedelta(seconds=self.cache_ttl)
        ]
        
        for key in expired_keys:
            self.user_cache.pop(key, None)
            self.cache_timestamps.pop(key, None)
```

## 🚨 Error Handling

### Comprehensive Error Handling

```python
# error_handler.py
import logging
from enum import Enum

class AuthErrorType(Enum):
    INVALID_API_KEY = "invalid_api_key"
    LIMIT_EXCEEDED = "limit_exceeded"
    IP_NOT_WHITELISTED = "ip_not_whitelisted"
    DATABASE_ERROR = "database_error"
    NETWORK_ERROR = "network_error"

class AuthenticationError(Exception):
    def __init__(self, error_type: AuthErrorType, message: str, details: dict = None):
        self.error_type = error_type
        self.message = message
        self.details = details or {}
        super().__init__(message)

class RobustUserManager:
    def __init__(self, db_path: str, retry_count: int = 3):
        self.db_path = db_path
        self.retry_count = retry_count
        self.logger = logging.getLogger(__name__)
    
    async def verify_api_key_robust(self, api_key: str, client_ip: str = None):
        """Verify API key with robust error handling"""
        for attempt in range(self.retry_count):
            try:
                return await self._verify_api_key_internal(api_key, client_ip)
                
            except aiosqlite.Error as e:
                self.logger.error(f"Database error (attempt {attempt + 1}): {str(e)}")
                if attempt == self.retry_count - 1:
                    raise AuthenticationError(
                        AuthErrorType.DATABASE_ERROR,
                        "Database connection failed",
                        {"original_error": str(e)}
                    )
                await asyncio.sleep(0.1 * (attempt + 1))  # Exponential backoff
                
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                raise AuthenticationError(
                    AuthErrorType.NETWORK_ERROR,
                    "Authentication service unavailable",
                    {"original_error": str(e)}
                )
    
    async def _verify_api_key_internal(self, api_key: str, client_ip: str = None):
        """Internal verification logic"""
        # ... implementation
        pass

# Usage in FastAPI
from fastapi import HTTPException

async def handle_auth_error(error: AuthenticationError):
    """Convert authentication errors to HTTP responses"""
    status_codes = {
        AuthErrorType.INVALID_API_KEY: 401,
        AuthErrorType.LIMIT_EXCEEDED: 429,
        AuthErrorType.IP_NOT_WHITELISTED: 403,
        AuthErrorType.DATABASE_ERROR: 503,
        AuthErrorType.NETWORK_ERROR: 503,
    }
    
    status_code = status_codes.get(error.error_type, 500)
    
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": error.error_type.value,
            "message": error.message,
            "details": error.details
        }
    )
```

## 📚 Best Practices

### 1. Security Best Practices

```python
# Secure integration practices
import secrets
import hashlib
import hmac

class SecureIntegration:
    def __init__(self, webhook_secret: str = None):
        self.webhook_secret = webhook_secret or secrets.token_hex(32)
    
    def validate_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Validate webhook signatures for secure communication"""
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def rate_limit_by_user(self, user_id: str, window: int = 60, limit: int = 10) -> bool:
        """Implement user-specific rate limiting"""
        # Implementation depends on your caching layer (Redis, etc.)
        pass
```

### 2. Monitoring and Logging

```python
# monitoring.py
import time
import logging
from functools import wraps

def monitor_performance(func):
    """Decorator to monitor function performance"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            logging.info(f"{func.__name__} completed in {duration:.3f}s")
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            logging.error(f"{func.__name__} failed after {duration:.3f}s: {str(e)}")
            raise
    
    return wrapper

# Usage
@monitor_performance
async def verify_user_with_monitoring(api_key: str):
    # Your verification logic
    pass
```

### 3. Configuration Management

```python
# config.py
import os
from dataclasses import dataclass

@dataclass
class IntegrationConfig:
    user_management_db: str = "user_management.db"
    cache_ttl: int = 300
    pool_size: int = 10
    retry_count: int = 3
    rate_limit_window: int = 60
    rate_limit_count: int = 100
    enable_monitoring: bool = True
    webhook_secret: str = None
    
    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        return cls(
            user_management_db=os.getenv("USER_MANAGEMENT_DB", "user_management.db"),
            cache_ttl=int(os.getenv("CACHE_TTL", "300")),
            pool_size=int(os.getenv("POOL_SIZE", "10")),
            retry_count=int(os.getenv("RETRY_COUNT", "3")),
            rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "60")),
            rate_limit_count=int(os.getenv("RATE_LIMIT_COUNT", "100")),
            enable_monitoring=os.getenv("ENABLE_MONITORING", "true").lower() == "true",
            webhook_secret=os.getenv("WEBHOOK_SECRET")
        )
```

This integration guide provides comprehensive examples for integrating the User Management API with various frameworks and languages. Choose the approach that best fits your architecture and requirements.