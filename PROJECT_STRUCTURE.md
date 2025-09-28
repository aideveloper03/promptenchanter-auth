# Project Structure - User Management API

This document outlines the complete project structure and explains the purpose of each file and directory.

## 📁 Root Directory Structure

```
user-management-api/
├── 📄 main.py                    # Main FastAPI application entry point
├── 📄 requirements.txt           # Python dependencies
├── 📄 .env.example              # Environment variables template
├── 📄 README.md                 # Main project documentation
├── 📄 PROJECT_STRUCTURE.md      # This file - project structure overview
├── 📄 quick_start.sh            # Quick setup script
├── 📄 test_basic.py             # Basic functionality tests
├── 📄 test_api.py               # API integration tests
├── 📂 app/                      # Main application package
├── 📂 docs/                     # Documentation files
└── 📂 tests/                    # Test files (placeholder)
```

## 📂 Application Structure (/app)

```
app/
├── 📄 __init__.py
├── 📂 api/                      # API route handlers
│   ├── 📄 __init__.py
│   ├── 📄 dependencies.py       # FastAPI dependencies for auth
│   ├── 📄 auth.py              # User authentication endpoints
│   ├── 📄 admin.py             # Admin management endpoints
│   └── 📄 staff.py             # Support staff endpoints
├── 📂 core/                     # Core configuration and utilities
│   ├── 📄 __init__.py
│   └── 📄 config.py            # Application configuration settings
├── 📂 db/                       # Database layer
│   ├── 📄 __init__.py
│   └── 📄 database.py          # Database operations and models
├── 📂 models/                   # Pydantic models for request/response
│   ├── 📄 __init__.py
│   ├── 📄 user.py              # User-related models
│   ├── 📄 admin.py             # Admin and staff models
│   └── 📄 message.py           # Message logging models
├── 📂 security/                 # Security and authentication
│   ├── 📄 __init__.py
│   └── 📄 auth.py              # Password hashing, JWT, encryption
├── 📂 utils/                    # Utility functions and background tasks
│   ├── 📄 __init__.py
│   └── 📄 tasks.py             # Background tasks and scheduling
├── 📂 admin/                    # Admin-specific utilities (placeholder)
│   └── 📄 __init__.py
└── 📂 middleware/               # Middleware for external integration
    ├── 📄 __init__.py
    └── 📄 auth_middleware.py    # Authentication middleware for external APIs
```

## 📂 Documentation (/docs)

```
docs/
├── 📄 SETUP_GUIDE.md           # Complete setup and installation guide
├── 📄 INTEGRATION_GUIDE.md     # Integration with external applications
├── 📄 API_REFERENCE.md         # Complete API endpoint documentation
└── 📄 DEPLOYMENT_GUIDE.md      # Production deployment instructions
```

## 📋 File Descriptions

### Core Application Files

#### `main.py`
- **Purpose**: FastAPI application entry point
- **Contains**: 
  - Application initialization
  - Middleware configuration
  - Route registration
  - Lifespan event handlers
  - Error handlers
- **Key Features**:
  - CORS middleware
  - Rate limiting
  - Health checks
  - API documentation

#### `requirements.txt`
- **Purpose**: Python package dependencies
- **Contains**: All required packages with versions
- **Key Dependencies**:
  - FastAPI for web framework
  - SQLite and aiosqlite for database
  - Cryptography for security
  - APScheduler for background tasks

#### `.env.example`
- **Purpose**: Environment configuration template
- **Contains**: All configurable settings with defaults
- **Security Note**: Copy to `.env` and update with secure values

### Application Modules

#### `app/api/`
Contains all API endpoint handlers:

- **`dependencies.py`**: FastAPI dependency injection for authentication
- **`auth.py`**: User registration, login, profile management
- **`admin.py`**: Administrative functions and user management
- **`staff.py`**: Support staff operations with permission levels

#### `app/core/`
Core application configuration:

- **`config.py`**: Centralized configuration using Pydantic settings

#### `app/db/`
Database layer:

- **`database.py`**: 
  - SQLite database operations
  - Connection management
  - CRUD operations for all entities
  - Batch processing functions

#### `app/models/`
Pydantic models for data validation:

- **`user.py`**: User registration, login, profile models
- **`admin.py`**: Admin and staff-related models
- **`message.py`**: Message logging models

#### `app/security/`
Security and authentication:

- **`auth.py`**: 
  - Password hashing (bcrypt)
  - JWT token creation/validation
  - API key generation
  - Data encryption/decryption
  - Security validation utilities

#### `app/utils/`
Utility functions:

- **`tasks.py`**: 
  - Background task scheduling
  - Daily limit resets
  - Message log batch processing
  - System health monitoring
  - Rate limiting utilities

#### `app/middleware/`
Middleware for external integration:

- **`auth_middleware.py`**: 
  - Standalone authentication middleware
  - Integration utilities for external APIs
  - Connection pooling and caching
  - Error handling

### Documentation Files

#### `README.md`
- **Purpose**: Main project documentation
- **Contains**: 
  - Feature overview
  - Quick installation guide
  - API examples
  - Security configuration
  - Troubleshooting

#### `docs/SETUP_GUIDE.md`
- **Purpose**: Comprehensive setup instructions
- **Contains**: 
  - Development setup
  - Production configuration
  - Docker deployment
  - Monitoring setup
  - Security hardening

#### `docs/INTEGRATION_GUIDE.md`
- **Purpose**: External application integration
- **Contains**: 
  - FastAPI integration
  - Flask/Django integration
  - Node.js integration
  - Middleware usage examples
  - Performance optimization

#### `docs/API_REFERENCE.md`
- **Purpose**: Complete API documentation
- **Contains**: 
  - All endpoint specifications
  - Request/response examples
  - Authentication methods
  - Error codes and handling

#### `docs/DEPLOYMENT_GUIDE.md`
- **Purpose**: Production deployment instructions
- **Contains**: 
  - Cloud platform deployments (AWS, GCP, Azure)
  - Container orchestration (Docker, Kubernetes)
  - Load balancing and scaling
  - Monitoring and logging setup

### Test Files

#### `test_basic.py`
- **Purpose**: Basic functionality verification
- **Tests**: 
  - Security functions
  - Database operations
  - Configuration loading
  - Core business logic

#### `test_api.py`
- **Purpose**: API endpoint integration testing
- **Tests**: 
  - Complete user workflow
  - Admin operations
  - Error handling
  - Rate limiting

#### `quick_start.sh`
- **Purpose**: Automated setup script
- **Features**: 
  - Environment validation
  - Dependency installation
  - Configuration generation
  - Security key generation
  - Basic testing

## 🗄️ Database Schema

### Tables Overview

#### `users`
- **Purpose**: Main user accounts
- **Key Fields**: username, email, password_hash, API key, limits, credits
- **Features**: Soft delete, conversation limits, subscription plans

#### `deleted_users`
- **Purpose**: Backup storage for deleted accounts
- **Key Fields**: Original user data + deletion metadata
- **Features**: Audit trail, data recovery

#### `message_logs`
- **Purpose**: Conversation logging
- **Key Fields**: username, model, messages, timestamp
- **Features**: Batch processing, performance optimization

#### `admins`
- **Purpose**: Administrative accounts
- **Key Fields**: username, password_hash, permissions
- **Features**: Separate from regular users, enhanced security

#### `support_staff`
- **Purpose**: Support staff accounts
- **Key Fields**: name, username, email, staff_level
- **Features**: Multi-level permissions, limited access

## 🔧 Configuration Management

### Environment Variables

The application uses environment variables for configuration:

- **Security**: SECRET_KEY, ENCRYPTION_KEY, password settings
- **Database**: Connection strings, backup settings
- **Features**: IP whitelisting, rate limits, email settings
- **Admin**: Default credentials, permissions
- **Logging**: Batch intervals, memory thresholds

### Configuration Hierarchy

1. **Environment Variables** (highest priority)
2. **`.env` file** (development)
3. **Default values** (lowest priority)

## 🚀 Deployment Patterns

### Development
- Direct Python execution
- SQLite database
- File-based logging
- Debug mode enabled

### Staging
- Docker containers
- Persistent volumes
- External monitoring
- Production-like security

### Production
- Container orchestration (Kubernetes/ECS)
- Load balancers
- Database clusters
- Comprehensive monitoring
- High availability setup

## 🔒 Security Architecture

### Authentication Layers
1. **IP Whitelisting**: Network-level access control
2. **Rate Limiting**: Request frequency control
3. **JWT Tokens**: Session management for users/admin/staff
4. **API Keys**: External service authentication
5. **Conversation Limits**: Usage-based access control

### Data Protection
- **Password Hashing**: bcrypt with configurable rounds
- **Data Encryption**: Fernet encryption for sensitive data
- **Input Sanitization**: XSS and injection prevention
- **Audit Logging**: Comprehensive activity tracking

## 📊 Performance Considerations

### Database Optimization
- **Indexes**: Automatic creation on frequently queried fields
- **Connection Pooling**: Async database connections
- **Batch Processing**: Efficient bulk operations

### Memory Management
- **Monitoring**: Automatic memory usage tracking
- **Thresholds**: Configurable memory limits
- **Cleanup**: Automatic garbage collection

### Scalability
- **Horizontal Scaling**: Stateless application design
- **Load Balancing**: Multiple instance support
- **Caching**: Optional Redis integration
- **Queue Processing**: Background task management

## 🔍 Monitoring & Observability

### Health Checks
- **System Health**: `/health` endpoint
- **Database Status**: Connection and performance
- **Memory Usage**: Real-time monitoring
- **Disk Space**: Storage utilization

### Logging
- **Application Logs**: Structured logging with levels
- **Access Logs**: Request/response tracking
- **Error Logs**: Exception handling and reporting
- **Audit Logs**: Security and administrative actions

### Metrics
- **Performance**: Response times, throughput
- **Usage**: API calls, user activity
- **Errors**: Error rates, types
- **Resources**: CPU, memory, storage

This project structure provides a solid foundation for a scalable, secure, and maintainable user management system that can be easily integrated with other applications and deployed in various environments.