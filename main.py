"""
User Management Backend API
A comprehensive user management system with authentication, API key management,
conversation limits, and admin/staff controls.
"""

import uvicorn
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.db.mongodb_database import mongodb_database
from app.cache.redis_manager import redis_manager
from app.security.auth import get_password_hash
from app.api import auth, admin, staff, email_verification
from app.utils.tasks import start_scheduler, stop_scheduler, health_check, rate_limiter
from app.middleware.performance_middleware import PerformanceMiddleware

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("Starting Enhanced User Management API...")
    
    # Initialize Redis cache
    await redis_manager.connect()
    redis_status = "enabled" if redis_manager.is_available() else "disabled (fallback to memory)"
    print(f"Redis cache: {redis_status}")
    
    # Initialize MongoDB database
    await mongodb_database.connect()
    
    # Create default admin if it doesn't exist
    try:
        admin_exists = await mongodb_database.get_admin_by_username(settings.ADMIN_USERNAME)
        if not admin_exists:
            admin_password_hash = get_password_hash(settings.ADMIN_PASSWORD)
            await mongodb_database.create_admin(settings.ADMIN_USERNAME, admin_password_hash)
            print(f"Created default admin user: {settings.ADMIN_USERNAME}")
    except Exception as e:
        print(f"Warning: Could not create default admin: {str(e)}")
    
    # Start background scheduler
    start_scheduler()
    
    print("Enhanced User Management API started successfully!")
    print(f"Admin username: {settings.ADMIN_USERNAME}")
    print(f"IP Whitelisting: {'Enabled' if settings.ENABLE_IP_WHITELIST else 'Disabled'}")
    print(f"Performance optimizations: Enabled")
    print(f"Database connection pooling: Enabled")
    
    yield
    
    # Shutdown
    print("Shutting down Enhanced User Management API...")
    stop_scheduler()
    await mongodb_database.disconnect()
    await redis_manager.disconnect()
    print("Enhanced User Management API shutdown complete.")

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
    A comprehensive user management backend with:
    - User registration and authentication
    - API key management with conversation limits
    - Admin and support staff controls
    - Message logging and rate limiting
    - IP whitelisting and security features
    
    ## Authentication
    
    ### User Authentication
    Use JWT tokens obtained from `/auth/login` endpoint.
    
    ### API Key Authentication  
    Use API keys in Authorization header: `Bearer pe-your-api-key-here`
    
    ### Admin Authentication
    Use JWT tokens obtained from `/admin/login` endpoint.
    
    ### Staff Authentication
    Use JWT tokens obtained from `/staff/login` endpoint.
    
    ## Rate Limiting
    
    - Default: 60 requests per minute per IP
    - API key endpoints have conversation limits
    - Limits reset every 24 hours
    
    ## Security Features
    
    - Password hashing with bcrypt
    - Data encryption for sensitive information
    - IP whitelisting (configurable)
    - Input sanitization and validation
    - Rate limiting and abuse prevention
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Add security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"]
    )

# Add performance middleware
app.add_middleware(
    PerformanceMiddleware,
    enable_caching=True,
    enable_rate_limiting=True
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Custom rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Custom rate limiting middleware"""
    client_ip = request.client.host
    
    # Skip rate limiting for health check
    if request.url.path == "/health":
        response = await call_next(request)
        return response
    
    # Check rate limit
    is_allowed = await rate_limiter.is_allowed(
        client_ip, 
        settings.RATE_LIMIT_PER_MINUTE, 
        60
    )
    
    if not is_allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded. Please try again later.",
                "limit": settings.RATE_LIMIT_PER_MINUTE,
                "window": "60 seconds"
            }
        )
    
    response = await call_next(request)
    return response

# Include API routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(staff.router, prefix="/api/v1")
app.include_router(email_verification.router, prefix="/api/v1")

# Enhanced health check endpoint
@app.get("/health", tags=["Health"])
async def get_health():
    """Get comprehensive system health status"""
    base_health = await health_check()
    
    # Add Redis health
    redis_health = await redis_manager.health_check()
    
    # Add database health
    try:
        await mongodb_database.client.admin.command('ping')
        db_health = "healthy"
    except Exception as e:
        db_health = f"error: {str(e)}"
    
    # Add performance metrics
    from app.middleware.performance_middleware import connection_manager
    perf_stats = connection_manager.get_stats()
    
    return {
        **base_health,
        "database_enhanced": db_health,
        "redis": redis_health,
        "performance": {
            "active_operations": perf_stats['active_operations'],
            "available_connection_slots": perf_stats['available_slots']
        }
    }

# Root endpoint
@app.get("/", tags=["Root"])
@limiter.limit("10/minute")
async def root(request: Request):
    """API information"""
    return {
        "message": "User Management API",
        "version": settings.APP_VERSION,
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

# API Information endpoint
@app.get("/api/v1/info", tags=["Information"])
@limiter.limit("30/minute")
async def api_info(request: Request):
    """Get API information and endpoints"""
    return {
        "api_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "authentication": {
                "register": "POST /api/v1/auth/register",
                "login": "POST /api/v1/auth/login",
                "profile": "GET /api/v1/auth/profile",
                "api_key": "GET /api/v1/auth/api-key",
                "regenerate_key": "POST /api/v1/auth/regenerate-key",
                "update_profile": "PUT /api/v1/auth/profile",
                "reset_password": "PUT /api/v1/auth/password",
                "delete_account": "DELETE /api/v1/auth/account",
                "verify_key": "POST /api/v1/auth/verify-key",
                "log_message": "POST /api/v1/auth/log-message"
            },
            "admin": {
                "login": "POST /api/v1/admin/login",
                "get_users": "GET /api/v1/admin/users",
                "get_user": "GET /api/v1/admin/users/{username}",
                "update_user": "PUT /api/v1/admin/users/{username}",
                "delete_user": "DELETE /api/v1/admin/users/{username}",
                "regenerate_user_key": "POST /api/v1/admin/users/{username}/regenerate-key",
                "create_staff": "POST /api/v1/admin/staff",
                "reset_limits": "POST /api/v1/admin/reset-limits"
            },
            "staff": {
                "login": "POST /api/v1/staff/login",
                "get_users": "GET /api/v1/staff/users",
                "get_user": "GET /api/v1/staff/users/{username}",
                "update_user": "PUT /api/v1/staff/users/{username}",
                "delete_user": "DELETE /api/v1/staff/users/{username}",
                "profile": "GET /api/v1/staff/profile"
            }
        },
        "authentication_methods": {
            "jwt_token": "Bearer token for user/admin/staff authentication",
            "api_key": "Bearer pe-xxx for API access with conversation limits"
        },
        "rate_limits": {
            "default": f"{settings.RATE_LIMIT_PER_MINUTE} requests per minute",
            "conversation_limits": "Per-user limits that reset daily"
        }
    }

# API Statistics endpoint (admin only)
@app.get("/api/v1/stats", tags=["Statistics"])
async def get_api_statistics():
    """Get API usage statistics (requires admin token)"""
    stats = await mongodb_database.get_usage_stats(days=7)
    return {
        "usage_statistics": stats,
        "cache_status": redis_manager.is_available(),
        "performance_mode": "enhanced"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "detail": exc.detail,
            "status_code": exc.status_code,
            "timestamp": str(asyncio.get_event_loop().time())
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    if settings.DEBUG:
        detail = str(exc)
    else:
        detail = "Internal server error"
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "detail": detail,
            "status_code": 500,
            "timestamp": str(asyncio.get_event_loop().time())
        }
    )

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )