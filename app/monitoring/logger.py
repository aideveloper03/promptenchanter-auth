import logging
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler
import sys
import os
from ..core.config import settings

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        if hasattr(record, 'endpoint'):
            log_entry['endpoint'] = record.endpoint
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        if hasattr(record, 'response_time'):
            log_entry['response_time'] = record.response_time
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # Create handler if not exists
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                'logs/security.log',
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)
    
    def log_failed_login(self, email: str, ip_address: str, reason: str):
        """Log failed login attempt"""
        self.logger.warning(
            f"Failed login attempt",
            extra={
                'event_type': 'failed_login',
                'email': email,
                'ip_address': ip_address,
                'reason': reason
            }
        )
    
    def log_successful_login(self, user_id: int, username: str, ip_address: str):
        """Log successful login"""
        self.logger.info(
            f"Successful login",
            extra={
                'event_type': 'successful_login',
                'user_id': user_id,
                'username': username,
                'ip_address': ip_address
            }
        )
    
    def log_api_key_usage(self, user_id: int, endpoint: str, ip_address: str):
        """Log API key usage"""
        self.logger.info(
            f"API key used",
            extra={
                'event_type': 'api_key_usage',
                'user_id': user_id,
                'endpoint': endpoint,
                'ip_address': ip_address
            }
        )
    
    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str):
        """Log rate limit exceeded"""
        self.logger.warning(
            f"Rate limit exceeded",
            extra={
                'event_type': 'rate_limit_exceeded',
                'ip_address': ip_address,
                'endpoint': endpoint
            }
        )
    
    def log_suspicious_activity(self, description: str, **kwargs):
        """Log suspicious activity"""
        self.logger.error(
            f"Suspicious activity: {description}",
            extra={
                'event_type': 'suspicious_activity',
                **kwargs
            }
        )

class PerformanceLogger:
    """Logger for performance metrics"""
    
    def __init__(self):
        self.logger = logging.getLogger('performance')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                'logs/performance.log',
                maxBytes=50*1024*1024,  # 50MB
                backupCount=3
            )
            handler.setFormatter(JSONFormatter())
            self.logger.addHandler(handler)
    
    def log_request(self, method: str, endpoint: str, response_time: float, 
                   status_code: int, user_id: Optional[int] = None):
        """Log request performance"""
        self.logger.info(
            f"{method} {endpoint} - {response_time:.3f}s - {status_code}",
            extra={
                'event_type': 'request_performance',
                'method': method,
                'endpoint': endpoint,
                'response_time': response_time,
                'status_code': status_code,
                'user_id': user_id
            }
        )
    
    def log_slow_query(self, query: str, duration: float, table: str = None):
        """Log slow database queries"""
        self.logger.warning(
            f"Slow query: {duration:.3f}s",
            extra={
                'event_type': 'slow_query',
                'query': query[:200],  # Truncate long queries
                'duration': duration,
                'table': table
            }
        )
    
    def log_cache_stats(self, hit_rate: float, total_requests: int):
        """Log cache performance statistics"""
        self.logger.info(
            f"Cache stats: {hit_rate:.2%} hit rate, {total_requests} requests",
            extra={
                'event_type': 'cache_stats',
                'hit_rate': hit_rate,
                'total_requests': total_requests
            }
        )

def setup_logging():
    """Setup application logging configuration"""
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO if not settings.DEBUG else logging.DEBUG)
    
    # Clear existing handlers
    root_logger.handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler for general application logs
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=20*1024*1024,  # 20MB
        backupCount=5
    )
    
    if settings.DEBUG:
        file_handler.setFormatter(console_format)
    else:
        file_handler.setFormatter(JSONFormatter())
    
    root_logger.addHandler(file_handler)
    
    # Error file handler
    error_handler = RotatingFileHandler(
        'logs/error.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(error_handler)
    
    # Suppress noisy loggers
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('passlib').setLevel(logging.WARNING)
    
    return root_logger

class MetricsCollector:
    """Collect and aggregate application metrics"""
    
    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        self.total_response_time = 0.0
        self.start_time = time.time()
        self.endpoint_stats = {}
    
    def record_request(self, endpoint: str, method: str, response_time: float, 
                      status_code: int):
        """Record request metrics"""
        self.request_count += 1
        self.total_response_time += response_time
        
        if status_code >= 400:
            self.error_count += 1
        
        # Track per-endpoint stats
        key = f"{method} {endpoint}"
        if key not in self.endpoint_stats:
            self.endpoint_stats[key] = {
                'count': 0,
                'total_time': 0.0,
                'errors': 0
            }
        
        self.endpoint_stats[key]['count'] += 1
        self.endpoint_stats[key]['total_time'] += response_time
        if status_code >= 400:
            self.endpoint_stats[key]['errors'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collected metrics"""
        uptime = time.time() - self.start_time
        avg_response_time = (
            self.total_response_time / self.request_count 
            if self.request_count > 0 else 0
        )
        
        # Calculate per-endpoint averages
        endpoint_averages = {}
        for endpoint, stats in self.endpoint_stats.items():
            endpoint_averages[endpoint] = {
                'count': stats['count'],
                'avg_response_time': stats['total_time'] / stats['count'],
                'error_rate': stats['errors'] / stats['count'] if stats['count'] > 0 else 0
            }
        
        return {
            'uptime_seconds': uptime,
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'error_rate': self.error_count / self.request_count if self.request_count > 0 else 0,
            'avg_response_time': avg_response_time,
            'requests_per_second': self.request_count / uptime if uptime > 0 else 0,
            'endpoint_stats': endpoint_averages
        }
    
    def reset_stats(self):
        """Reset all metrics"""
        self.request_count = 0
        self.error_count = 0
        self.total_response_time = 0.0
        self.start_time = time.time()
        self.endpoint_stats = {}

# Global instances
security_logger = SecurityLogger()
performance_logger = PerformanceLogger()
metrics_collector = MetricsCollector()

# Setup logging on import
logger = setup_logging()