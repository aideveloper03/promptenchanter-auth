#!/bin/bash

# Development Setup Script for User Management API

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is available
check_docker() {
    if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Setup using Docker
setup_docker() {
    print_status "Setting up development environment with Docker..."
    
    # Create .env file for development
    if [ ! -f ".env" ]; then
        print_status "Creating development .env file..."
        cat > .env << EOF
# Development Environment Configuration
SECRET_KEY=dev-secret-key-not-for-production-12345678901234567890
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./data/user_management_dev.db
BCRYPT_ROUNDS=4
ENCRYPTION_KEY=dev-encryption-key-32-bytes-long
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123!
ENABLE_IP_WHITELIST=false
WHITELISTED_IPS=127.0.0.1,localhost
RATE_LIMIT_PER_MINUTE=120
BATCH_LOG_INTERVAL_MINUTES=5
MEMORY_THRESHOLD_MB=50
APP_NAME=User Management API (Dev)
APP_VERSION=1.0.0-dev
DEBUG=true
REDIS_URL=redis://redis-dev:6379/0
EOF
        print_success "Development .env file created!"
    fi
    
    # Start development environment
    print_status "Starting development environment..."
    docker-compose -f docker-compose.dev.yml up -d
    
    # Wait for services to start
    print_status "Waiting for services to start..."
    sleep 15
    
    # Check if services are running
    if docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        print_success "Development environment is running!"
        show_dev_info
    else
        print_error "Failed to start development environment. Check logs with: docker-compose -f docker-compose.dev.yml logs"
    fi
}

# Setup using local Python environment
setup_local() {
    print_status "Setting up local development environment..."
    
    # Check Python version
    if ! python3 --version | grep -q "Python 3\.[8-9]\|Python 3\.1[0-9]"; then
        print_error "Python 3.8+ is required"
        exit 1
    fi
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    print_status "Installing dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Create .env file for local development
    if [ ! -f ".env" ]; then
        print_status "Creating development .env file..."
        cat > .env << EOF
# Local Development Environment Configuration
SECRET_KEY=local-dev-secret-key-not-for-production-123456789012345
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./user_management_dev.db
BCRYPT_ROUNDS=4
ENCRYPTION_KEY=local-dev-encryption-key-32-bytes
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123!
ENABLE_IP_WHITELIST=false
WHITELISTED_IPS=127.0.0.1,localhost
RATE_LIMIT_PER_MINUTE=120
BATCH_LOG_INTERVAL_MINUTES=5
MEMORY_THRESHOLD_MB=50
APP_NAME=User Management API (Local Dev)
APP_VERSION=1.0.0-dev
DEBUG=true
EOF
        print_success "Development .env file created!"
    fi
    
    print_success "Local development environment setup complete!"
    show_local_info
}

show_dev_info() {
    echo ""
    print_status "Development Environment Information:"
    echo "======================================"
    echo "Application URL: http://localhost:8000"
    echo "API Documentation: http://localhost:8000/docs"
    echo "Health Check: http://localhost:8000/health"
    echo "Redis: localhost:6379"
    echo ""
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: admin123!"
    echo ""
    echo "Useful Commands:"
    echo "- View logs: docker-compose -f docker-compose.dev.yml logs -f"
    echo "- Stop: docker-compose -f docker-compose.dev.yml down"
    echo "- Restart: docker-compose -f docker-compose.dev.yml restart"
    echo "- Shell into container: docker-compose -f docker-compose.dev.yml exec user-management-api-dev bash"
}

show_local_info() {
    echo ""
    print_status "Local Development Information:"
    echo "=============================="
    echo "To start the application:"
    echo "1. source venv/bin/activate"
    echo "2. python main.py"
    echo ""
    echo "Application will be available at: http://localhost:8000"
    echo "API Documentation: http://localhost:8000/docs"
    echo ""
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: admin123!"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    if check_docker && docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        # Run tests in Docker
        docker-compose -f docker-compose.dev.yml exec user-management-api-dev python -m pytest -v
    else
        # Run tests locally
        if [ -f "venv/bin/activate" ]; then
            source venv/bin/activate
            PYTHONPATH=/workspace python -m pytest -v
        else
            print_error "Virtual environment not found. Run setup first."
            exit 1
        fi
    fi
}

# Main function
main() {
    echo "=========================================="
    echo "  User Management API - Development Setup"
    echo "=========================================="
    
    case "${1:-auto}" in
        "docker")
            if check_docker; then
                setup_docker
            else
                print_error "Docker/Docker Compose not found. Please install Docker first."
                exit 1
            fi
            ;;
        "local")
            setup_local
            ;;
        "test")
            run_tests
            ;;
        "auto")
            if check_docker; then
                print_status "Docker detected. Setting up with Docker..."
                setup_docker
            else
                print_warning "Docker not found. Setting up local environment..."
                setup_local
            fi
            ;;
        "stop")
            if check_docker; then
                print_status "Stopping development environment..."
                docker-compose -f docker-compose.dev.yml down
                print_success "Development environment stopped!"
            else
                print_warning "Docker not available. To stop local server, use Ctrl+C"
            fi
            ;;
        *)
            echo "Usage: $0 {auto|docker|local|test|stop}"
            echo "  auto   - Automatically choose setup method (default)"
            echo "  docker - Use Docker for development"
            echo "  local  - Use local Python environment"
            echo "  test   - Run tests"
            echo "  stop   - Stop development environment"
            exit 1
            ;;
    esac
}

main "$@"