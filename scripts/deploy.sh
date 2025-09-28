#!/bin/bash

# User Management API Deployment Script
# This script handles production deployment with Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
SSL_DIR="ssl"

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

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        print_warning ".env file not found. Creating from template..."
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_warning "Please edit .env file with your configuration before proceeding."
            exit 1
        else
            print_error ".env.example file not found. Cannot create .env file."
            exit 1
        fi
    fi
    
    print_success "Prerequisites check passed!"
}

check_ssl_certificates() {
    print_status "Checking SSL certificates..."
    
    mkdir -p "$SSL_DIR"
    
    if [ ! -f "$SSL_DIR/cert.pem" ] || [ ! -f "$SSL_DIR/key.pem" ]; then
        print_warning "SSL certificates not found. Generating self-signed certificates for development..."
        
        # Generate self-signed certificate
        openssl req -x509 -newkey rsa:4096 -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
            -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        print_warning "Self-signed certificates generated. Replace with proper certificates for production!"
    else
        print_success "SSL certificates found!"
    fi
}

build_and_deploy() {
    print_status "Building and deploying application..."
    
    # Pull latest images
    docker-compose -f "$DOCKER_COMPOSE_FILE" pull
    
    # Build application image
    docker-compose -f "$DOCKER_COMPOSE_FILE" build --no-cache
    
    # Start services
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    
    print_success "Application deployed successfully!"
}

check_health() {
    print_status "Checking application health..."
    
    # Wait for application to start
    sleep 30
    
    # Check if services are running
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps | grep -q "Up"; then
        print_success "Services are running!"
        
        # Check application health endpoint
        if curl -f http://localhost/health &> /dev/null; then
            print_success "Application health check passed!"
        else
            print_warning "Application health check failed. Check logs with: docker-compose logs"
        fi
    else
        print_error "Some services failed to start. Check logs with: docker-compose logs"
        exit 1
    fi
}

show_info() {
    print_status "Deployment Information:"
    echo "=========================="
    echo "Application URL: https://localhost"
    echo "API Documentation: https://localhost/docs"
    echo "Health Check: https://localhost/health"
    echo ""
    echo "Admin Credentials:"
    echo "Username: $(grep ADMIN_USERNAME .env | cut -d'=' -f2)"
    echo "Password: $(grep ADMIN_PASSWORD .env | cut -d'=' -f2)"
    echo ""
    echo "Useful Commands:"
    echo "- View logs: docker-compose logs -f"
    echo "- Stop services: docker-compose down"
    echo "- Restart services: docker-compose restart"
    echo "- Update application: ./scripts/deploy.sh"
}

# Main deployment flow
main() {
    echo "========================================"
    echo "  User Management API Deployment       "
    echo "========================================"
    
    check_prerequisites
    check_ssl_certificates
    build_and_deploy
    check_health
    show_info
    
    print_success "Deployment completed successfully!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        print_status "Stopping services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" down
        print_success "Services stopped!"
        ;;
    "restart")
        print_status "Restarting services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" restart
        print_success "Services restarted!"
        ;;
    "logs")
        docker-compose -f "$DOCKER_COMPOSE_FILE" logs -f
        ;;
    "health")
        check_health
        ;;
    *)
        echo "Usage: $0 {deploy|stop|restart|logs|health}"
        echo "  deploy  - Deploy the application (default)"
        echo "  stop    - Stop all services"
        echo "  restart - Restart all services"
        echo "  logs    - Show and follow logs"
        echo "  health  - Check application health"
        exit 1
        ;;
esac