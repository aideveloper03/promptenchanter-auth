#!/bin/bash

# User Management API - Quick Start Script
# This script helps you get the API running quickly

set -e

echo "🚀 User Management API - Quick Start"
echo "===================================="

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.8 or higher is required. Found: $python_version"
    echo "Please install Python 3.8+ and try again."
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
    
    # Generate secure keys
    echo "🔐 Generating secure keys..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    
    # Update .env file
    sed -i "s/your-super-secret-key-here-change-this-in-production/$SECRET_KEY/g" .env
    sed -i "s/your-encryption-key-here-32-bytes/$ENCRYPTION_KEY/g" .env
    
    echo "✅ Environment configuration created with secure keys"
else
    echo "✅ Environment configuration already exists"
fi

# Run basic tests
echo "🧪 Running basic tests..."
if python3 test_basic.py; then
    echo "✅ Basic tests passed"
else
    echo "❌ Basic tests failed. Please check the error messages above."
    exit 1
fi

# Check if port 8000 is available
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️ Warning: Port 8000 is already in use"
    echo "You may need to stop the existing service or use a different port"
    echo "To use a different port, run: uvicorn main:app --port 8001"
else
    echo "✅ Port 8000 is available"
fi

echo ""
echo "🎉 Setup Complete! Your User Management API is ready to run."
echo ""
echo "📋 Next steps:"
echo "1. Review and customize .env file if needed:"
echo "   nano .env"
echo ""
echo "2. Start the API server:"
echo "   python main.py"
echo "   # OR"
echo "   uvicorn main:app --reload"
echo ""
echo "3. Access the API:"
echo "   🌐 API Documentation: http://localhost:8000/docs"
echo "   🏥 Health Check: http://localhost:8000/health"
echo "   📊 API Info: http://localhost:8000/api/v1/info"
echo ""
echo "4. Default admin credentials:"
echo "   👤 Username: admin"
echo "   🔑 Password: admin123!"
echo "   🚨 CHANGE THIS PASSWORD IN PRODUCTION!"
echo ""
echo "5. Test the API endpoints:"
echo "   python test_api.py"
echo ""
echo "📚 Documentation:"
echo "   📖 README: ./README.md"
echo "   🔧 Setup Guide: ./docs/SETUP_GUIDE.md"
echo "   🔗 Integration Guide: ./docs/INTEGRATION_GUIDE.md"
echo "   📡 API Reference: ./docs/API_REFERENCE.md"
echo "   🚀 Deployment Guide: ./docs/DEPLOYMENT_GUIDE.md"
echo ""
echo "🔒 Security reminders:"
echo "   • Change SECRET_KEY and ENCRYPTION_KEY in production"
echo "   • Use a strong admin password"
echo "   • Enable IP whitelisting for production (ENABLE_IP_WHITELIST=true)"
echo "   • Set up SSL/TLS encryption"
echo "   • Review firewall settings"
echo ""
echo "🆘 Need help?"
echo "   • Check the troubleshooting section in docs/SETUP_GUIDE.md"
echo "   • Review error logs for debugging"
echo "   • Ensure all requirements are properly installed"
echo ""
echo "Happy coding! 🎯"