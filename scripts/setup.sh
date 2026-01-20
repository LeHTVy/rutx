#!/bin/bash
# Setup script for AI Pentest Agent

set -e

echo "🔧 Setting up AI Pentest Agent..."

# Check Python version
echo "📋 Checking Python version..."
python3 --version || { echo "❌ Python 3 is required but not found"; exit 1; }

# Create virtual environment
echo "📦 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "ℹ️  Virtual environment already exists"
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Install Playwright browsers (if needed)
echo "🌐 Installing Playwright browsers..."
python -m playwright install chromium || echo "⚠️  Playwright installation skipped (optional)"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434

# API Keys (optional - add your keys here)
# SERPAPI_API_KEY=your_serpapi_key_here
# SHODAN_API_KEY=your_shodan_key_here
# VIRUSTOTAL_API_KEY=your_virustotal_key_here
# SECURITYTRAILS_API_KEY=your_securitytrails_key_here

# PostgreSQL Configuration (for conversation management)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DATABASE=firestarter_pg
POSTGRES_USER=firestarter_ad
POSTGRES_PASSWORD=your_password_here

# Redis Configuration (for short-term memory buffer)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Logging
LOG_LEVEL=INFO
EOF
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists"
fi

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/pentest_results
mkdir -p knowledge/data/{cve,exploits,logs,ioc}

# Check PostgreSQL connection and setup (optional)
echo "🔍 Checking PostgreSQL setup..."
if command -v psql &> /dev/null; then
    # Load .env if exists to get PostgreSQL config
    if [ -f .env ]; then
        export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)
    fi
    
    POSTGRES_DATABASE=${POSTGRES_DATABASE:-firestarter_pg}
    POSTGRES_USER=${POSTGRES_USER:-firestarter_ad}
    
    if psql -h ${POSTGRES_HOST:-localhost} -U ${POSTGRES_USER} -d ${POSTGRES_DATABASE} -c "SELECT 1;" &> /dev/null; then
        echo "✅ PostgreSQL connection successful"
    else
        echo "⚠️  PostgreSQL database or user not found."
        echo "   Run setup script to create database and user:"
        echo "   ./scripts/setup_postgresql.sh"
        echo ""
        echo "   Or see docs/POSTGRESQL_SETUP.md for manual setup"
    fi
else
    echo "ℹ️  psql not found. Skipping PostgreSQL check."
    echo "   Install PostgreSQL client: sudo apt install postgresql-client"
fi

# Check Redis connection (optional check)
echo "🔍 Checking Redis connection..."
if command -v redis-cli &> /dev/null; then
    if redis-cli ping &> /dev/null; then
        echo "✅ Redis is running"
    else
        echo "⚠️  Redis is not accessible. Make sure Redis is running."
        echo "   See docs/REDIS_SETUP.md for setup instructions"
        echo "   Or install: sudo apt install redis-server"
    fi
else
    echo "ℹ️  redis-cli not found. Skipping Redis check."
    echo "   Install Redis: sudo apt install redis-server"
    echo "   See docs/REDIS_SETUP.md for setup instructions"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "To run the application:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run: python main.py"
echo ""
echo "Or use the run script: ./run.sh"
