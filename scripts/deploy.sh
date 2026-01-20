#!/bin/bash
# SNODE Deployment Script
# =======================
# Automated deployment script for SNODE AI Agent
# Supports: Ubuntu/Debian Linux

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_DIR="${1:-/opt/snode}"
VENV_DIR="$PROJECT_DIR/venv"
REPO_URL="${2:-}"  # Git repo URL (optional)
PYTHON_VERSION="3.10"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              SNODE AI Agent Deployment Script                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}⚠️  Running as root. Will create project in $PROJECT_DIR${NC}"
    USER_HOME="/root"
else
    USER_HOME="$HOME"
    echo -e "${CYAN}ℹ️  Running as user: $(whoami)${NC}"
fi

# ============================================================
# STEP 1: Install System Dependencies
# ============================================================
echo -e "${BLUE}[1/8]${NC} Installing system dependencies..."
sudo apt update -qq
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    build-essential \
    postgresql \
    postgresql-contrib \
    libpq-dev \
    > /dev/null 2>&1

# Check Python version
PYTHON_VER=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}✓${NC} Python $PYTHON_VER installed"

# ============================================================
# STEP 2: Setup PostgreSQL
# ============================================================
echo -e "${BLUE}[2/8]${NC} Setting up PostgreSQL..."

# Check if PostgreSQL is running
if sudo systemctl is-active --quiet postgresql; then
    echo -e "${GREEN}✓${NC} PostgreSQL is running"
else
    echo -e "${YELLOW}⚠${NC}  Starting PostgreSQL..."
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
fi

# Create database and user
DB_NAME="snode_memory"
DB_USER="snode"
DB_PASS="snode123"  # Change this in production!

sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" 2>/dev/null || echo -e "${GREEN}✓${NC} User $DB_USER already exists"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || echo -e "${GREEN}✓${NC} Database $DB_NAME already exists"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null || true

echo -e "${GREEN}✓${NC} PostgreSQL configured"

# ============================================================
# STEP 3: Clone/Setup Project
# ============================================================
echo -e "${BLUE}[3/8]${NC} Setting up project directory..."

# Check if current directory is already a git repo
CURRENT_DIR="$(pwd)"
IS_GIT_REPO=false
if [ -d ".git" ]; then
    IS_GIT_REPO=true
    echo -e "${GREEN}✓${NC} Detected git repository in current directory"
fi

if [ -n "$REPO_URL" ]; then
    # Clone from Git (only if PROJECT_DIR is different from current)
    if [ "$CURRENT_DIR" = "$PROJECT_DIR" ]; then
        echo -e "${GREEN}✓${NC} Already in target directory. Skipping clone."
    elif [ -d "$PROJECT_DIR" ]; then
        echo -e "${YELLOW}⚠${NC}  Directory exists. Pulling latest changes..."
        cd "$PROJECT_DIR"
        if [ -d ".git" ]; then
            git pull
        else
            echo -e "${YELLOW}⚠${NC}  Not a git repo. Using existing directory."
        fi
    else
        echo -e "${YELLOW}⚠${NC}  Cloning repository..."
        sudo mkdir -p "$(dirname $PROJECT_DIR)"
        sudo git clone "$REPO_URL" "$PROJECT_DIR"
        sudo chown -R $USER:$USER "$PROJECT_DIR"
    fi
else
    # Use current directory (if already git pulled) or copy to target
    if [ "$CURRENT_DIR" = "$PROJECT_DIR" ]; then
        echo -e "${GREEN}✓${NC} Already in target directory. Using current location."
    elif [ "$IS_GIT_REPO" = true ]; then
        # Current dir is git repo, but target is different
        if [ ! -d "$PROJECT_DIR" ]; then
            echo -e "${YELLOW}⚠${NC}  Copying git repository to $PROJECT_DIR..."
            sudo mkdir -p "$PROJECT_DIR"
            sudo cp -r . "$PROJECT_DIR/"
            sudo chown -R $USER:$USER "$PROJECT_DIR"
        else
            echo -e "${GREEN}✓${NC} Target directory exists. Using it."
        fi
    else
        # Not a git repo, just copy files
        if [ ! -d "$PROJECT_DIR" ]; then
            echo -e "${YELLOW}⚠${NC}  Creating project directory..."
            sudo mkdir -p "$PROJECT_DIR"
            sudo chown -R $USER:$USER "$PROJECT_DIR"
        fi
        
        if [ "$CURRENT_DIR" != "$PROJECT_DIR" ]; then
            echo -e "${YELLOW}⚠${NC}  Copying files to $PROJECT_DIR..."
            sudo cp -r . "$PROJECT_DIR/"
            sudo chown -R $USER:$USER "$PROJECT_DIR"
        fi
    fi
fi

cd "$PROJECT_DIR"
echo -e "${GREEN}✓${NC} Project directory: $PROJECT_DIR"

# ============================================================
# STEP 4: Create Python Virtual Environment
# ============================================================
echo -e "${BLUE}[4/8]${NC} Creating Python virtual environment..."

if [ -d "$VENV_DIR" ]; then
    echo -e "${GREEN}✓${NC} Virtual environment already exists"
else
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}✓${NC} Virtual environment created"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# ============================================================
# STEP 5: Install Python Dependencies
# ============================================================
echo -e "${BLUE}[5/8]${NC} Installing Python dependencies..."

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt > /dev/null 2>&1
    echo -e "${GREEN}✓${NC} Python dependencies installed"
else
    echo -e "${RED}✗${NC} requirements.txt not found!"
    exit 1
fi

# Install additional dependencies
pip install psycopg2-binary python-dotenv > /dev/null 2>&1
echo -e "${GREEN}✓${NC} Additional dependencies installed"

# ============================================================
# STEP 6: Install Security Tools
# ============================================================
echo -e "${BLUE}[6/8]${NC} Installing security tools..."

if [ -f "install_tools.sh" ]; then
    chmod +x install_tools.sh
    bash install_tools.sh
    echo -e "${GREEN}✓${NC} Security tools installation completed"
else
    echo -e "${YELLOW}⚠${NC}  install_tools.sh not found. Skipping tools installation."
fi

# ============================================================
# STEP 7: Setup Environment Variables
# ============================================================
echo -e "${BLUE}[7/8]${NC} Setting up environment variables..."

ENV_FILE="$PROJECT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" << EOF
# SNODE Environment Configuration
# ===============================

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=snode_memory
POSTGRES_USER=snode
POSTGRES_PASSWORD=snode123

# API Keys (Get from respective services)
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
NVD_API_KEY=

# LLM Configuration (Ollama)
OLLAMA_ENDPOINT=http://localhost:11434/api/chat
OLLAMA_MODEL=mistral

# Optional: OpenAI/Anthropic (if using cloud LLM)
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
EOF
    echo -e "${GREEN}✓${NC} Created .env file at $ENV_FILE"
    echo -e "${YELLOW}⚠${NC}  Please edit .env file and add your API keys!"
else
    echo -e "${GREEN}✓${NC} .env file already exists"
fi

# ============================================================
# STEP 8: Initialize Directories and Permissions
# ============================================================
echo -e "${BLUE}[8/8]${NC} Initializing directories..."

# Create necessary directories
mkdir -p "$PROJECT_DIR/data"
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/scan_results"
mkdir -p "$PROJECT_DIR/reports"
mkdir -p "$PROJECT_DIR/discoveries"
mkdir -p "$PROJECT_DIR/workspace"
mkdir -p "$PROJECT_DIR/audit_logs"

# Set permissions
chmod 755 "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR/data"
chmod -R 755 "$PROJECT_DIR/logs"

echo -e "${GREEN}✓${NC} Directories initialized"

# ============================================================
# VERIFICATION
# ============================================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Deployment Summary                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check Python packages
echo -e "${CYAN}Checking Python packages...${NC}"
python3 -c "import langchain; print('✓ langchain')" 2>/dev/null || echo -e "${RED}✗ langchain${NC}"
python3 -c "import langgraph; print('✓ langgraph')" 2>/dev/null || echo -e "${RED}✗ langgraph${NC}"
python3 -c "import chromadb; print('✓ chromadb')" 2>/dev/null || echo -e "${RED}✗ chromadb${NC}"
python3 -c "import psycopg2; print('✓ psycopg2')" 2>/dev/null || echo -e "${RED}✗ psycopg2${NC}"

# Check Ollama
echo ""
echo -e "${CYAN}Checking Ollama...${NC}"
if command -v ollama >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Ollama is installed"
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Ollama is running"
    else
        echo -e "${YELLOW}⚠${NC}  Ollama is installed but not running"
        echo -e "${YELLOW}   Start with: ollama serve${NC}"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Ollama not found. Install from: https://ollama.ai${NC}"
fi

# Check PostgreSQL
echo ""
echo -e "${CYAN}Checking PostgreSQL...${NC}"
if sudo systemctl is-active --quiet postgresql; then
    echo -e "${GREEN}✓${NC} PostgreSQL is running"
else
    echo -e "${RED}✗${NC} PostgreSQL is not running"
fi

echo ""
echo -e "${GREEN}✅ Deployment completed!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Edit .env file: ${CYAN}nano $ENV_FILE${NC}"
echo -e "  2. Add your API keys (Shodan, SecurityTrails, etc.)"
echo -e "  3. Install Ollama if not installed: ${CYAN}curl -fsSL https://ollama.ai/install.sh | sh${NC}"
echo -e "  4. Pull LLM model: ${CYAN}ollama pull mistral${NC}"
echo -e "  5. Activate venv and run: ${CYAN}source $VENV_DIR/bin/activate && python3 -m app.cli.main${NC}"
echo ""
