#!/bin/bash
# ============================================================================
# SNODE Database Setup Script
# ============================================================================
# This script sets up PostgreSQL with pgvector and Redis for production
# memory architecture (adapted from firestarter).
#
# Requirements:
# - PostgreSQL 14+
# - Redis
# - pgvector extension
#
# Usage:
#   chmod +x scripts/setup_database.sh
#   ./scripts/setup_database.sh
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SNODE Database Setup${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"

# Load environment variables
if [ -f .env ]; then
    source .env
    echo -e "${GREEN}✓${NC} Loaded .env file"
else
    echo -e "${YELLOW}!${NC} No .env file found, using defaults"
fi

# Default values
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DATABASE=${POSTGRES_DATABASE:-snode_db}
POSTGRES_USER=${POSTGRES_USER:-snode}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-snode_password}

REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}

# ============================================================================
# Check PostgreSQL
# ============================================================================
echo ""
echo -e "${YELLOW}Checking PostgreSQL...${NC}"

if command -v psql &> /dev/null; then
    echo -e "${GREEN}✓${NC} PostgreSQL client found"
else
    echo -e "${RED}✗${NC} PostgreSQL client not found. Install with:"
    echo "    Ubuntu/Debian: sudo apt install postgresql postgresql-contrib"
    echo "    macOS: brew install postgresql"
    exit 1
fi

# Check if PostgreSQL is running
if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" &> /dev/null; then
    echo -e "${GREEN}✓${NC} PostgreSQL is running on $POSTGRES_HOST:$POSTGRES_PORT"
else
    echo -e "${RED}✗${NC} PostgreSQL is not running. Start with:"
    echo "    sudo systemctl start postgresql"
    exit 1
fi

# ============================================================================
# Check Redis
# ============================================================================
echo ""
echo -e "${YELLOW}Checking Redis...${NC}"

if command -v redis-cli &> /dev/null; then
    echo -e "${GREEN}✓${NC} Redis client found"
else
    echo -e "${RED}✗${NC} Redis client not found. Install with:"
    echo "    Ubuntu/Debian: sudo apt install redis-server"
    echo "    macOS: brew install redis"
    exit 1
fi

# Check if Redis is running
if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping &> /dev/null; then
    echo -e "${GREEN}✓${NC} Redis is running on $REDIS_HOST:$REDIS_PORT"
else
    echo -e "${RED}✗${NC} Redis is not running. Start with:"
    echo "    sudo systemctl start redis"
    exit 1
fi

# ============================================================================
# Setup PostgreSQL Database
# ============================================================================
echo ""
echo -e "${YELLOW}Setting up PostgreSQL database...${NC}"

# Create user and database (requires superuser)
echo "Creating database and user..."

# Create user with password (login as postgres, then set password)
sudo -u postgres psql << EOF
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_USER') THEN
        CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';
    ELSE
        ALTER USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';
    END IF;
END
\$\$;

-- Create database if not exists  
SELECT 'CREATE DATABASE $POSTGRES_DATABASE OWNER $POSTGRES_USER'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DATABASE')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DATABASE TO $POSTGRES_USER;
EOF

echo -e "${GREEN}✓${NC} Database $POSTGRES_DATABASE and user $POSTGRES_USER created"

# ============================================================================
# Install pgvector extension
# ============================================================================
echo ""
echo -e "${YELLOW}Installing pgvector extension...${NC}"

# Check if pgvector is installed
if sudo -u postgres psql -d "$POSTGRES_DATABASE" -c "SELECT 1 FROM pg_extension WHERE extname = 'vector';" | grep -q 1; then
    echo -e "${GREEN}✓${NC} pgvector extension already installed"
else
    # Try to create extension
    sudo -u postgres psql -d "$POSTGRES_DATABASE" -c "CREATE EXTENSION IF NOT EXISTS vector;" 2>/dev/null || {
        echo -e "${RED}✗${NC} Failed to install pgvector. Install it first:"
        echo "    Ubuntu: sudo apt install postgresql-16-pgvector"
        echo "    Or build from source: https://github.com/pgvector/pgvector"
        exit 1
    }
    echo -e "${GREEN}✓${NC} pgvector extension installed"
fi

# ============================================================================
# Run Schema Migration
# ============================================================================
echo ""
echo -e "${YELLOW}Running schema migration...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="$SCRIPT_DIR/../app/database/schema.sql"

if [ -f "$SCHEMA_FILE" ]; then
    PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -f "$SCHEMA_FILE"
    echo -e "${GREEN}✓${NC} Schema migration complete"
else
    echo -e "${RED}✗${NC} Schema file not found: $SCHEMA_FILE"
    exit 1
fi

# ============================================================================
# Verify Installation
# ============================================================================
echo ""
echo -e "${YELLOW}Verifying installation...${NC}"

# Check tables
TABLES=$(PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
echo -e "${GREEN}✓${NC} Created $TABLES tables"

# Check pgvector
PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "SELECT '[1,2,3]'::vector;" &>/dev/null
echo -e "${GREEN}✓${NC} pgvector working correctly"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Database configuration:"
echo "  Host:     $POSTGRES_HOST"
echo "  Port:     $POSTGRES_PORT"
echo "  Database: $POSTGRES_DATABASE"
echo "  User:     $POSTGRES_USER"
echo ""
echo "Redis configuration:"
echo "  Host:     $REDIS_HOST"
echo "  Port:     $REDIS_PORT"
echo ""
echo "Add the following to your .env file:"
echo ""
echo "POSTGRES_HOST=$POSTGRES_HOST"
echo "POSTGRES_PORT=$POSTGRES_PORT"
echo "POSTGRES_DATABASE=$POSTGRES_DATABASE"
echo "POSTGRES_USER=$POSTGRES_USER"
echo "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
echo ""
echo "REDIS_HOST=$REDIS_HOST"
echo "REDIS_PORT=$REDIS_PORT"
echo ""
