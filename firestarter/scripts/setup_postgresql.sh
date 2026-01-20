#!/bin/bash
# Script to setup PostgreSQL database and user for Chroma Server

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)
fi

# Default values
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DATABASE=${POSTGRES_DATABASE:-firestarter_pg}
POSTGRES_USER=${POSTGRES_USER:-firestarter_ad}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-""}

echo "🔧 Setting up PostgreSQL for Chroma Server..."
echo "   Host: $POSTGRES_HOST"
echo "   Port: $POSTGRES_PORT"
echo "   Database: $POSTGRES_DATABASE"
echo "   User: $POSTGRES_USER"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "❌ Error: psql command not found"
    echo "   Please install PostgreSQL client tools"
    echo "   Ubuntu/Debian: sudo apt install postgresql-client"
    echo "   CentOS/RHEL: sudo yum install postgresql"
    exit 1
fi

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL connection..."
if ! PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U postgres -d postgres -c "SELECT 1;" &> /dev/null; then
    # Try without password (local connection)
    if ! psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U postgres -d postgres -c "SELECT 1;" &> /dev/null 2>&1; then
        echo "❌ Error: Cannot connect to PostgreSQL"
        echo "   Make sure PostgreSQL is running:"
        echo "   Ubuntu/Debian: sudo systemctl status postgresql"
        echo "   CentOS/RHEL: sudo systemctl status postgresql-14"
        echo ""
        echo "   If PostgreSQL is not installed, see docs/POSTGRESQL_SETUP.md"
        exit 1
    fi
    USE_SUDO_USER=true
else
    USE_SUDO_USER=false
fi

echo "✅ PostgreSQL connection successful"
echo ""

# Function to run SQL as postgres user
run_sql_as_postgres() {
    local sql="$1"
    if [ "$USE_SUDO_USER" = "true" ]; then
        sudo -u postgres psql -h $POSTGRES_HOST -p $POSTGRES_PORT -c "$sql"
    else
        PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U postgres -c "$sql"
    fi
}

# Function to run SQL in database
run_sql_in_database() {
    local sql="$1"
    if [ "$USE_SUDO_USER" = "true" ]; then
        sudo -u postgres psql -h $POSTGRES_HOST -p $POSTGRES_PORT -d $POSTGRES_DATABASE -c "$sql"
    else
        PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U postgres -d $POSTGRES_DATABASE -c "$sql"
    fi
}

# Check if user exists
echo "🔍 Checking if user '$POSTGRES_USER' exists..."
USER_EXISTS=$(run_sql_as_postgres "SELECT 1 FROM pg_user WHERE usename='$POSTGRES_USER';" 2>/dev/null | grep -c "1" || echo "0")

if [ "$USER_EXISTS" = "0" ]; then
    echo "   User '$POSTGRES_USER' does not exist. Creating..."
    
    if [ -z "$POSTGRES_PASSWORD" ]; then
        echo "❌ Error: POSTGRES_PASSWORD is not set in .env file"
        echo "   Please set POSTGRES_PASSWORD in your .env file"
        exit 1
    fi
    
    run_sql_as_postgres "CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';"
    echo "✅ User '$POSTGRES_USER' created"
else
    echo "✅ User '$POSTGRES_USER' already exists"
fi

# Check if database exists
echo "🔍 Checking if database '$POSTGRES_DATABASE' exists..."
DB_EXISTS=$(run_sql_as_postgres "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DATABASE';" 2>/dev/null | grep -c "1" || echo "0")

if [ "$DB_EXISTS" = "0" ]; then
    echo "   Database '$POSTGRES_DATABASE' does not exist. Creating..."
    run_sql_as_postgres "CREATE DATABASE $POSTGRES_DATABASE OWNER $POSTGRES_USER;"
    echo "✅ Database '$POSTGRES_DATABASE' created"
else
    echo "✅ Database '$POSTGRES_DATABASE' already exists"
fi

# Grant privileges
echo "🔧 Granting privileges to user '$POSTGRES_USER'..."
run_sql_as_postgres "GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DATABASE TO $POSTGRES_USER;"
echo "✅ Privileges granted"

# Check if pgvector extension is installed
echo "🔍 Checking pgvector extension..."
PGVECTOR_INSTALLED=$(run_sql_in_database "SELECT 1 FROM pg_extension WHERE extname='vector';" 2>/dev/null | grep -c "1" || echo "0")

if [ "$PGVECTOR_INSTALLED" = "0" ]; then
    echo "   pgvector extension not found. Installing..."
    
    # Try to create extension
    if run_sql_in_database "CREATE EXTENSION IF NOT EXISTS vector;" 2>/dev/null; then
        echo "✅ pgvector extension installed"
    else
        echo "⚠️  Warning: Could not install pgvector extension"
        echo "   You may need to install pgvector manually:"
        echo "   See docs/POSTGRESQL_SETUP.md for instructions"
        echo ""
        echo "   After installing pgvector, run:"
        echo "   psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DATABASE -c 'CREATE EXTENSION vector;'"
    fi
else
    echo "✅ pgvector extension already installed"
fi

# Verify connection with new user
echo ""
echo "🔍 Verifying connection with user '$POSTGRES_USER'..."
if PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DATABASE -c "SELECT 1;" &> /dev/null; then
    echo "✅ Connection verified successfully"
    echo ""
    echo "✅ PostgreSQL setup completed!"
    echo ""
    echo "You can now start Chroma Server:"
    echo "  ./scripts/start_chroma_server.sh"
else
    echo "⚠️  Warning: Could not verify connection with new user"
    echo "   Please check your configuration"
    exit 1
fi
