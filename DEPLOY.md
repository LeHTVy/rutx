# 🚀 SNODE Deployment Guide

Hướng dẫn deploy SNODE AI Agent lên server Ubuntu/Debian.

## 📋 Yêu cầu hệ thống

- **OS**: Ubuntu 20.04+ / Debian 11+
- **RAM**: Tối thiểu 4GB (khuyến nghị 8GB+)
- **Disk**: Tối thiểu 20GB free space
- **Python**: 3.10+
- **PostgreSQL**: 12+ (hoặc SQLite cho development)
- **Ollama**: Để chạy LLM local (hoặc dùng cloud LLM)

## 🔧 Cách 1: Deploy tự động (Khuyến nghị)

### Bước 1: Clone repository

```bash
# Clone repo
git clone <your-repo-url> /opt/snode
cd /opt/snode

# Hoặc nếu đã có code local, copy lên server
scp -r /path/to/local/snode user@server:/opt/
```

### Bước 2: Chạy script deploy

```bash
# Make executable
chmod +x deploy.sh

# Deploy (tự động setup tất cả)
sudo bash deploy.sh /opt/snode

# Hoặc với Git repo URL
sudo bash deploy.sh /opt/snode https://github.com/your-repo/snode.git
```

Script sẽ tự động:
- ✅ Cài đặt system dependencies
- ✅ Setup PostgreSQL database
- ✅ Tạo Python virtual environment
- ✅ Cài đặt Python packages
- ✅ Cài đặt security tools
- ✅ Tạo .env file
- ✅ Initialize directories

### Bước 3: Cấu hình

```bash
# Edit .env file
nano /opt/snode/.env
```

Thêm API keys:
```env
SHODAN_API_KEY=your_shodan_key
SECURITYTRAILS_API_KEY=your_securitytrails_key
NVD_API_KEY=your_nvd_key  # Optional
```

### Bước 4: Cài đặt Ollama (nếu chưa có)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull LLM model
ollama pull mistral
# hoặc
ollama pull deepseek-r1:latest
```

### Bước 5: Chạy ứng dụng

```bash
cd /opt/snode
source venv/bin/activate
python3 -m app.cli.main
```

## 🔧 Cách 2: Deploy thủ công

### Bước 1: Cài đặt system dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    git curl wget build-essential postgresql postgresql-contrib \
    libpq-dev
```

### Bước 2: Setup PostgreSQL

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE USER snode WITH PASSWORD 'snode123';
CREATE DATABASE snode_memory OWNER snode;
GRANT ALL PRIVILEGES ON DATABASE snode_memory TO snode;
\q
EOF
```

### Bước 3: Clone/Copy project

```bash
# Option 1: Clone from Git
git clone <your-repo-url> /opt/snode
cd /opt/snode

# Option 2: Copy from local
scp -r /path/to/snode user@server:/opt/
ssh user@server
cd /opt/snode
```

### Bước 4: Setup Python environment

```bash
cd /opt/snode

# Create virtual environment
python3 -m venv venv

# Activate
source venv/bin/activate

# Install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install psycopg2-binary python-dotenv
```

### Bước 5: Cài đặt security tools

```bash
chmod +x install_tools.sh
bash install_tools.sh
```

### Bước 6: Cấu hình environment

```bash
# Create .env file
cat > .env << EOF
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=snode_memory
POSTGRES_USER=snode
POSTGRES_PASSWORD=snode123

SHODAN_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
NVD_API_KEY=your_key_here

OLLAMA_ENDPOINT=http://localhost:11434/api/chat
OLLAMA_MODEL=mistral
EOF
```

### Bước 7: Initialize directories

```bash
mkdir -p data logs scan_results reports discoveries workspace audit_logs
chmod -R 755 data logs
```

### Bước 8: Chạy ứng dụng

```bash
source venv/bin/activate
python3 -m app.cli.main
```

## 🔄 Cách 3: Deploy với Systemd Service (Production)

Tạo systemd service để chạy SNODE như daemon:

### Tạo service file

```bash
sudo nano /etc/systemd/system/snode.service
```

Nội dung:

```ini
[Unit]
Description=SNODE AI Agent
After=network.target postgresql.service

[Service]
Type=simple
User=your_user
WorkingDirectory=/opt/snode
Environment="PATH=/opt/snode/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/snode/venv/bin/python3 -m app.cli.main
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Enable và start service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable snode

# Start service
sudo systemctl start snode

# Check status
sudo systemctl status snode

# View logs
sudo journalctl -u snode -f
```

## 🔍 Kiểm tra deployment

### 1. Kiểm tra Python packages

```bash
source venv/bin/activate
python3 -c "import langchain, langgraph, chromadb, psycopg2; print('All packages OK')"
```

### 2. Kiểm tra PostgreSQL

```bash
sudo systemctl status postgresql
psql -U snode -d snode_memory -h localhost -c "SELECT version();"
```

### 3. Kiểm tra Ollama

```bash
ollama list
curl http://localhost:11434/api/tags
```

### 4. Kiểm tra security tools

```bash
which nmap subfinder httpx nuclei
nmap --version
subfinder -version
```

## 📝 Cấu hình nâng cao

### Sử dụng Cloud LLM thay vì Ollama

Edit `.env`:

```env
# OpenAI
OPENAI_API_KEY=sk-...
LLM_PROVIDER=openai
OPENAI_MODEL=gpt-4

# Hoặc Anthropic
ANTHROPIC_API_KEY=sk-...
LLM_PROVIDER=anthropic
ANTHROPIC_MODEL=claude-3-opus
```

### Sử dụng SQLite thay vì PostgreSQL (Development)

Chương trình sẽ tự động fallback về SQLite nếu PostgreSQL không available.

### Cấu hình ChromaDB

ChromaDB sẽ tự động tạo database tại `data/chroma/`. Không cần cấu hình thêm.

## 🔐 Bảo mật

### 1. Thay đổi PostgreSQL password

```bash
sudo -u postgres psql
ALTER USER snode WITH PASSWORD 'strong_password_here';
\q
```

Update `.env`:
```env
POSTGRES_PASSWORD=strong_password_here
```

### 2. Firewall rules

```bash
# Chỉ cho phép localhost kết nối PostgreSQL
sudo ufw allow from 127.0.0.1 to any port 5432
```

### 3. File permissions

```bash
# .env file should be readable only by owner
chmod 600 /opt/snode/.env
```

## 🐛 Troubleshooting

### PostgreSQL connection error

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check connection
psql -U snode -d snode_memory -h localhost

# Check logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### Python import errors

```bash
# Reinstall packages
source venv/bin/activate
pip install --force-reinstall -r requirements.txt
```

### Ollama connection error

```bash
# Start Ollama
ollama serve

# Check if running
curl http://localhost:11434/api/tags
```

### Tools not found

```bash
# Check PATH
echo $PATH

# Add Go tools to PATH
export PATH=$PATH:~/go/bin:~/.local/bin
echo 'export PATH=$PATH:~/go/bin:~/.local/bin' >> ~/.bashrc
```

## 📊 Monitoring

### View logs

```bash
# Application logs
tail -f /opt/snode/logs/*.log

# Systemd service logs
sudo journalctl -u snode -f

# PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### Check disk space

```bash
# Check database size
du -sh /opt/snode/data/

# Check ChromaDB size
du -sh /opt/snode/data/chroma/
```

## 🔄 Update deployment

```bash
cd /opt/snode

# Pull latest changes
git pull

# Update Python packages
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Restart service (if using systemd)
sudo systemctl restart snode
```

## 📞 Support

Nếu gặp vấn đề:
1. Kiểm tra logs
2. Verify tất cả services đang chạy
3. Kiểm tra file permissions
4. Kiểm tra network connectivity
