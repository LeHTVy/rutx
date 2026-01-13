# ⚡ SNODE Quick Start Guide

Hướng dẫn nhanh để bắt đầu với SNODE AI Agent.

## 🚀 Deploy nhanh (3 bước)

### 1. Clone và deploy

```bash
# Clone repo
git clone <your-repo-url> /opt/snode
cd /opt/snode

# Chạy script deploy tự động
sudo bash deploy.sh /opt/snode
```

### 2. Cấu hình API keys

```bash
# Edit .env file
nano /opt/snode/.env

# Thêm API keys:
# - SHODAN_API_KEY=...
# - SECURITYTRAILS_API_KEY=...
```

### 3. Chạy ứng dụng

```bash
cd /opt/snode
source venv/bin/activate
python3 -m app.cli.main
```

## 📦 Pull repo từ Git

### Nếu repo đã có trên Git:

```bash
# Clone
git clone https://github.com/your-username/snode.git /opt/snode
cd /opt/snode

# Deploy
sudo bash deploy.sh /opt/snode
```

### Nếu muốn push code lên Git:

```bash
# Initialize git (nếu chưa có)
cd /home/hellrazor/rutx
git init
git add .
git commit -m "Initial commit"

# Add remote
git remote add origin https://github.com/your-username/snode.git
git push -u origin main
```

## 🔧 Setup Ollama (LLM Local)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull model
ollama pull mistral
# hoặc
ollama pull deepseek-r1:latest

# Start Ollama (nếu chưa tự động start)
ollama serve
```

## ✅ Kiểm tra

```bash
# Check Python
python3 --version

# Check PostgreSQL
sudo systemctl status postgresql

# Check Ollama
ollama list

# Check tools
which nmap subfinder httpx nuclei
```

## 🎯 Sử dụng

```bash
# Activate venv
source /opt/snode/venv/bin/activate

# Run SNODE
python3 -m app.cli.main

# Hoặc dùng launcher
/opt/snode/snode
```

## 📝 Example .env file

```env
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=snode_memory
POSTGRES_USER=snode
POSTGRES_PASSWORD=snode123

SHODAN_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here

OLLAMA_ENDPOINT=http://localhost:11434/api/chat
OLLAMA_MODEL=mistral
```

## 🔗 Links hữu ích

- **Full Deployment Guide**: Xem `DEPLOY.md`
- **Tools Installation**: Xem `INSTALL_TOOLS.md`
- **API Keys**:
  - Shodan: https://account.shodan.io/
  - SecurityTrails: https://securitytrails.com/app/signup
