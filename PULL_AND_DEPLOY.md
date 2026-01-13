# 📥 Pull & Deploy SNODE

Hướng dẫn ngắn gọn để pull repo và deploy lên server.

## 📥 Pull Repository

### Option 1: Clone từ Git (Nếu repo đã có trên Git)

```bash
# Clone repository
git clone https://github.com/your-username/snode.git /opt/snode
cd /opt/snode
```

### Option 2: Copy từ máy local lên server

```bash
# Từ máy local
cd /home/hellrazor/rutx
tar -czf snode.tar.gz --exclude='venv' --exclude='__pycache__' --exclude='*.pyc' .
scp snode.tar.gz user@server:/tmp/

# Trên server
cd /opt
sudo tar -xzf /tmp/snode.tar.gz -C /opt/snode
cd /opt/snode
```

### Option 3: Sử dụng rsync (Khuyến nghị - nhanh hơn)

```bash
# Từ máy local
rsync -avz --exclude 'venv' --exclude '__pycache__' --exclude '*.pyc' \
    /home/hellrazor/rutx/ user@server:/opt/snode/
```

## 🚀 Deploy lên Server

### Cách 1: Deploy tự động (Khuyến nghị)

```bash
# Trên server
cd /opt/snode
sudo bash deploy.sh /opt/snode
```

Script sẽ tự động:
- ✅ Cài đặt dependencies
- ✅ Setup PostgreSQL
- ✅ Tạo Python venv
- ✅ Cài đặt packages
- ✅ Cài đặt security tools
- ✅ Tạo .env file

### Cách 2: Deploy thủ công

Xem chi tiết trong `DEPLOY.md`

## ⚙️ Cấu hình sau khi deploy

### 1. Edit .env file

```bash
nano /opt/snode/.env
```

Thêm API keys:
```env
SHODAN_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
```

### 2. Cài đặt Ollama (nếu chưa có)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
```

### 3. Chạy ứng dụng

```bash
cd /opt/snode
source venv/bin/activate
python3 -m app.cli.main
```

## 🔄 Update deployment

### Nếu dùng Git:

```bash
cd /opt/snode
git pull
source venv/bin/activate
pip install -r requirements.txt --upgrade
```

### Nếu copy từ local:

```bash
# Từ máy local, sync lại
rsync -avz --exclude 'venv' --exclude '__pycache__' \
    /home/hellrazor/rutx/ user@server:/opt/snode/

# Trên server
cd /opt/snode
source venv/bin/activate
pip install -r requirements.txt --upgrade
```

## 📋 Checklist

- [ ] Repository đã được clone/copy lên server
- [ ] Script `deploy.sh` đã chạy thành công
- [ ] PostgreSQL đã được setup và running
- [ ] Python venv đã được tạo và packages đã install
- [ ] Security tools đã được cài đặt (nmap, subfinder, etc.)
- [ ] File `.env` đã được tạo và cấu hình API keys
- [ ] Ollama đã được cài đặt và model đã được pull
- [ ] Ứng dụng có thể chạy được

## 🐛 Troubleshooting

### Lỗi: Permission denied

```bash
sudo chown -R $USER:$USER /opt/snode
```

### Lỗi: PostgreSQL connection failed

```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Lỗi: Python packages not found

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Lỗi: Tools not found

```bash
# Check PATH
echo $PATH

# Add to PATH
export PATH=$PATH:~/go/bin:~/.local/bin
echo 'export PATH=$PATH:~/go/bin:~/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

## 📞 Cần giúp đỡ?

- Xem `DEPLOY.md` cho hướng dẫn chi tiết
- Xem `QUICK_START.md` cho quick start
- Xem `INSTALL_TOOLS.md` cho tools installation
