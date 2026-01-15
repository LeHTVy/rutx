# Re-index ChromaDB RAG Collections

Script `reindex_rag.py` dùng để re-index tất cả collections trong UnifiedRAG với metadata mới.

## Khi nào cần re-index?

- Sau khi thêm/sửa metadata trong `CommandTemplate` (description, use_cases)
- Sau khi cập nhật `tool_metadata.py`
- Sau khi thêm security technologies mới vào `security_tech.py`
- Sau khi cập nhật port metadata trong `port_metadata.py`
- Khi muốn xóa và rebuild toàn bộ RAG database

## Cách sử dụng

### Re-index tất cả collections (khuyến nghị)

```bash
python reindex_rag.py --force
```

Lệnh này sẽ:
- Xóa tất cả collections cũ
- Re-index lại với metadata mới từ registry + tool_metadata.py
- Index security technologies từ security_tech.py
- Index port metadata từ port_metadata.py
- Index cloud services từ cloud_metadata.py

### Re-index chỉ một số collections

```bash
# Chỉ re-index tools và security_tech
python reindex_rag.py --force --collections tools,security_tech

# Chỉ re-index ports
python reindex_rag.py --force --collections ports
```

### Re-index không xóa dữ liệu cũ (không khuyến nghị)

```bash
python reindex_rag.py --collections tools
```

⚠️ **Lưu ý**: Cách này có thể tạo duplicate entries. Nên dùng `--force` để xóa collection cũ trước.

## Collections có sẵn

- `tools`: Tools và commands với description, use_cases, phase metadata
- `security_tech`: Security technologies (WAF, CDN, firewall) và bypass methods
- `ports`: Port và service metadata
- `cloud`: Cloud service provider metadata

## Ví dụ output

```
============================================================
ChromaDB RAG Re-indexing Script
============================================================

⚠️  FORCE MODE: Existing collections will be deleted!
Continue? (yes/no): yes

🔧 Initializing UnifiedRAG...

📋 Collections to re-index: tools, ports, security_tech, cloud

📚 Re-indexing Tools & Commands...
  ✓ Deleted old tools_commands collection
  📚 Indexed 245 tool commands from registry (merged with tool_metadata) in UnifiedRAG
  ✓ Tools collection indexed: 245 commands

🛡️ Re-indexing Security Technologies...
  ✓ Deleted old security_tech collection
  📚 Indexed 10 security technologies in UnifiedRAG
  ✓ Security tech collection indexed: 10 technologies

🔌 Re-indexing Port Metadata...
  ✓ Deleted old port_metadata collection
  📚 Indexed 150 port entries in UnifiedRAG
  ✓ Ports collection indexed: 150 entries

☁️ Re-indexing Cloud Services...
  ✓ Deleted old cloud_services collection
  📚 Indexed 15 cloud services in UnifiedRAG
  ✓ Cloud services collection indexed: 15 services

============================================================
✅ Re-indexing completed successfully!
============================================================

📊 Collection Summary:
  • Tools/Commands: 245 entries
  • Security Tech: 10 entries
  • Ports: 150 entries
  • Cloud Services: 15 entries
```

## Troubleshooting

### Lỗi: "Collection not found"
- Bình thường nếu collection chưa tồn tại
- Script sẽ tự động tạo collection mới

### Lỗi: "Could not sync with tool registry"
- Kiểm tra xem `app.tools.registry` có hoạt động không
- Script sẽ fallback về `tool_metadata.py` nếu registry unavailable

### Metadata không được cập nhật
- Đảm bảo đã dùng `--force` để xóa collection cũ
- Kiểm tra xem metadata mới đã được thêm vào `CommandTemplate` hoặc `tool_metadata.py` chưa
