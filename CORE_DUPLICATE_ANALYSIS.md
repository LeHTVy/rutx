# Phân tích Duplicate Functionality trong app/core/

## 🔍 Tổng quan

Có nhiều điểm tương đồng và duplicate giữa `app/core/` và các modules khác trong hệ thống.

---

## 1. ⚙️ CONFIG SYSTEMS (3 systems)

### 1.1 `app/core/config.py` - Config
**Mục đích**: Application config (paths, tool settings)
```python
class Config:
    llm_model: str
    llm_temperature: float
    project_root: Path
    data_dir: Path
    results_dir: Path
    discoveries_dir: Path
    default_timeout: int
    max_targets: int
```

**Được dùng**: 
- `app/core/state.py`
- `app/rag/unified_memory.py`
- `app/agent/memory.py`
- `app/rag/tool_index.py`

### 1.2 `app/llm/config.py` - LLMConfig
**Mục đích**: LLM model configuration
```python
class LLMConfig:
    model: str
    planner_model: str
    analyzer_model: str
    executor_model: str
    reasoning_model: str
    temperature: float
    endpoint: str
```

**Được dùng**:
- `app/llm/client.py`
- `app/cli/main.py`
- Tất cả LLM interactions

### 1.3 `config.py` (root) - Global Config
**Mục đích**: Global settings (mọi thứ)
```python
OLLAMA_ENDPOINT = ...
MODEL_NAME = ...
TIMEOUT_NMAP = ...
ENABLE_GUARDRAILS = ...
SHODAN_API_KEY = ...
# ... 100+ settings
```

**Được dùng**: 
- Legacy code
- Some handlers

### ⚠️ Vấn đề
- **3 config systems** khác nhau
- Overlap: `llm_model` có trong cả 3
- Khó maintain: phải update 3 chỗ

### ✅ Khuyến nghị
**Consolidate thành 1 system:**
- Merge `app/core/config.py` và `app/llm/config.py` → `app/core/config.py`
- Migrate `config.py` (root) → `app/core/config.py`
- Hoặc: Giữ `app/core/config.py` cho app config, `app/llm/config.py` cho LLM config (tách biệt concerns)

---

## 2. 📝 LOGGER SYSTEMS (2 systems)

### 2.1 `app/core/logger.py` - Standard Logger
**Mục đích**: Standard Python logging
```python
def get_logger(name: str = "snode") -> logging.Logger:
    # Standard Python logging
```

**Được dùng**: 
- Không thấy usage (có thể deprecated)

### 2.2 `app/ui/logger.py` - UILogger
**Mục đích**: Rich UI logging với components
```python
class UILogger:
    def info(self, message: str, icon: str = None)
    def success(self, message: str, icon: str = None)
    def error(self, message: str, icon: str = None)
    # Uses Rich console
```

**Được dùng**:
- `app/agent/tools/*` → `from app.ui import get_logger`
- `app/agent/graph.py`
- Tất cả agent tools

### ⚠️ Vấn đề
- **2 logger systems** khác nhau
- `app/core/logger.py` không được dùng
- `app/ui/logger.py` là standard

### ✅ Khuyến nghị
**Xóa `app/core/logger.py`** (không được dùng)
- Hoặc: Merge vào `app/ui/logger.py` nếu cần standard logging

---

## 3. 💾 STATE MANAGEMENT (4 systems)

### 3.1 `app/core/state.py` - SubdomainState
**Mục đích**: File-based subdomain persistence
```python
class SubdomainState:
    def add(subdomains, domain) -> Path
    def get_file(domain) -> Path
    def load(domain) -> List[str]
```

**Được dùng**:
- `app/tools/handlers/recon.py`
- `app/tools/handlers/vuln.py`
- `app/tools/handlers/web.py`

### 3.2 `app/agent/graph.py` - AgentState
**Mục đích**: In-memory state cho LangGraph
```python
class AgentState(TypedDict):
    query: str
    messages: List[Message]
    intent: str
    suggested_tools: List[str]
    context: Dict[str, Any]
    # ... LangGraph state
```

**Được dùng**:
- LangGraph agent flow
- In-memory only

### 3.3 `app/memory/session.py` - AgentContext
**Mục đích**: Shared context giữa agents
```python
@dataclass
class AgentContext:
    domain: str
    subdomains: List[str]
    ips: List[str]
    vulnerabilities: List[Dict]
    # ... Shared context
```

**Được dùng**:
- Multi-agent coordination
- Session persistence

### 3.4 `app/rag/unified_memory.py` - get_subdomains()
**Mục đích**: ChromaDB-based subdomain retrieval
```python
def get_subdomains(domain: str, limit: int = 200) -> List[str]:
    # Query ChromaDB
```

**Được dùng**:
- `app/agent/orchestration/coordinator.py`
- `app/agent/utils/memory_display.py`
- `app/agent/core/target_collector.py`

### ⚠️ Vấn đề
- **4 state systems** khác nhau
- Overlap: `subdomains` có trong cả 4
- Khó sync: data có thể inconsistent

### ✅ Khuyến nghị
**Phân tách rõ ràng:**
- `SubdomainState` (file-based) → Giữ cho file persistence
- `AgentState` (LangGraph) → Giữ cho LangGraph flow
- `AgentContext` (multi-agent) → Giữ cho agent coordination
- `unified_memory.get_subdomains()` → Giữ cho ChromaDB retrieval

**Nhưng**: Cần sync mechanism giữa chúng

---

## 4. ✅ VALIDATION SYSTEMS (3 systems)

### 4.1 `app/core/validators.py` - DEPRECATED
**Mục đích**: Wrapper (deprecated)
```python
# DEPRECATED: Use InputGuardrail and OutputGuardrail directly
```

**Được dùng**: Không (deprecated)

### 4.2 `app/core/input_filter.py` + `output_filter.py` - Security Guardrails
**Mục đích**: Security validation (prompt injection, dangerous commands)
```python
class InputGuardrail:
    def validate(user_input) -> Tuple[bool, str]

class OutputGuardrail:
    def validate(command) -> Tuple[bool, str, List[str]]
```

**Được dùng**: 
- Security checks
- Command validation

### 4.3 `app/agent/utils/validators.py` - ToolParamValidator
**Mục đích**: Tool parameter validation
```python
class ToolParamValidator:
    def validate_params(tool, command, params) -> ValidationResult
    def validate_tool(tool, command, params) -> ValidationResult
```

**Được dùng**:
- `app/agent/graph.py`
- `app/agent/tools/executor_tool.py`
- Tool execution validation

### ⚠️ Vấn đề
- **3 validation systems** khác nhau
- `validators.py` deprecated nhưng vẫn tồn tại
- Overlap: validation logic có thể duplicate

### ✅ Khuyến nghị
**Xóa `app/core/validators.py`** (deprecated)
- Giữ `input_filter.py` + `output_filter.py` cho security
- Giữ `app/agent/utils/validators.py` cho tool validation
- Phân tách rõ: Security vs Tool validation

---

## 📊 Tổng kết

| Category | Systems | Status | Action |
|----------|---------|--------|--------|
| **Config** | 3 | ⚠️ Overlap | Consolidate hoặc tách biệt concerns |
| **Logger** | 2 | ⚠️ Unused | Xóa `app/core/logger.py` |
| **State** | 4 | ⚠️ Overlap | Giữ nhưng cần sync mechanism |
| **Validation** | 3 | ⚠️ Deprecated | Xóa `app/core/validators.py` |

---

## 🎯 Khuyến nghị tổng thể

### Priority 1: Cleanup (Dễ, ít risk)
1. ✅ **Xóa `app/core/logger.py`** (không được dùng)
2. ✅ **Xóa `app/core/validators.py`** (deprecated)

### Priority 2: Consolidate (Medium, cần test)
3. ⚠️ **Consolidate Config**: 
   - Option A: Merge `app/core/config.py` + `app/llm/config.py` → 1 system
   - Option B: Giữ tách biệt nhưng document rõ concerns

### Priority 3: Refactor (Hard, cần design)
4. 🔄 **State Management**: 
   - Design sync mechanism giữa 4 systems
   - Hoặc consolidate nếu có thể

---

## 💡 Lưu ý

- **Không nên** xóa tất cả duplicate ngay lập tức
- **Nên** phân tích usage trước khi consolidate
- **Nên** test kỹ sau khi consolidate
- **Nên** document rõ concerns của mỗi system
