# Đề xuất Refactor: Tích hợp Checklist Planning vào Analyzer

## Vấn đề hiện tại

1. **Checklist được tạo ở analyzer** (`prompt_analysis_node` → `task_breakdown_tool`)
2. **Checklist được sử dụng ở planner** (`planner_node` → `planner_tool`)
3. **Checklist được mark completed ở analyzer** (`analyzer_node` → `analyzer_tool`)

→ Checklist logic bị phân tán giữa analyzer và planner

## Flow hiện tại

```
User Prompt
  ↓
prompt_analysis_node (analyzer) → Tạo checklist
  ↓
target_verification_node
  ↓
planner_node (tools) → Sử dụng checklist để suggest tools
  ↓
confirm_node
  ↓
executor_node (tools) → Execute tools
  ↓
analyzer_node (tools) → Analyze, mark task completed
```

## Đề xuất Refactor

### Option 1: Tạo Checklist Planner trong Analyzer

Tạo `app/agent/analyzer/checklist_planner.py`:
- Handle checklist integration (lấy next task)
- Suggest tools dựa trên checklist task
- Planner tool chỉ focus vào tool selection (không cần checklist logic)

### Option 2: Di chuyển toàn bộ Planner vào Analyzer

Di chuyển `planner_tool.py` → `app/agent/analyzer/planner_tool.py`:
- Tất cả checklist logic ở một nơi
- Planner và analyzer cùng module

### Option 3: Tách Checklist Planning thành service riêng

Tạo `app/agent/analyzer/checklist_planning_service.py`:
- Service để handle checklist planning
- Cả planner và analyzer đều sử dụng service này

## Khuyến nghị: Option 1

**Lý do:**
- Giữ planner tool ở `tools/` vì nó là một tool trong graph
- Tách checklist planning logic vào analyzer vì checklist được tạo và completed ở đó
- Planner tool chỉ cần gọi checklist planning service từ analyzer

## Implementation Plan

1. Tạo `app/agent/analyzer/checklist_planning_service.py`:
   - `get_next_task_from_checklist()` - Lấy next task
   - `suggest_tools_for_task()` - Suggest tools cho task
   - `update_query_with_task()` - Update query với task context

2. Refactor `planner_tool.py`:
   - Remove checklist handling logic
   - Call checklist planning service từ analyzer
   - Focus vào: context aggregation, agent routing, validation, tool availability

3. Refactor `analyzer_tool.py`:
   - Sử dụng checklist planning service để mark completed
   - Giữ logic analyze results
